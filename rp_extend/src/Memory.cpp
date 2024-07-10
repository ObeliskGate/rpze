#include "shm.h"
#include "stdafx.h"
#include "Memory.h"
#include "MemoryException.h"

void Memory::getRemoteMemoryAddress()
{
	if (!isShmPrepared())
		throw MemoryException("getRemoteMemoryAddress: main loop not prepared", pid);
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY_PTR;
	untilGameExecuted();
	if (shm().executeResult == ExecuteResult::SUCCESS)
		remoteMemoryAddress = *shm().getReadWriteBuffer<uint32_t>();
	else throw MemoryException("getRemoteMemoryAddress: unexpected behavior", pid);
}

Memory::Memory(DWORD pid) : pid(pid)
{
	auto nameAffix = std::wstring{ UU_NAME_AFFIX } + std::to_wstring(pid);
	hMemory = OpenFileMappingW(FILE_MAP_ALL_ACCESS, 
		FALSE,
		(nameAffix + L"_shm").c_str());
	if (!hMemory)
		throw MemoryException(
			std::format("failed to find shared memory, err {}", GetLastError()), pid);
	
	pShm = static_cast<Shm*>(MapViewOfFile(hMemory, 
		FILE_MAP_ALL_ACCESS, 
		0, 
		0, 
		SHARED_MEMORY_SIZE));
	if (!pShm)
		throw MemoryException(
			std::format("failed tocreate shared memory, err {}", GetLastError()), pid);

	if (shm().alreadyShared)
		throw MemoryException("shared memory has already been connected", pid);
	shm().alreadyShared = true;

	pCurrentPhaseCode = &shm().phaseCode;
	pCurrentRunState = &shm().runState;
	pCurrentSyncMethod = &shm().syncMethod;
	hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hPvz)
		throw MemoryException(
			std::format("failed to find game process, err {}", GetLastError()), pid);
	

	hMutex = OpenMutexW(MUTEX_ALL_ACCESS, 
		FALSE,
		(nameAffix + L"_mutex").c_str());
	if (!hMutex)
		throw MemoryException(
			std::format("failed to find mutex, err {}", GetLastError()), pid);


	shm().globalState = HookState::CONNECTED;
	startControl();
	getRemoteMemoryAddress();
	endControl();

	shm().syncMethod = SyncMethod::MUTEX; // 第一次通信切忌不能用mutex, game还没拿到锁
	shm().jumpingSyncMethod = SyncMethod::SPIN;
#ifndef NDEBUG
	std::println("memory constructed, remote base_ptr is {:x}", remoteMemoryAddress);
#endif
}

Memory::~Memory()
{
	endControl();
	shm().globalState = HookState::NOT_CONNECTED;
	shm().alreadyShared = false;
	UnmapViewOfFile(pShm);
	CloseHandle(hMemory);
	CloseHandle(hPvz);
	CloseHandle(hMutex);
}

inline void Memory::setReadWriteOffsets(std::span<uint32_t> offsets)
{
	memcpy(const_cast<uint32_t*>(shm().offsets), offsets.data(), offsets.size_bytes());
	shm().offsets[offsets.size()] = Shm::OFFSET_END;
}

volatile void* Memory::_readMemory(uint32_t size, std::span<uint32_t> offsets)
{
	shm().memoryNum = size;
	setReadWriteOffsets(offsets);
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY;
	untilGameExecuted(); 
	if (shm().executeResult == ExecuteResult::SUCCESS) return shm().getReadWriteBuffer();
	if (shm().executeResult == ExecuteResult::FAIL) return nullptr;
	throw MemoryException("_readMemory: unexpected behavior", this->pid);
}

bool Memory::_writeMemory(const void* pVal, uint32_t size, std::span<uint32_t> offsets)
{
	shm().memoryNum = size;
	memcpy(const_cast<void*>(shm().getReadWriteBuffer()), pVal, size);
	setReadWriteOffsets(offsets);
	getCurrentPhaseCode() = PhaseCode::WRITE_MEMORY;
	untilGameExecuted();
	if (shm().executeResult == ExecuteResult::SUCCESS) return true;
	if (shm().executeResult == ExecuteResult::FAIL) return false;
	throw MemoryException("_writeMemory: unexpected behavior", this->pid);
}

void Memory::before() const
{
	waitMutex<>();
	while (isBlocked()) waiting("before");
}

void Memory::next() const
{
	releaseMutex<>();
	getCurrentPhaseCode() = PhaseCode::CONTINUE;
	if (*pCurrentSyncMethod == SyncMethod::MUTEX)
		while (!(getCurrentRunState() != RunState::OVER || getCurrentPhaseCode() == PhaseCode::WAIT))
		 // give the game time to get mutex
			waiting("next");
		
}

void Memory::skipFrames(size_t num) const
{
	if (!isShmPrepared()) [[unlikely]]
		throw MemoryException("before: main loop hook not connected", this->pid);
	
	for (size_t i = 0; i < num; i++)
	{
		next();
		before();
	}
}

bool Memory::startJumpFrame()
{
	if (!isShmPrepared()) [[unlikely]]
		throw MemoryException("startJumpFrame: main loop hook not prepared", this->pid);
	if (!shm().boardPtr) [[unlikely]]
		throw MemoryException("startJumpFrame: board ptr not found", this->pid);
	if (jumpingFrame) return false;
	jumpingFrame = true;
	pCurrentPhaseCode = &shm().jumpingPhaseCode;
	pCurrentRunState = &shm().jumpingRunState;
	pCurrentSyncMethod = &shm().jumpingSyncMethod;


	// 非syncMethod -> 跳帧syncMethod | 锁所有权变化
	// mutex -> spin | extend -> extend 保持跳帧时全程拿锁即可, 不做事
	// spin -> mutex | dll -> extend 最后waitMutex拿锁, 不做事
	// mutex -> mutex | extend -> dll 放锁
	// spin -> spin | dll -> dll 不做事

	if (shm().syncMethod == SyncMethod::MUTEX && shm().jumpingSyncMethod == SyncMethod::MUTEX)
		releaseMutex<false>();
	
	shm().jumpingPhaseCode = PhaseCode::CONTINUE;
	shm().phaseCode = PhaseCode::JUMP_FRAME;
	while (isBlocked())
		waiting("startJumpFrame");
	 // give dll time to get mutex; equals to before() without mutex
	waitMutex<>();
	return true;
}

bool Memory::endJumpFrame()
{
	// 跳syncMethod -> 非syncMethod | 锁所有权变化
	// mutex -> spin | extend -> dll 还锁
	// spin -> mutex | extend -> extend 不做事
	// mutex -> mutex | extend -> dll 放锁再拿
	// spin -> spin | dll -> dll 不做事

	if (!isShmPrepared()) [[unlikely]]
		throw MemoryException("endJumpFrame: main loop hook not prepared", this->pid);
	
	if (!jumpingFrame) return false;
	jumpingFrame = false;
	releaseMutex<>();

	pCurrentPhaseCode = &shm().phaseCode;
	pCurrentRunState = &shm().runState;
	pCurrentSyncMethod = &shm().syncMethod;

	shm().phaseCode = PhaseCode::WAIT;
	shm().jumpingPhaseCode = PhaseCode::CONTINUE;
	while (shm().jumpingRunState == RunState::OVER)
		waiting("endJumpFrame");
	 // give dll time to get mutex
	if (shm().jumpingSyncMethod == SyncMethod::MUTEX && shm().syncMethod == SyncMethod::MUTEX)
		waitMutex<false>();
	return true;
}

void* Memory::getRemotePtr(std::span<uint32_t> offsets)
{
	uintptr_t basePtr = offsets[0];
	for (size_t i = 1; i < offsets.size(); i++)
	{
		// if (!basePtr) return nullptr;
		ReadProcessMemory(hPvz, 
			reinterpret_cast<LPCVOID>(basePtr), 
			&basePtr, 
			sizeof(uint32_t), 
			nullptr);
		if (!basePtr) return nullptr;
		basePtr += offsets[i];
	}
	return reinterpret_cast<void*>(basePtr);
}


std::optional<std::unique_ptr<char[]>> Memory::readBytes(uint32_t size, std::span<uint32_t> offsets, bool forceRemote)
{
	if (forceRemote || !isShmPrepared())
	{
		auto remotePtr = getRemotePtr(offsets);
		if (!remotePtr) return {};
		auto ret = std::make_unique<char[]>(size);
		ReadProcessMemory(hPvz, remotePtr, ret.get(), size, nullptr);
		return ret;
	}
	if (size > Shm::BUFFER_SIZE) [[unlikely]] throw std::invalid_argument("readBytes: too many bytes");
	if (offsets.size() > Shm::OFFSETS_LEN) [[unlikely]] throw std::invalid_argument("readBytes: too many offsets");
	auto p = _readMemory(size, offsets);
	if (!p) return {};
	auto ret = std::make_unique<char[]>(size);
	memcpy(ret.get(), const_cast<const void*>(p), size);
	return ret;
}

bool Memory::writeBytes(const std::string_view inputBytes, std::span<uint32_t> offsets, bool forceRemote)
{
	if (forceRemote || !isShmPrepared())
	{
		auto remotePtr = getRemotePtr(offsets);
		if (!remotePtr) return false;
		WriteProcessMemory(hPvz, remotePtr, inputBytes.data(), inputBytes.size(), nullptr);
		return true;
	}
	if (inputBytes.size() > Shm::BUFFER_SIZE) [[unlikely]] throw std::invalid_argument("writeBytes: too many bytes");
	if (offsets.size() > Shm::OFFSETS_LEN) [[unlikely]] throw std::invalid_argument("writeBytes: too many offsets");
	return _writeMemory(inputBytes.data(), inputBytes.size(), offsets);
}

bool Memory::runCode(const std::string_view codes) const
{
	if (codes.size() > SHARED_MEMORY_SIZE) [[unlikely]]
		throw std::invalid_argument("runCode: too many codes");
	
	if (!isShmPrepared()) [[unlikely]]
		throw MemoryException("runCode: main loop not prepared", this->pid);

#ifndef NDEBUG
	std::println("run code");
#endif
	memcpy(const_cast<void*>(shm().getAsmBuffer()), codes.data(), codes.size());
	getCurrentPhaseCode() = PhaseCode::RUN_CODE;
	untilGameExecuted();
	if (shm().executeResult == ExecuteResult::SUCCESS) [[likely]] return true;
	if (shm().executeResult == ExecuteResult::FAIL) return false;
	throw MemoryException("runCode: unexpected behavior", this->pid);
}

void Memory::startControl()
{
	if (hookConnected(HookPosition::MAIN_LOOP)) return;
#ifndef NDEBUG
	std::println("start control");
#endif
	shm().phaseCode = PhaseCode::CONTINUE;
	shm().jumpingPhaseCode = PhaseCode::CONTINUE;
	openHook(HookPosition::MAIN_LOOP); // mutex: this process
	before();
}

void Memory::endControl()
{
	if (!hookConnected(HookPosition::MAIN_LOOP)) return;
	if (!isShmPrepared()) [[unlikely]]
		throw MemoryException("endControl: main loop not prepared", this->pid);
#ifndef NDEBUG
	std::println("end control");
#endif
	if (jumpingFrame) endJumpFrame();
	releaseMutex<>();
	closeHook(HookPosition::MAIN_LOOP);
	shm().phaseCode = PhaseCode::CONTINUE;
	shm().jumpingPhaseCode = PhaseCode::CONTINUE;
	while (shm().runState == RunState::OVER)
		waiting("endControl");
	
}

void Memory::openHook(HookPosition hook)
{
	shm().hookStateArr[getHookIndex(hook)] = HookState::CONNECTED;
}

void Memory::closeHook(HookPosition hook)
{
	shm().hookStateArr[getHookIndex(hook)] = HookState::NOT_CONNECTED;
}

void Memory::setSyncMethod(SyncMethod val)
{
	if (hookConnected(HookPosition::MAIN_LOOP)) [[unlikely]]
		throw MemoryException(
			"setSyncMethod: cannot set sync method when main loop hook is connected", this->pid);
	shm().syncMethod = val;
}

void Memory::setJumpingSyncMethod(SyncMethod val)
{
	if (jumpingFrame) [[unlikely]]
		throw MemoryException(
			"setJumpingSyncMethod: cannot set jumping sync method when jumping frame", this->pid);
	shm().jumpingSyncMethod = val;
}

std::pair<bool, uint32_t> Memory::getPBoard() const
{
	auto t = shm().isBoardPtrValid;
	shm().isBoardPtrValid = true;
	return { t, shm().boardPtr };
}

void Memory::waiting(std::string_view callerName) const
{
	if (!globalConnected()) [[unlikely]]
	{
		std::string message;
		switch (shm().error)
		{
		case ShmError::CAUGHT_SEH:
			message = "got seh";
			break;
		case ShmError::CAUGHT_CPP_EXCEPTION:
			message = std::format("got c++ exception, message: \n{}", const_cast<const char*>(shm().getReadWriteBuffer<char>()));
			break;
		case ShmError::NONE:
			message = "main loop not connected";
			break;
		}
		throw MemoryException(std::format("waiting at `{}`: {}", callerName, message), this->pid);
	}
}
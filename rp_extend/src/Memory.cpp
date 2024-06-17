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
			("find shared memory failed: " + std::to_string(GetLastError())).c_str(), pid);
	
	pShm = static_cast<Shm*>(MapViewOfFile(hMemory, 
		FILE_MAP_ALL_ACCESS, 
		0, 
		0, 
		SHARED_MEMORY_SIZE));
	if (!pShm)
		throw MemoryException(
			("create shared memory failed: " + std::to_string(GetLastError())).c_str(), pid);

	if (shm().already_shared)
		throw MemoryException("memory: shared memory has already been connected", pid);
	shm().already_shared = true;

	pCurrentPhaseCode = &shm().phaseCode;
	pCurrentRunState = &shm().runState;
	pCurrentSyncMethod = &shm().syncMethod;
	hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hPvz)
		throw MemoryException(
			("cannot find game process: " + std::to_string(GetLastError())).c_str(), pid);
	

	hMutex = OpenMutexW(MUTEX_ALL_ACCESS, 
		FALSE,
		(nameAffix + L"_mutex").c_str());
	if (!hMutex)
		throw MemoryException(
			("cannot find mutex: " + std::to_string(GetLastError())).c_str(), pid);


	shm().globalState = HookState::CONNECTED;
	startControl();
	getRemoteMemoryAddress();
	endControl();

	shm().syncMethod = SyncMethod::MUTEX; // 第一次通信切忌不能用mutex, game还没拿到锁
	shm().jumpingSyncMethod = SyncMethod::SPIN;
#ifndef NDEBUG
	std::cout << "memory constructed, remote base_ptr is " << remoteMemoryAddress << std::endl;
#endif
}

Memory::~Memory()
{
	endControl();
	shm().globalState = HookState::NOT_CONNECTED;
	shm().already_shared = false;
	UnmapViewOfFile(pShm);
	CloseHandle(hMemory);
	CloseHandle(hPvz);
	CloseHandle(hMutex);
}

volatile void* Memory::_readMemory(uint32_t size, const uint32_t* offsets, uint32_t len)
{
	shm().memoryNum = size;
	CopyMemory(const_cast<uint32_t*>(shm().offsets), offsets, sizeof(uint32_t) * len);
	shm().offsets[len] = Shm::OFFSET_END;
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY;
	untilGameExecuted(); 
	if (shm().executeResult == ExecuteResult::SUCCESS) return shm().getReadWriteBuffer();
	if (shm().executeResult == ExecuteResult::FAIL) return nullptr;
	throw MemoryException("_readMemory: unexpected behavior", this->pid);
}

bool Memory::_writeMemory(const void* pVal, uint32_t size, const uint32_t* offsets, uint32_t len)
{
	shm().memoryNum = size;
	CopyMemory(const_cast<void*>(shm().getReadWriteBuffer()), pVal, size);
	CopyMemory(const_cast<uint32_t*>(shm().offsets), offsets, sizeof(uint32_t) * len);
	shm().offsets[len] = Shm::OFFSET_END;
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
		while (! (getCurrentRunState() != RunState::OVER || getCurrentPhaseCode() == PhaseCode::WAIT))
		{ // give the game time to get mutex
			if (!globalConnected())
				throw MemoryException("next: global not connected", this->pid);
		}
}

void Memory::skipFrames(size_t num) const
{
	if (!isShmPrepared())
		throw MemoryException("before: main loop hook not connected", this->pid);
	
	for (size_t i = 0; i < num; i++)
	{
		next();
		before();
	}
}

bool Memory::startJumpFrame()
{
	if (!isShmPrepared())
		throw MemoryException("startJumpFrame: main loop hook not prepared", this->pid);
	if (!shm().boardPtr)
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
	{
		if (!globalConnected())
			throw MemoryException("startJumpFrame: global hook not connected", this->pid);
	} // give dll time to get mutex; equals to before() without mutex
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

	if (!isShmPrepared())
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
	{
		if (!globalConnected())
			throw MemoryException("endJumpFrame: global hook not connected", this->pid);
	} // give dll time to get mutex
	if (shm().jumpingSyncMethod == SyncMethod::MUTEX && shm().syncMethod == SyncMethod::MUTEX)
		waitMutex<false>();
	return true;
}

void* Memory::getRemotePtr(const uint32_t* offsets, uint32_t len)
{
	uint64_t basePtr = offsets[0];
	for (size_t i = 1; i < len; i++)
	{
		if (!basePtr) return nullptr;
		ReadProcessMemory(hPvz, 
			reinterpret_cast<LPCVOID>(basePtr), 
			&basePtr, 
			sizeof(uint32_t), 
			nullptr);
		basePtr += offsets[i];
	}
	return reinterpret_cast<void*>(basePtr);
}


std::optional<std::unique_ptr<char[]>> Memory::readBytes(uint32_t size, const uint32_t* offsets, uint32_t len, bool forceRemote)
{
	if (forceRemote || !isShmPrepared())
	{
		auto remotePtr = getRemotePtr(offsets, len);
		if (!remotePtr) return {};
		auto ret = std::make_unique<char[]>(size);
		ReadProcessMemory(hPvz, remotePtr, ret.get(), size, nullptr);
		return ret;
	}
	if (size > Shm::BUFFER_SIZE) throw std::invalid_argument("readBytes: too many bytes");
	if (len > Shm::OFFSETS_LEN) throw std::invalid_argument("readBytes: too many offsets");
	auto p = _readMemory(size, offsets, len);
	if (!p) return {};
	auto ret = std::make_unique<char[]>(size);
	CopyMemory(ret.get(), const_cast<const void*>(p), size);
	return ret;
}

bool Memory::writeBytes(const char* in, uint32_t size, const uint32_t* offsets, uint32_t len, bool forceRemote)
{
	if (forceRemote || !isShmPrepared())
	{
		auto remotePtr = getRemotePtr(offsets, len);
		if (!remotePtr) return false;
		WriteProcessMemory(hPvz, remotePtr, in, size, nullptr);
		return true;
	}
	if (size > Shm::BUFFER_SIZE) throw std::invalid_argument("writeBytes: too many bytes");
	if (len > Shm::OFFSETS_LEN) throw std::invalid_argument("writeBytes: too many offsets");
	return _writeMemory(in, size, offsets, len);
}

bool Memory::runCode(const char* codes, size_t len) const
{
	if (len > SHARED_MEMORY_SIZE)
		throw std::invalid_argument("runCode: too many codes");
	
	if (!isShmPrepared())
		throw MemoryException("runCode: main loop not prepared", this->pid);

#ifndef NDEBUG
	std::cout << "run code" << std::endl;
#endif
	memcpy(const_cast<void*>(shm().getAsmBuffer()), codes, len);
	getCurrentPhaseCode() = PhaseCode::RUN_CODE;
	untilGameExecuted();
	if (shm().executeResult == ExecuteResult::SUCCESS) return true;
	if (shm().executeResult == ExecuteResult::FAIL) return false;
	throw MemoryException("runCode: unexpected behavior", this->pid);
}

void Memory::startControl()
{
	if (hookConnected(HookPosition::MAIN_LOOP)) return;
#ifndef NDEBUG
	std::cout << "start control" << std::endl;
#endif
	shm().phaseCode = PhaseCode::CONTINUE;
	shm().jumpingPhaseCode = PhaseCode::CONTINUE;
	openHook(HookPosition::MAIN_LOOP); // mutex: this process
	before();
}

void Memory::endControl()
{
	if (!hookConnected(HookPosition::MAIN_LOOP)) return;
	if (!isShmPrepared())
		throw MemoryException("endControl: main loop not prepared", this->pid);
#ifndef NDEBUG
	std::cout << "end control" << std::endl;
#endif
	if (jumpingFrame) endJumpFrame();
	releaseMutex<>();
	closeHook(HookPosition::MAIN_LOOP);
	shm().phaseCode = PhaseCode::CONTINUE;
	shm().jumpingPhaseCode = PhaseCode::CONTINUE;
	while (shm().runState == RunState::OVER)
	{
		if (!globalConnected())
			throw MemoryException("endControl: global not connected", this->pid);
	}
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
	if (hookConnected(HookPosition::MAIN_LOOP))
		throw MemoryException(
			"setSyncMethod: cannot set sync method when main loop hook is connected", this->pid);
	shm().syncMethod = val;
}

void Memory::setJumpingSyncMethod(SyncMethod val)
{
	if (jumpingFrame)
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

void Memory::waiting(const char* callerName) const
{
	if (!globalConnected())
	{
		auto str = std::string{ "waiting at " } + callerName + 
			": main loop not connected, errno " + std::to_string(static_cast<int32_t>(shm().error));
		throw MemoryException(str.c_str(), this->pid);
	}
}
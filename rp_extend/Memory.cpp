#include "stdafx.h"
#include "Memory.h"
#include "MemoryException.h"

void Memory::getRemoteMemoryAddress()
{
	if (!isShmPrepared())
		throw MemoryException("getRemoteMemoryAddress: main loop not prepared", pid);
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY_PTR;
	untilGameExecuted();
	if (executeResult() == ExecuteResult::SUCCESS)
		remoteMemoryAddress = *static_cast<volatile uint32_t*>(getReadWriteVal());
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
	
	pBuf = MapViewOfFile(hMemory, 
		FILE_MAP_ALL_ACCESS, 
		0, 
		0, 
		SHARED_MEMORY_SIZE);
	if (!pBuf)
		throw MemoryException(
			("create shared memory failed: " + std::to_string(GetLastError())).c_str(), pid);
	

	pCurrentPhaseCode = &phaseCode();
	pCurrentRunState = &runState();
	pCurrentSyncMethod = &syncMethod();
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


	globalState() = HookState::CONNECTED;
	startControl();
	getRemoteMemoryAddress();
	endControl();

	syncMethod() = SyncMethod::MUTEX; // 第一次通信切忌不能用mutex, game还没拿到锁
	jumpingSyncMethod() = SyncMethod::SPIN;
}

Memory::~Memory()
{
	endControl();
	globalState() = HookState::NOT_CONNECTED;
	UnmapViewOfFile(pBuf);
	CloseHandle(hMemory);
	CloseHandle(hPvz);
	CloseHandle(hMutex);
}

volatile void* Memory::_readMemory(uint32_t size, const uint32_t* offsets, uint32_t len)
{
	memoryNum() = size;
	CopyMemory(getOffsets(), offsets, sizeof(uint32_t) * len);
	getOffsets()[len] = OFFSET_END;
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY;
	untilGameExecuted(); 
	if (executeResult() == ExecuteResult::SUCCESS) return getReadWriteVal();
	if (executeResult() == ExecuteResult::FAIL) return nullptr;
	throw MemoryException("_readMemory: unexpected behavior", this->pid);
}

bool Memory::_writeMemory(const void* pVal, uint32_t size, const uint32_t* offsets, uint32_t len)
{
	memoryNum() = size;
	CopyMemory(getReadWriteVal(), pVal, size);
	CopyMemory(getOffsets(), offsets, sizeof(uint32_t) * len);
	getOffsets()[len] = OFFSET_END;
	getCurrentPhaseCode() = PhaseCode::WRITE_MEMORY;
	untilGameExecuted();
	if (executeResult() == ExecuteResult::SUCCESS) return true;
	if (executeResult() == ExecuteResult::FAIL) return false;
	throw MemoryException("_writeMemory: unexpected behavior", this->pid);
}

void Memory::before() const
{
	waitMutex<>();
	while (isBlocked())
	{
		if (!globalConnected())
			throw MemoryException("before: global not connected", this->pid);
	}
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
	if (!boardPtr())
		throw MemoryException("startJumpFrame: board ptr not found", this->pid);
	if (jumpingFrame) return false;
	jumpingFrame = true;
	pCurrentPhaseCode = &jumpingPhaseCode();
	pCurrentRunState = &jumpingRunState();
	pCurrentSyncMethod = &jumpingSyncMethod();


	// 非syncMethod -> 跳帧syncMethod | 锁所有权变化
	// mutex -> spin | extend -> extend 保持跳帧时全程拿锁即可, 不做事
	// spin -> mutex | dll -> extend 最后waitMutex拿锁, 不做事
	// mutex -> mutex | extend -> dll 放锁
	// spin -> spin | dll -> dll 不做事

	if (jumpingSyncMethod() == SyncMethod::MUTEX && syncMethod() == SyncMethod::MUTEX)
		releaseMutex<false>();
	
	jumpingPhaseCode() = PhaseCode::CONTINUE;
	phaseCode() = PhaseCode::JUMP_FRAME;
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

	pCurrentPhaseCode = &phaseCode();
	pCurrentRunState = &runState();
	pCurrentSyncMethod = &syncMethod();

	phaseCode() = PhaseCode::WAIT;
	jumpingPhaseCode() = PhaseCode::CONTINUE;
	while (jumpingRunState() == RunState::OVER)
	{
		if (!globalConnected())
			throw MemoryException("endJumpFrame: global hook not connected", this->pid);
	} // give dll time to get mutex
	if (jumpingSyncMethod() == SyncMethod::MUTEX && syncMethod() == SyncMethod::MUTEX)
		waitMutex<false>();
	return true;
}

void Memory::untilGameExecuted() const
{
	while (getCurrentPhaseCode() != PhaseCode::WAIT)
	{
		if (!globalConnected())
			throw MemoryException("untilGameExecuted: global hook not connected", this->pid);
	}
}

std::optional<std::unique_ptr<char[]>> Memory::readBytes(uint32_t size, const uint32_t* offsets, uint32_t len)
{
	if (size > BUFFER_SIZE) throw std::invalid_argument("readBytes: too many bytes");
	if (len > OFFSET_LENGTH) throw std::invalid_argument("readBytes: too many offsets");
	if (!isShmPrepared())
	{
		auto remotePtr = getRemotePtr<char[]>(offsets, len);
		if (!remotePtr) return {};
		auto ret = std::make_unique<char[]>(size);
		ReadProcessMemory(hPvz, remotePtr, ret.get(), size, nullptr);
		return ret;
	}
	auto p = _readMemory(size, offsets, len);
	if (!p) return {};
	auto ret = std::make_unique<char[]>(size);
	CopyMemory(ret.get(), const_cast<const void*>(p), size);
	return ret;
}

bool Memory::writeBytes(const char* in, uint32_t size, const uint32_t* offsets, uint32_t len)
{
	if (size > BUFFER_SIZE) throw std::invalid_argument("writeBytes: too many bytes");
	if (len > OFFSET_LENGTH) throw std::invalid_argument("writeBytes: too many offsets");
	if (!isShmPrepared())
	{
		auto remotePtr = getRemotePtr<char[]>(offsets, len);
		if (!remotePtr) return false;
		WriteProcessMemory(hPvz, remotePtr, in, size, nullptr);
		return true;
	}
	return _writeMemory(in, size, offsets, len);
}

bool Memory::runCode(const char* codes, size_t len) const
{
	if (len > SHARED_MEMORY_SIZE)
		throw std::invalid_argument("runCode: too many codes");
	
	if (!isShmPrepared())
		throw MemoryException("runCode: main loop not prepared", this->pid);

	CopyMemory(getAsmPtr(), codes, len);
	getCurrentPhaseCode() = PhaseCode::RUN_CODE;
	untilGameExecuted();
	if (executeResult() == ExecuteResult::SUCCESS) return true;
	if (executeResult() == ExecuteResult::FAIL) return false;
	throw MemoryException("runCode: unexpected behavior", this->pid);
}

void Memory::startControl()
{
	if (hookConnected(HookPosition::MAIN_LOOP)) return;
	phaseCode() = PhaseCode::CONTINUE;
	jumpingPhaseCode() = PhaseCode::CONTINUE;
	openHook(HookPosition::MAIN_LOOP); // mutex: this process
	before();
}

void Memory::endControl()
{
	if (!hookConnected(HookPosition::MAIN_LOOP)) return;
	if (!isShmPrepared())
		throw MemoryException("endControl: main loop not prepared", this->pid);
	if (jumpingFrame) endJumpFrame();
	releaseMutex<>();
	closeHook(HookPosition::MAIN_LOOP);
	phaseCode() = PhaseCode::CONTINUE;
	jumpingPhaseCode() = PhaseCode::CONTINUE;
	while (runState() == RunState::OVER)
	{
		if (!globalConnected())
			throw MemoryException("endControl: global not connected", this->pid);
	}
}

void Memory::openHook(HookPosition hook)
{
	hookStateArr()[getHookIndex(hook)] = HookState::CONNECTED;
}

void Memory::closeHook(HookPosition hook)
{
	hookStateArr()[getHookIndex(hook)] = HookState::NOT_CONNECTED;
}

void Memory::setSyncMethod(SyncMethod val)
{
	if (hookConnected(HookPosition::MAIN_LOOP))
		throw MemoryException(
			"setSyncMethod: cannot set sync method when main loop hook is connected", this->pid);
	syncMethod() = val;
}

void Memory::setJumpingSyncMethod(SyncMethod val)
{
	if (jumpingFrame)
		throw MemoryException(
			"setJumpingSyncMethod: cannot set jumping sync method when jumping frame", this->pid);
	jumpingSyncMethod() = val;
}

std::tuple<bool, uint32_t> Memory::getPBoard() const
{
	auto t = isBoardPtrValid();
	isBoardPtrValid() = true;
	return { t, boardPtr() };
}

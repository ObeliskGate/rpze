#include "stdafx.h"
#include "Memory.h"

#define __until(expr) do {} while (!(expr))

void Memory::getRemoteMemoryAddress()
{
	if (!isShmPrepared())
		throw MemoryException("getRemoteMemoryAddress: main loop not prepared", pid);
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY_PTR;
	untilGameExecuted();
	if (executeResult() == ExecuteResult::SUCCESS)
	{
		remoteMemoryAddress = *static_cast<volatile uint32_t*>(getReadWriteVal());
	}
	else throw MemoryException("getRemoteMemoryAddress: unexpected behavior", pid);
}

Memory::Memory(DWORD pid)
{
	auto fileName = std::wstring{ SHARED_MEMORY_NAME_AFFIX }.append(std::to_wstring(pid));
	hMemory = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, fileName.c_str());
	if (hMemory == NULL)
	{
		std::cerr << "find shared memory failed: " << GetLastError() << std::endl;
		throw MemoryException("find shared memory failed", pid);
	}
	pBuf = MapViewOfFile(hMemory, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEMORY_SIZE);
	if (pBuf == NULL)
	{
		std::cerr << "create shared memory failed: " << GetLastError() << std::endl;
		throw MemoryException("create shared memory failed", pid);
	}
	std::cout << "find shared memory success" << std::endl;

	pCurrentPhaseCode = &phaseCode();
	pCurrentRunState = &runState();
	this->pid = pid;
	this->hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hPvz)
	{
		throw MemoryException("cannot find game process!", pid);
	}
	globalState() = HookState::CONNECTED;
	startControl();
	before();
	getRemoteMemoryAddress();
	endControl();
}

Memory::~Memory()
{
	endControl();
	globalState() = HookState::NOT_CONNECTED;
	UnmapViewOfFile(pBuf);
	CloseHandle(hMemory);
	CloseHandle(hPvz);
}

std::optional<volatile void*> Memory::_readMemory(uint32_t size, const uint32_t* offsets, uint32_t len)
{
	memoryNum() = size;
	CopyMemory(getOffsets(), offsets, sizeof(uint32_t) * len);
	getOffsets()[len] = OFFSET_END;
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY;
	untilGameExecuted(); 
	if (executeResult() == ExecuteResult::SUCCESS) return getReadWriteVal();
	if (executeResult() == ExecuteResult::FAIL) return {};
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
	while (isBlocked())
	{
		if (globalState() == HookState::NOT_CONNECTED) 
			throw MemoryException("before: hook not connected", this->pid);
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
	jumpingPhaseCode() = PhaseCode::WAIT;
	phaseCode() = PhaseCode::JUMP_FRAME;
	before();
	return true;
}

bool Memory::endJumpFrame()
{
	if (!isShmPrepared())
throw MemoryException("endJumpFrame: main loop hook not prepared", this->pid);
	
	if (!jumpingFrame) return false;
	jumpingFrame = false;
	pCurrentPhaseCode = &phaseCode();
	pCurrentRunState = &runState();
	phaseCode() = PhaseCode::WAIT;
	jumpingPhaseCode() = PhaseCode::CONTINUE;
	before();
	return true;
}

void Memory::untilGameExecuted() const
{
	while (getCurrentPhaseCode() != PhaseCode::WAIT)
	{
		if (globalState() == HookState::NOT_CONNECTED) 
			throw MemoryException("untilGameExecuted: hook not connected", this->pid);
	}
}

std::optional<std::unique_ptr<char[]>> Memory::readBytes(uint32_t size, const uint32_t* offsets, uint32_t len)
{
	if (size > BUFFER_SIZE) throw std::invalid_argument("readBytes: too many bytes");
	if (len > OFFSET_LENGTH) throw std::invalid_argument("readBytes: too many offsets");
	if (!isShmPrepared())
	{
		auto remotePtr = getRemotePtr<char[]>(offsets, len);
		if (!remotePtr.has_value()) return {};
		auto ret = std::make_unique<char[]>(size);
		ReadProcessMemory(hPvz, *remotePtr, ret.get(), size, nullptr);
		return ret;
	}
	auto p = _readMemory(size, offsets, len);
	if (!p.has_value()) return {};
	auto ret = std::make_unique<char[]>(size);
	memcpy(ret.get(), const_cast<const void*>(*p), size);
	return ret;
}

bool Memory::writeBytes(const char* in, uint32_t size, const uint32_t* offsets, uint32_t len)
{
	if (size > BUFFER_SIZE) throw std::invalid_argument("writeBytes: too many bytes");
	if (len > OFFSET_LENGTH) throw std::invalid_argument("writeBytes: too many offsets");
	if (!isShmPrepared())
	{
		auto remotePtr = getRemotePtr<char[]>(offsets, len);
		if (!remotePtr.has_value()) return false;
		WriteProcessMemory(hPvz, *remotePtr, in, size, nullptr);
		return true;
	}
	return _writeMemory(in, size, offsets, len);
}

bool Memory::runCode(const char* codes, size_t len) const
{
	if (len > SHARED_MEMORY_SIZE)
		throw std::invalid_argument("runCode: too many codes");
	
	if (!isShmPrepared())
	{
		throw MemoryException("runCode: main loop not prepared", this->pid);
	}
	memcpy(getAsmPtr(), codes, len);
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
	openHook(HookPosition::MAIN_LOOP);
	before();
}

void Memory::endControl()
{
	if (!hookConnected(HookPosition::MAIN_LOOP)) return;
	if (jumpingFrame) endJumpFrame();
	closeHook(HookPosition::MAIN_LOOP);
	phaseCode() = PhaseCode::CONTINUE;
	jumpingPhaseCode() = PhaseCode::CONTINUE;
}

void Memory::openHook(HookPosition hook)
{
	hookStateArr()[getHookIndex(hook)] = HookState::CONNECTED;
}

void Memory::closeHook(HookPosition hook)
{
	hookStateArr()[getHookIndex(hook)] = HookState::NOT_CONNECTED;
}

std::tuple<bool, uint32_t> Memory::getPBoard() const
{
	auto t = isBoardPtrValid();
	isBoardPtrValid() = true;
	return { t, boardPtr() };
}

#undef __until

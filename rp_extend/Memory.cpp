#include "stdafx.h"
#include "Memory.h"

#define __until(expr) do {} while (!(expr))

void Memory::getRemoteMemoryAddress()
{
	if (!isShmPrepared())
	{
		throw std::exception("getRemoteMemoryAddress: main loop not prepared");
	}
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY_PTR;
	untilGameExecuted();
	if (executeResult() == ExecuteResult::SUCCESS)
	{
		remoteMemoryAddress = *static_cast<volatile uint32_t*>(getReadWriteVal());
	}
	else throw std::exception("getRemoteMemoryAddress: unexpected behavior");
}

Memory::Memory(DWORD pid)
{
	auto fileName = std::wstring{ SHARED_MEMORY_NAME_AFFIX }.append(std::to_wstring(pid));
	hMemory = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, fileName.c_str());
	if (hMemory == NULL)
	{
		std::cerr << "find shared memory failed: " << GetLastError() << std::endl;
		throw std::exception("find shared memory failed");
	}
	pBuf = MapViewOfFile(hMemory, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEMORY_SIZE);
	if (pBuf == NULL)
	{
		std::cerr << "create shared memory failed: " << GetLastError() << std::endl;
		throw std::exception("create shared memory failed");
	}
	std::cout << "find shared memory success" << std::endl;

	pCurrentPhaseCode = &phaseCode();
	pCurrentRunState = &runState();
	this->pid = pid;
	this->hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hPvz)
	{
		throw std::exception("cannot find game process!");
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
	throw std::exception("_readMemory: unexpected behavior");
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
	throw std::exception("_writeMemory: unexpected behavior");
}

void Memory::before() const
{
	while (isBlocked())
	{
		if (globalState() == HookState::NOT_CONNECTED) throw std::exception("before: hook not connected");
	}
}

void Memory::skipFrames(size_t num) const
{
	if (!isShmPrepared())
	{
		throw std::exception("before: main loop hook not connected");
	}
	for (size_t i = 0; i < num; i++)
	{
		next();
		before();
	}
}

bool Memory::startJumpFrame()
{
	if (!isShmPrepared())
	{
		throw std::exception("startJumpFrame: main loop hook not prepared");
	}
	if (!boardPtr())
	{
		throw std::exception("startJumpFrame: board ptr not found");
	}
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
	{
		throw std::exception("endJumpFrame: main loop hook not prepared");
	}
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
			throw std::exception("untilGameExecuted: hook not connected");
	}
}

std::optional<std::unique_ptr<char[]>> Memory::readBytes(uint32_t size, const uint32_t* offsets, uint32_t len)
{
	if (size > BUFFER_SIZE) throw std::exception("readBytes: too many bytes");
	if (len > OFFSET_LENGTH) throw std::exception("readBytes: too many offsets");
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
	if (size > BUFFER_SIZE) throw std::exception("writeBytes: too many bytes");
	if (len > OFFSET_LENGTH) throw std::exception("writeBytes: too many offsets");
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
	{
		throw std::exception("runCode: too many codes");
	}
	if (!isShmPrepared())
	{
		throw std::exception("runCode: main loop not prepared");
	}
	memcpy(getAsmPtr(), codes, len);
	getCurrentPhaseCode() = PhaseCode::RUN_CODE;
	untilGameExecuted();
	if (executeResult() == ExecuteResult::SUCCESS) return true;
	if (executeResult() == ExecuteResult::FAIL) return false;
	throw std::exception("runCode: unexpected behavior");
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

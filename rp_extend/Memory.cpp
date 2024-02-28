#include "stdafx.h"
#include "Memory.h"

#define __until(expr) do {} while (!(expr))

void Memory::getRemoteMemoryAddress()
{
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
	if (!hookConnected(HookPosition::MAIN_LOOP))
	{
		throw std::exception("before: main loop hook not connected");
	}
	while (isBlocked())
	{
		if (globalState() == HookState::NOT_CONNECTED) throw std::exception("before: hook not connected");
	}
}

bool Memory::startJumpFrame()
{
	if (!hookConnected(HookPosition::MAIN_LOOP))
	{
		throw std::exception("startJumpFrame: main loop hook not connected");
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
	return true;
}

bool Memory::endJumpFrame()
{
	if (!hookConnected(HookPosition::MAIN_LOOP))
	{
		throw std::exception("endJumpFrame: main loop hook not connected");
	}
	if (!jumpingFrame) return false;
	jumpingFrame = false;
	pCurrentPhaseCode = &phaseCode();
	pCurrentRunState = &runState();
	phaseCode() = PhaseCode::WAIT;
	jumpingPhaseCode() = PhaseCode::CONTINUE;
	return true;
}

void Memory::untilGameExecuted() const
{
	while (getCurrentPhaseCode() != PhaseCode::WAIT)
	{
		if (globalState() == HookState::NOT_CONNECTED) throw std::exception("untilGameExecuted: hook not connected");
	}
}

std::optional<std::unique_ptr<char[]>> Memory::readBytes(uint32_t size, const uint32_t* offsets, uint32_t len)
{
	if (size > BUFFER_SIZE) throw std::exception("readBytes: too many bytes");
	if (len > LENGTH) throw std::exception("readBytes: too many offsets");
	if (!hookConnected(HookPosition::MAIN_LOOP))
	{
		HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (!hPvz)
		{
			throw std::exception("readBytes: open game process failed");
		}	
		uint64_t basePtr = offsets[0];
		do
		{
			for (size_t i = 1; i < len; i++)
			{
				ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &basePtr, sizeof(uint32_t), nullptr);
				if (!basePtr) break;
				basePtr += offsets[i];
			}
			if (!basePtr) break;
			auto ret = std::make_unique<char[]>(size);
			ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), ret.get(), size, nullptr);
			CloseHandle(hPvz);
			return ret;
		} while (false);
		CloseHandle(hPvz);
		return {};
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
	if (len > LENGTH) throw std::exception("writeBytes: too many offsets");
	if (!hookConnected(HookPosition::MAIN_LOOP))
	{
		HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (!hPvz)
		{
			throw std::exception("writeBytes: open game process failed");
		}
		uint64_t basePtr = offsets[0];
		do
		{
			for (size_t i = 1; i < len; i++)
			{
				ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &basePtr, sizeof(uint32_t), nullptr);
				if (!basePtr) break;
				basePtr += offsets[i];
			}
			if (!basePtr) break;
			WriteProcessMemory(hPvz, reinterpret_cast<LPVOID>(basePtr), in, size, nullptr);
			CloseHandle(hPvz);
			return true;
		} while (false);
		CloseHandle(hPvz);
		return false;
	}
	return _writeMemory(in, size, offsets, len);
}

bool Memory::runCode(const char* codes, size_t len) const
{
	if (len > SHARED_MEMORY_SIZE)
	{
		throw std::exception("runCode: too many codes");
	}
	if (!hookConnected(HookPosition::MAIN_LOOP))
	{
		throw std::exception("runCode: main loop hook not connected");
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
	phaseCode() = PhaseCode::CONTINUE;
	jumpingPhaseCode() = PhaseCode::CONTINUE;
	openHook(HookPosition::MAIN_LOOP);
	__until(isBlocked());
	next();
}

void Memory::endControl()
{
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

#undef __until

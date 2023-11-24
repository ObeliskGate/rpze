#include "stdafx.h"
#include "Memory.h"

#define __until(expr) do {} while (!(expr))

void Memory::getRemoteMemoryAddress()
{
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY_PTR;
	__until(getCurrentPhaseCode() == PhaseCode::WAIT);

	if (executeResult() == ExecuteResult::SUCCESS)
		remoteMemoryAddress = *static_cast<volatile uint32_t*>(getReadResult());
	else throw std::exception("unexpected behavior");
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
	pBuf = MapViewOfFile(hMemory, FILE_MAP_ALL_ACCESS, 0, 0, 1024);
	if (pBuf == NULL)
	{
		std::cerr << "create shared memory failed: " << GetLastError() << std::endl;
		throw std::exception("create shared memory failed");
	}
	std::cout << "find shared memory success" << std::endl;

	pCurrentPhaseCode = &phaseCode();
	pCurrentRunState = &runState();
	globalState() = GlobalState::NOT_CONNECTED;
	this->pid = pid;
}

std::optional<volatile void*> Memory::_readMemory(BYTE size, const std::vector<int32_t>& offsets)
{
	if (offsets.size() > LENGTH) return {};
	memoryNum() = size;
	CopyMemory(getOffsets(), offsets.data(), sizeof(int32_t) * offsets.size());
	getOffsets()[offsets.size()] = OFFSET_END;
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY;
	__until(getCurrentPhaseCode() == PhaseCode::WAIT);//等待执行完成
	if (executeResult() == ExecuteResult::SUCCESS) return getReadResult();
	if (executeResult() == ExecuteResult::FAIL) return {};
	throw std::exception("unexpected behavior of _readMemory");
}

bool Memory::_writeMemory(const void* pVal, BYTE size, const std::vector<int32_t>& offsets)
{
	if (offsets.size() > LENGTH) return false;
	memoryNum() = size;
	memcpy(getWrittenVal(), pVal, size);
	CopyMemory(getOffsets(), offsets.data(), sizeof(int32_t) * offsets.size());
	getOffsets()[offsets.size()] = OFFSET_END;

	getCurrentPhaseCode() = PhaseCode::WRITE_MEMORY;
	__until(getCurrentPhaseCode() == PhaseCode::WAIT);  //等待执行完成
	if (executeResult() == ExecuteResult::SUCCESS) return true;
	if (executeResult() == ExecuteResult::FAIL) return false;
	throw std::exception("unexpected behavior of _writeMemory");
}

bool Memory::startJumpFrame()
{
	if (isJumpingFrame) return false;
	isJumpingFrame = true;
	pCurrentPhaseCode = &jumpingPhaseCode();
	pCurrentRunState = &jumpingRunState();
	jumpingPhaseCode() = PhaseCode::WAIT;
	phaseCode() = PhaseCode::JUMP_FRAME;
	return true;
}

bool Memory::endJumpFrame()
{
	if (!isJumpingFrame) return false;
	isJumpingFrame = false;
	pCurrentPhaseCode = &phaseCode();
	pCurrentRunState = &runState();
	phaseCode() = PhaseCode::WAIT;
	jumpingPhaseCode() = PhaseCode::CONTINUE;
	return true;
}

bool Memory::runCode(const char* codes, int num)
{
	if (num > 400)
	{
		executeResult() = ExecuteResult::FAIL;
		throw std::exception("runCode: too many codes");
	}
	CopyMemory(getAsmPtr(), codes, num);
	getCurrentPhaseCode() = PhaseCode::RUN_CODE;
	__until(getCurrentPhaseCode() == PhaseCode::WAIT);  //等待执行完成
	if (executeResult() == ExecuteResult::SUCCESS) return true;
	if (executeResult() == ExecuteResult::FAIL) return false;
	throw std::exception("unexpected behavior of runCode");
}

void Memory::startControl()
{
	phaseCode() = PhaseCode::CONTINUE;
	jumpingPhaseCode() = PhaseCode::CONTINUE;
	globalState() = GlobalState::CONNECTED;
}

void Memory::endControl()
{
	globalState() = GlobalState::NOT_CONNECTED;
	phaseCode() = PhaseCode::CONTINUE;
	jumpingPhaseCode() = PhaseCode::CONTINUE;
}

uint32_t Memory::getWrittenAddress()
{
	if (!remoteMemoryAddress) getRemoteMemoryAddress();
	return remoteMemoryAddress + 88;
}

#undef __until

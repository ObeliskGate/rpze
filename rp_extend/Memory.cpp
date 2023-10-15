#include "stdafx.h"
#include "Memory.h"

#define __until(expr) do {} while (!(expr))

void Memory::getRemoteMemoryAddress()
{
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY_PTR;
	__until(getCurrentPhaseCode() == PhaseCode::WAIT);

	if (getExecuteResult() == ExecuteResult::SUCCESS)
		remoteMemoryAddress = *static_cast<volatile uint32_t*>(getReadResult());
	else throw std::exception("unexpected behavior");
}

Memory::Memory(DWORD pid)
{
	auto fileName = std::wstring{ SHARED_MEMORY_NAME_AFFIX }.append(std::to_wstring(pid));
	hMemory = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, fileName.c_str());
	if (hMemory == NULL)
	{
		std::cerr << "find shared memory failed" << GetLastError() << std::endl;
		throw std::exception("find shared memory failed");
	}
	pBuf = MapViewOfFile(hMemory, FILE_MAP_ALL_ACCESS, 0, 0, 1024);
	if (pBuf == NULL)
	{
		std::cerr << "create shared memory failed: " << GetLastError() << std::endl;
		throw std::exception("create shared memory failed");
	}
	else
	{
		std::cout << "find shared memory success" << std::endl;
	}

	pCurrentPhaseCode = &getPhaseCode();
	pCurrentRunState = &getRunState();
	getGlobalState() = GlobalState::CONNECTED;
	this->pid = pid;
}

std::optional<volatile void*> Memory::_readMemory(BYTE size, const std::vector<int32_t>& offsets)
{
	getMemoryNum() = size;
	int idx = 0;
	for (auto it : offsets)
	{
		getOffsets()[idx] = it;
		idx++;
	}
	getOffsets()[idx] = OFFSET_END;
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY;
	__until(getCurrentPhaseCode() == PhaseCode::WAIT);//等待执行完成
	if (getExecuteResult() == ExecuteResult::SUCCESS) return getReadResult();
	if (getExecuteResult() == ExecuteResult::FAIL) return {};
	throw std::exception("unexpected behavior");
}

bool Memory::_writeMemory(const void* pVal, BYTE size, const std::vector<int32_t>& offsets)
{
	getMemoryNum() = size;
	memcpy(getWrittenVal(), pVal, size);
	int idx = 0;
	for (auto it : offsets)
	{
		getOffsets()[idx] = it;
		idx++;
	}
	getOffsets()[idx] = OFFSET_END;

	getCurrentPhaseCode() = PhaseCode::WRITE_MEMORY;
	__until(getCurrentPhaseCode() == PhaseCode::WAIT);  //等待执行完成
	if (getExecuteResult() == ExecuteResult::SUCCESS) return true;
	if (getExecuteResult() == ExecuteResult::FAIL) return false;
	throw std::exception("unexpected behavior");
}

bool Memory::startJumpFrame()
{
	if (isJumpingFrame) return false;
	isJumpingFrame = true;
	pCurrentPhaseCode = &getJumpingPhaseCode();
	pCurrentRunState = &getJumpingRunState();
	getJumpingPhaseCode() = PhaseCode::WAIT;
	getPhaseCode() = PhaseCode::JUMP_FRAME;
	return true;
}

bool Memory::endJumpFrame()
{
	if (!isJumpingFrame) return false;
	isJumpingFrame = false;
	pCurrentPhaseCode = &getPhaseCode();
	pCurrentRunState = &getRunState();
	getPhaseCode() = PhaseCode::WAIT;
	getJumpingPhaseCode() = PhaseCode::CONTINUE;
	return true;
}

bool Memory::runCode(const char* codes, int num)
{
	memcpy(reinterpret_cast<char*>(getAsmPtr()), codes, num);

	getCurrentPhaseCode() = PhaseCode::RUN_CODE;
	__until(getCurrentPhaseCode() == PhaseCode::WAIT);  //等待执行完成
	if (getExecuteResult() == ExecuteResult::SUCCESS) return true;
	if (getExecuteResult() == ExecuteResult::FAIL) return false;
	throw std::exception("unexpected behavior");
}

void Memory::endControl()
{
	getGlobalState() = GlobalState::NOT_CONNECTED;
	getPhaseCode() = PhaseCode::CONTINUE;
	getJumpingPhaseCode() = PhaseCode::CONTINUE;
}

uint32_t Memory::getWrittenAddress()
{
	if (!remoteMemoryAddress) getRemoteMemoryAddress();
	return remoteMemoryAddress + 72;
}

#undef __until

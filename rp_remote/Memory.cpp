#include "stdafx.h"
#include "Memory.h"

Memory::Memory(HANDLE hPvz)
{
	auto fileName = std::wstring(SHARED_MEMORY_NAME_AFFIX).append(std::to_wstring(GetProcessId(hPvz)));
	hMemory = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, fileName.c_str());
	if (hMemory == NULL)
	{
		std::cerr << "Ѱ�ҹ����ڴ�ʧ��: " << GetLastError() << std::endl;
		throw std::exception("find shared memory failed");
	}
	pBuf = MapViewOfFile(hMemory, FILE_MAP_ALL_ACCESS, 0, 0, 1024);
	if (pBuf == NULL)
	{
		std::cerr << "�����ļ���ͼʧ��: " << GetLastError() << std::endl;
		throw std::exception("create shared memory failed");
	}
	else
	{
		std::cout << "Ѱ�ҹ����ڴ�ɹ�" << std::endl;
	}

}

std::optional<volatile void*> Memory::_readMemory(BYTE size,const std::initializer_list<int32_t>& offsets)
{
	getMemoryNum() = size;
	int idx = 0;
	for (auto it : offsets)
	{
		getOffsets()[idx] = it;
		idx++;
	}
	getOffsets()[idx] = OFFSET_END;
	getPhaseCode() = PhaseCode::READ_MEMORY;
	getReadWriteState() = ReadWriteState::FUNCTIONING;	// �����remote��!!!
	while (getReadWriteState() == ReadWriteState::FUNCTIONING) { std::cout << "f" << std::endl; } 
	auto tmp = getReadWriteState();
	getReadWriteState() = ReadWriteState::READY;
	if (tmp == ReadWriteState::FAIL) return {};
	if (tmp == ReadWriteState::SUCCESS) return getReadResult();
	throw std::exception("unexpected behavior");
}

bool Memory::_writeMemory(const void* pVal, BYTE size, const std::initializer_list<int32_t>& offsets)
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
	getPhaseCode() = PhaseCode::WRITE_MEMORY;
	getReadWriteState() = ReadWriteState::FUNCTIONING;	// �����remote��!!!
	while (getReadWriteState() == ReadWriteState::FUNCTIONING) { std::cout << "f" << std::endl; } // һ��Ҫ�ǲ�����ready ����Ҳ��
	auto tmp = getReadWriteState();
	getReadWriteState() = ReadWriteState::READY;
	if (tmp == ReadWriteState::FAIL) return false;
	if (tmp == ReadWriteState::SUCCESS) return true;
	throw std::exception("unexpected behavior");
}

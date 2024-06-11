#include "stdafx.h"
#include "SharedMemory.h"

SharedMemory::SharedMemory()
{
	auto hProc = GetCurrentProcess();
	auto nameAffix = std::wstring{ UU_NAME_AFFIX } + std::to_wstring(GetProcessId(hProc));
	hMapFile = CreateFileMappingW(
		INVALID_HANDLE_VALUE,
		nullptr,                
		PAGE_READWRITE,    
		0,                      
		SHARED_MEMORY_SIZE,
		(nameAffix + L"_shm").c_str());
	if (!hMapFile)
	{
		std::cout << "cannot create shared memory: " << GetLastError() << std::endl;
		throw std::runtime_error("cannot create shared memory");
	}
	sharedMemoryPtr = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEMORY_SIZE);
	if (sharedMemoryPtr)
	{
		std::cout << "create shared memory success" << std::endl;
	}

	for (size_t i = 0; i < OFFSETS_LEN; i++)
	{
		getOffsets()[i] = OFFSET_END;
	}
	globalState() = HookState::NOT_CONNECTED;
	isBoardPtrValid() = false;
	for (size_t i = 0; i < HOOK_LEN; i++)
	{
		hookStateArr()[i] = HookState::NOT_CONNECTED;
	}

	hMutex = CreateMutexW(nullptr, FALSE, (nameAffix + L"_mutex").c_str());
	if (!hMutex)
	{
		std::cout << "cannot create mutex: " << GetLastError() << std::endl;
		throw std::exception();
	}
}

SharedMemory::~SharedMemory()
{
	globalState() = HookState::NOT_CONNECTED;
	UnmapViewOfFile(sharedMemoryPtr);
	CloseHandle(hMapFile);
	CloseHandle(hMutex);
}

void* SharedMemory::getReadWritePtr() const
{
	uint32_t ptr = getOffsets()[0];
	for (size_t i = 1; i < OFFSETS_LEN; i++)
	{
		if (getOffsets()[i] == OFFSET_END) break;
		ptr = *reinterpret_cast<uint32_t*>(ptr);
		if (!ptr) return {};
		ptr += getOffsets()[i];
	}

	if (!ptr || ptr == OFFSET_END) return nullptr;
	return reinterpret_cast<void*>(ptr);
}

void SharedMemory::waitMutex() const
{
#ifdef _DEBUG
	switch (WaitForSingleObject(hMutex, 500))
#else
	switch (WaitForSingleObject(hMutex, INFINITE))
#endif
	{
	case WAIT_OBJECT_0:
#ifdef _DEBUG
		std::cout << "waitMutex: WAIT_OBJECT_0" << std::endl;
#endif
		break;
	case WAIT_ABANDONED:
		std::cout << "waitMutex: WAIT_ABANDONED" << std::endl;
		throw std::exception();
#ifdef _DEBUG
	case WAIT_TIMEOUT:
		std::cout << "waitMutex: WAIT_TIMEOUT" << std::endl;
		throw std::exception();
#endif
	case WAIT_FAILED:
		std::cout << "waitMutex: WAIT_FAILED, error" << GetLastError() << std::endl;
		throw std::exception();
	default:
		std::cout << "waitMutex: unexpected behavior" << std::endl;
		throw std::exception();
	}
}

void SharedMemory::releaseMutex() const
{
	if (!ReleaseMutex(hMutex))
	{
		std::cout << "releaseMutex: failed, error: " << GetLastError() << std::endl;
		throw std::exception();
	}
#ifdef _DEBUG
	std::cout << "releaseMutex: success" << std::endl;
#endif
}

SharedMemory* SharedMemory::getInstance()
{
	if (instancePtr != nullptr) return instancePtr;
	instancePtr = new SharedMemory();
	return instancePtr;
}

bool SharedMemory::deleteInstance()
{
	if (!instancePtr) return false;
	delete instancePtr;
	instancePtr = nullptr;
	return true;
}

bool SharedMemory::readMemory() const
{
	*static_cast<volatile uint64_t*>(getReadWriteVal()) = 0;
	bool b;
	do
	{
		auto p = getReadWritePtr();
		if (!p)
		{
			b = false;
			break;
		}
		CopyMemory(getReadWriteVal(), p, memoryNum());
		b = true;
	} while (false);
	executeResult() = b ? ExecuteResult::SUCCESS : ExecuteResult::FAIL;
	return b;
}

bool SharedMemory::writeMemory() const
{
	bool b;
	do {
		auto p = getReadWritePtr();
		if (!p)
		{
			b = false;
			break;
		}
		CopyMemory(p, getReadWriteVal(), memoryNum());
		b = true;
	} while (false);
	executeResult() = b ? ExecuteResult::SUCCESS : ExecuteResult::FAIL;
	return b;
}

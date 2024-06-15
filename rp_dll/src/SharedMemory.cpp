#include "stdafx.h"
#include <stdexcept>
#include <string>
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
	sharedMemoryPtr = static_cast<Shm*>(MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEMORY_SIZE));
	if (sharedMemoryPtr)
	{
		std::cout << "create shared memory success" << std::endl;
#ifndef NDEBUG
		std::cout << "shared memory ptr: " << sharedMemoryPtr << std::endl;
#endif
	}

	for (size_t i = 0; i < Shm::OFFSETS_LEN; i++)
	{
		shm().offsets[i] = Shm::OFFSET_END;
	}
	shm().globalState = HookState::NOT_CONNECTED;
	shm().isBoardPtrValid = false;
	for (size_t i = 0; i < Shm::HOOK_LEN; i++)
	{
		shm().hookStateArr[i] = HookState::NOT_CONNECTED;
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
	shm().globalState = HookState::NOT_CONNECTED;
	UnmapViewOfFile(const_cast<Shm*>(sharedMemoryPtr));
	CloseHandle(hMapFile);
	CloseHandle(hMutex);
}

void* SharedMemory::getReadWritePtr() const
{
	uint32_t ptr = shm().offsets[0];
	for (size_t i = 1; i < Shm::OFFSETS_LEN; i++)
	{
		if (shm().offsets[i] == Shm::OFFSET_END) break;
		ptr = *reinterpret_cast<uint32_t*>(ptr);
		if (!ptr) return nullptr;
		ptr += shm().offsets[i];
	}

	if (!ptr || ptr == Shm::OFFSET_END) return nullptr;
	return reinterpret_cast<void*>(ptr);
}

void SharedMemory::waitMutex() const
{
#ifndef NDEBUG
	switch (WaitForSingleObject(hMutex, 500))
#else
	switch (WaitForSingleObject(hMutex, INFINITE))
#endif
	{
	case WAIT_OBJECT_0:
#ifndef NDEBUG
		std::cout << "waitMutex: WAIT_OBJECT_0" << std::endl;
#endif
		break;
	case WAIT_ABANDONED:
		std::cout << "waitMutex: WAIT_ABANDONED" << std::endl;
		throw std::exception();
#ifndef NDEBUG
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
#ifndef NDEBUG
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
	*reinterpret_cast<volatile uint64_t*>(shm().readWriteBuffer) = 0;
	bool b;
	do
	{
		auto p = getReadWritePtr();
		if (!p)
		{
			b = false;
			break;
		}
		CopyMemory(const_cast<void*>(shm().getReadWriteBuffer<>()), p, shm().memoryNum);
		b = true;
	} while (false);
	shm().executeResult = b ? ExecuteResult::SUCCESS : ExecuteResult::FAIL;
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
		CopyMemory(p, const_cast<void*>(shm().getReadWriteBuffer<>()), shm().memoryNum);
		b = true;
	} while (false);
	shm().executeResult = b ? ExecuteResult::SUCCESS : ExecuteResult::FAIL;
	return b;
}

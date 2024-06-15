#pragma once
#include "shm.h"
#include "stdafx.h"
class SharedMemory
{
	inline static SharedMemory* instancePtr = nullptr;

	volatile Shm* sharedMemoryPtr;
	HANDLE hMapFile;
	HANDLE hMutex;

	SharedMemory();
	~SharedMemory();

	// 返回用来read或write的指针
	void* getReadWritePtr() const;
public:
	volatile Shm& shm() const { return *sharedMemoryPtr; }

	void waitMutex() const;

	void releaseMutex() const;

	DWORD getSharedMemoryPtr() const { return reinterpret_cast<DWORD>(sharedMemoryPtr); }

	static SharedMemory* getInstance();

	static bool deleteInstance();

	// 读内存
	bool readMemory() const;

	// 写内存
	bool writeMemory() const;
};

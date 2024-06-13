#pragma once
#include "stdafx.h"
#include "Enums.h"

class SharedMemory
{
	inline static SharedMemory* instancePtr = nullptr;

	void* sharedMemoryPtr;
	HANDLE hMapFile;
	HANDLE hMutex;

	SharedMemory();
	~SharedMemory();

	// 返回用来read或write的指针
	void* getReadWritePtr() const;

	template <typename T = BYTE>
	T* getPtr() const { return static_cast<T*>(sharedMemoryPtr); }

	template <typename T>
	T& getRef(const int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }

public:


	static constexpr uint32_t BUFFER_OFFSET = 1024 * 4;
	static constexpr uint32_t BUFFER_SIZE = SHARED_MEMORY_SIZE - BUFFER_OFFSET;
	static constexpr uint32_t RESULT_OFFSET = 1024;
	static constexpr uint32_t RESULT_SIZE = BUFFER_OFFSET - RESULT_OFFSET;

	void waitMutex() const;

	void releaseMutex() const;

	void* getSharedMemoryPtr() const { return sharedMemoryPtr; }

	static SharedMemory* getInstance();

	static bool deleteInstance();

	// 怎么运行游戏
	volatile PhaseCode& phaseCode() const { return getRef<PhaseCode>(0); }

	// 游戏运行状态
	volatile RunState& runState() const { return getRef<RunState>(4); }

	// pBoard指针
	volatile uint32_t& boardPtr() const { return getRef<uint32_t>(8); }


	//  跳帧时怎么运行游戏
	volatile PhaseCode& jumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// 跳帧时游戏的运行状态
	volatile RunState& jumpingRunState() const { return getRef<RunState>(16); }

	// 读写内存时 要读写的内存的位数
	volatile const uint32_t& memoryNum() const { return getRef<uint32_t>(20); }


	static constexpr size_t OFFSETS_LEN = 16;
	static constexpr uint32_t OFFSET_END = std::numeric_limits<uint32_t>::max();
	// 读写内存时的偏移, 如{0x6a9ec0, 0x768, OFFSET_END, ...}, 遇到OFFSET_END停止读取
	volatile uint32_t* getOffsets() const { return reinterpret_cast<uint32_t*>(getPtr() + 24); }

	// 占位8个字节, 读写内存时 指向值 / 结果的指针
	void* getReadWriteVal() const { return getPtr() + BUFFER_OFFSET; }

	// 全局状态
	volatile HookState& globalState() const { return getRef<HookState>(90); }

	// 执行结果
	volatile ExecuteResult& executeResult() const { return getRef<ExecuteResult>(94); }

	// pBoard指针效验位
	volatile bool& isBoardPtrValid() const { return getRef<bool>(106); }

	static constexpr size_t HOOK_LEN = 16;
	// hook位置的状态
	volatile HookState* hookStateArr() const { return reinterpret_cast<HookState*>(getPtr() + 112); }

	volatile SyncMethod& syncMethod() const { return getRef<SyncMethod>(200); }

	volatile SyncMethod& jumpingSyncMethod() const { return getRef<SyncMethod>(204); }

	// 用来存放asm的指针, 从1024开始
	void* getAsmPtr() const { return getPtr() + BUFFER_OFFSET; }

	// 读内存
	bool readMemory() const;

	// 写内存
	bool writeMemory() const;
};

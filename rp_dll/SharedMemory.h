#pragma once
#include "pch.h"
#include "Enums.h"

class SharedMemory
{
	static SharedMemory* instancePtr;

	void* sharedMemoryPtr;
	HANDLE hMapFile;
	std::wstring sharedMemoryName;
	SharedMemory();
	~SharedMemory() { CloseHandle(hMapFile); }

	template<typename T = BYTE>
	inline T* getPtr() const { return reinterpret_cast<T*>(sharedMemoryPtr); }

	template<typename T>
	inline T& getRef(int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }

	// 返回用来read或write的指针
	std::optional<void*> getReadWritePtr() const;

public:
	static SharedMemory* const getInstance();

	static bool deleteInstance();

	// 共享内存名称
	inline std::wstring getName() const { return sharedMemoryName; }

	// 怎么运行游戏
	inline volatile PhaseCode& getPhaseCode() const { return getRef<PhaseCode>(0); }

	// 游戏运行状态
	inline RunState& getRunState() const { return getRef<RunState>(4); }

	// 游戏当前时间
	inline uint32_t& getGameTime() const { return getRef<uint32_t>(8); }

	//  跳帧时怎么运行游戏
	inline volatile PhaseCode& getJumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// 跳帧时游戏的运行状态
	inline RunState& getJumpingRunState() const { return getRef<RunState>(16); }

	// 读写内存时 要读写的内存的位数, 最大为8
	inline volatile const uint32_t& getMemoryNum() const { return getRef<uint32_t>(20); }


	static constexpr size_t LENGTH = 10;
	static constexpr int32_t OFFSET_END = -1;
	// 读写内存时的偏移, 如{0x6a9ec0, 0x768, OFFSET_END, ...}, 遇到OFFSET_END停止读取
	inline volatile int32_t* getOffsets() const { return reinterpret_cast<int32_t*>(getPtr() + 24); }

	// 占位8个字节, 读写内存时 指向写入的内存的内容的指针
	inline volatile const void* const getWrittenVal() const { return static_cast<void*>(getPtr() + 64); }

	// 占位8个字节, 读写内存时 指向读取内存结果的指针
	inline void* const getReadResult() const { return static_cast<void*>(getPtr() + 72); }

	inline ExecuteResult& getExecuteResult() const { return getRef<ExecuteResult>(84); }

	// 读内存
	bool readMemory();

	// 写内存
	bool writeMemory();
};
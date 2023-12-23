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
	~SharedMemory() 
	{ 
		UnmapViewOfFile(sharedMemoryPtr);
		CloseHandle(hMapFile); 
	}

	template<typename T = BYTE>
	inline T* getPtr() const { return static_cast<T*>(sharedMemoryPtr); }

	template<typename T>
	inline T& getRef(const int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }

	// 返回用来read或write的指针
	std::optional<void*> getReadWritePtr() const;

public:
	void* getSharedMemoryPtr() const { return sharedMemoryPtr; }

	static SharedMemory* getInstance();

	static bool deleteInstance();

	// 怎么运行游戏
	inline volatile PhaseCode& phaseCode() const { return getRef<PhaseCode>(0); }

	// 游戏运行状态
	inline volatile RunState& runState() const { return getRef<RunState>(4); }

	// 游戏当前时间
	inline volatile int32_t& gameTime() const { return getRef<int32_t>(8); }

	//  跳帧时怎么运行游戏
	inline volatile PhaseCode& jumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// 跳帧时游戏的运行状态
	inline volatile RunState& jumpingRunState() const { return getRef<RunState>(16); }

	// 读写内存时 要读写的内存的位数, 最大为8
	inline volatile const uint32_t& memoryNum() const { return getRef<uint32_t>(20); }


#undef max
	static constexpr size_t LENGTH = 10;
	static constexpr uint32_t OFFSET_END = std::numeric_limits<uint32_t>::max();
	// 读写内存时的偏移, 如{0x6a9ec0, 0x768, OFFSET_END, ...}, 遇到OFFSET_END停止读取
	inline volatile uint32_t* getOffsets() const { return reinterpret_cast<uint32_t*>(getPtr() + 24); }

	// 占位8个字节, 读写内存时 指向写入的内存的内容的指针
	inline void* getWrittenVal() const { return getPtr() + 64; }

	// 占位8个字节, 读写内存时 指向读取内存结果的指针
	inline void* getReadResult() const { return getPtr() + 72; }

	// 全局状态
	inline volatile HookState& globalState() const { return getRef<HookState>(80); }

	// 执行结果
	inline volatile ExecuteResult& executeResult() const { return getRef<ExecuteResult>(84); }

	// 8字节 返回结果
	inline void* returnResult() const { return getPtr() + 88; }

	// pBoard指针
	inline volatile uint32_t& boardPtr() const { return getRef<uint32_t>(96); }

	// pBoard指针效验位
	inline volatile bool& isBoardPtrValid() const { return getRef<bool>(100); }

	// 开10个
	// hook位置的状态
	inline volatile HookState* hookStateArr() const { return reinterpret_cast<HookState*>(getPtr() + 104); }

	// 用来存放asm的指针, 从600开始
	inline void* getAsmPtr() const { return getPtr() + 600; }

	// 读内存
	bool readMemory();

	// 写内存
	bool writeMemory();
};
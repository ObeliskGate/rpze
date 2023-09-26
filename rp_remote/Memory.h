#pragma once
#include "stdafx.h"
#include "Enums.h"

class Memory
{
	void* pBuf;
	HANDLE hMemory;

	template<typename T = BYTE>
	inline T* getPtr() const { return reinterpret_cast<T*>(pBuf); }

	template<typename T>
	inline T& getRef(int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }
public:
	Memory(HANDLE hPvz);

	~Memory() { CloseHandle(hMemory); }

	// 怎么运行游戏
	inline volatile PhaseCode& getPhaseCode() const { return getRef<PhaseCode>(0); }

	// 游戏运行状态
	inline volatile RunState& getRunState() const { return getRef<RunState>(4); }

	// 游戏当前时间
	inline volatile uint32_t& getGameTime() const { return getRef<uint32_t>(8); }

	//  跳帧时怎么运行游戏
	inline volatile PhaseCode& getJumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// 跳帧时游戏的运行状态
	inline RunState& getJumpingRunState() const { return getRef<RunState>(16); }

	// 读写内存时 要读写的内存的位数, 最大为8
	inline uint32_t& getMemoryNum() const { return getRef<uint32_t>(20); }


	static constexpr size_t LENGTH = 10;
	static constexpr int32_t OFFSET_END = -1;
	// 读写内存时的偏移, 如{0x6a9ec0, 0x768, OFFSET_END, ...}, 遇到OFFSET_END停止读取
	inline int32_t* getOffsets() const { return reinterpret_cast<int32_t*>(getPtr() + 24); }

	// 占位8个字节, 读写内存时 指向共享内存中写入的内存的内容的指针
	inline void* const getWrittenVal() const { return static_cast<void*>(getPtr() + 64); }

	// 占位8个字节, 读写内存时 指向读取内存结果的指针
	inline volatile void* const getReadResult() const { return static_cast<void*>(getPtr() + 72); }

	// 读写状态
	inline volatile ReadWriteState& getReadWriteState() const { return getRef<ReadWriteState>(80); }

	// 读取内存, 但是没有杂七杂八的检查
	std::optional<volatile void*> _readMemory(BYTE size, const std::initializer_list<int32_t>& offsets);

	// 写入内存, 但是没有杂七杂八的检查
	bool _writeMemory(const void* pVal, BYTE size, const std::initializer_list<int32_t>& offsets);

	// 形如<int>({0x6a9ec0, 0x768})这样调用
	// 仅支持sizeof(T)<=8且offsets不超过10
	template <typename T>
	std::optional<T> readMemory(const std::initializer_list<int32_t>& offsets);

	template<typename T>
	bool writeMemory(T val, const std::initializer_list<int32_t>& offsets);
};

template<typename T>
inline std::optional<T> Memory::readMemory(const std::initializer_list<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "sizeof(T)<=8");
	auto p = _readMemory(sizeof(T), offsets);
	if (!p.has_value()) return {};
	return *(T*)(p.value());
}

template<typename T>
inline bool Memory::writeMemory(T val, const std::initializer_list<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "sizeof(T)<=8");
	return _writeMemory(&val, sizeof(T), offsets);
}

#pragma once
#include "stdafx.h"
#include "Enums.h"

class Memory
{
	void* pBuf;
	HANDLE hMemory;

	// 是否在跳帧
	bool isJumpingFrame = false;

	volatile PhaseCode* pCurrentPhaseCode;
	volatile RunState* pCurrentRunState;

	template<typename T = BYTE>
	inline T* getPtr() const { return reinterpret_cast<T*>(pBuf); }

	template<typename T>
	inline T& getRef(int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }
public:
	Memory(DWORD pid);

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
	inline volatile RunState& getJumpingRunState() const { return getRef<RunState>(16); }

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
	
	//这里空了4byte 在80

	// 读写结果
	inline volatile ExecuteResult& getExecuteResult() const { return getRef<ExecuteResult>(84); }

	inline volatile PhaseCode& getCurrentPhaseCode() { return *pCurrentPhaseCode; }

	inline volatile RunState& getCurrentRunState() { return *pCurrentRunState; }


	// 读取内存, 但是没有杂七杂八的检查
	std::optional<volatile void*> _readMemory(BYTE size, const std::initializer_list<int32_t>& offsets);

	// 写入内存, 但是没有杂七杂八的检查
	bool _writeMemory(const void* pVal, BYTE size, const std::initializer_list<int32_t>& offsets);

	// 主要接口


	// 跳到下一帧
	inline void next() { getCurrentPhaseCode() = PhaseCode::CONTINUE; }
	
	// 开始跳帧, 若已在跳帧返回false
	bool startJumpFrame();

	// 结束跳帧, 若不在跳帧返回false
	bool endJumpFrame();

	inline bool isBlocked() { return *pCurrentRunState == RunState::RUNNING; }
	// 形如<int>({0x6a9ec0, 0x768})这样调用
	// 仅支持sizeof(T)<=8且offsets数量不超过10
	template <typename T>
	std::optional<T> readMemory(const std::initializer_list<int32_t>& offsets);

	// **直接**将传入的val写入游戏指定地址
	// 故请不要传入带有本地指针的对象
	template<typename T>
	bool writeMemory(T&& val, const std::initializer_list<int32_t>& offsets);
};

template<typename T>
inline std::optional<T> Memory::readMemory(const std::initializer_list<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8. ");
	if (offsets.size() > 10) return {};
	auto p = _readMemory(sizeof(T), offsets);
	if (!p.has_value()) return {};
	return *(T*)(p.value()); // 不知道为啥r_cast和s_cast都不行
}

template<typename T>
inline bool Memory::writeMemory(T&& val, const std::initializer_list<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8.");
	if (offsets.size() > 10) return false;
	return _writeMemory(&val, sizeof(T), offsets);
}

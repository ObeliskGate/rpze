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

	// 在pvz中共享内存的基址
	uint32_t remoteMemoryAddress = 0;

	template<typename T = BYTE>
	inline T* getPtr() const { return static_cast<T*>(pBuf); }

	template<typename T>
	inline T& getRef(const int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }

	void getRemoteMemoryAddress();

	// pvz进程id
	DWORD pid = 0;
public:
	explicit Memory(DWORD pid);

	~Memory() { endControl(); CloseHandle(hMemory);  }

	inline DWORD getPid() const { return pid; }

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
	inline void* getWrittenVal() const { return getPtr() + 64; }

	// 占位8个字节, 读写内存时 指向读取内存结果的指针
	inline volatile void* getReadResult() const { return static_cast<void*>(getPtr() + 72); }
	
	// 获得全局状态
	inline GlobalState& getGlobalState() const { return getRef<GlobalState>(80); }

	// 读写结果
	inline volatile ExecuteResult& getExecuteResult() const { return getRef<ExecuteResult>(84); }

	// 8字节 返回结果
	inline volatile void* getReturnResult() const { return static_cast<void*>(getPtr() + 88);  }

	// 用来存放asm的指针, 从600开始
	inline void* getAsmPtr() const { return getPtr() + 600; }

	inline volatile PhaseCode& getCurrentPhaseCode() const { return *pCurrentPhaseCode; }

	inline volatile RunState& getCurrentRunState() const { return *pCurrentRunState; }


	// 读取内存, 但是没有杂七杂八的检查
	std::optional<volatile void*> _readMemory(BYTE size, const std::vector<int32_t>& offsets);

	// 写入内存, 但是没有杂七杂八的检查
	bool _writeMemory(const void* pVal, BYTE size, const std::vector<int32_t>& offsets);

	template<typename T>
	std::optional<T> _readRemoteMemory(const std::vector<int32_t>& offsets);

	template<typename T>
	bool _writeRemoteMemory(T&& val, const std::vector<int32_t>& offsets);

	// 主要接口

	// 跳到下一帧
	inline void next() { getCurrentPhaseCode() = PhaseCode::CONTINUE; }
	
	// 开始跳帧, 若已在跳帧返回false
	bool startJumpFrame();

	// 结束跳帧, 若不在跳帧返回false
	bool endJumpFrame();

	inline bool isBlocked() const { return *pCurrentRunState == RunState::RUNNING; }
	// 形如<int>({0x6a9ec0, 0x768})这样调用
	// 仅支持sizeof(T)<=8且offsets数量不超过10
	template <typename T>
	std::optional<T> readMemory(const std::vector<int32_t>& offsets);

	// **直接**将传入的val写入游戏指定地址
	// 故请不要传入带有本地指针的对象
	template<typename T>
	bool writeMemory(T&& val, const std::vector<int32_t>& offsets);

	bool runCode(const char* codes, int num);

	void endControl();

	uint32_t getWrittenAddress();
};

template <typename T>
std::optional<T> Memory::_readRemoteMemory(const std::vector<int32_t>& offsets)
{
	HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	int32_t basePtr = offsets[0];
	do
	{
		for (size_t i = 1; i < offsets.size(); i++)
		{
			if (!basePtr) break;
			ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &basePtr, sizeof(int32_t), nullptr);
			if (!basePtr) break;
			basePtr += offsets[i];
		}
		if (!basePtr) break;
		T ret;
		ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &ret, sizeof(T), nullptr);
		CloseHandle(hPvz);
		return ret;
	} while (false);
	CloseHandle(hPvz);
	return {};
}

template <typename T>
bool Memory::_writeRemoteMemory(T&& val, const std::vector<int32_t>& offsets)
{
	HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	int32_t basePtr = offsets[0];
	do
	{
		for (size_t i = 1; i < offsets.size(); i++)
		{
			if (!basePtr) break;
			ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &basePtr, sizeof(int32_t), nullptr);
			if (!basePtr) break;
			basePtr += offsets[i];
		}
		if (!basePtr) break;
		WriteProcessMemory(hPvz, reinterpret_cast<LPVOID>(basePtr), &val, sizeof(T), nullptr);
		CloseHandle(hPvz);
		return true;
	} while (false);
	CloseHandle(hPvz);
	return false;
}

template<typename T>
inline std::optional<T> Memory::readMemory(const std::vector<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8. ");
	if (offsets.size() > 10) return {};
	if (getGlobalState() == GlobalState::NOT_CONNECTED) return _readRemoteMemory<T>(offsets);
	auto p = _readMemory(sizeof(T), offsets);
	if (!p.has_value()) return {};
	return *static_cast<volatile T*>(p.value());
}

template<typename T>
inline bool Memory::writeMemory(T&& val, const std::vector<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8.");
	if (offsets.size() > 10) return false;
	if (getGlobalState() == GlobalState::NOT_CONNECTED) return _writeRemoteMemory(std::forward<T>(val), offsets);
	return _writeMemory(&val, sizeof(T), offsets);
}

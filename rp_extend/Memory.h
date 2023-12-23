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

	~Memory() { 
		endControl();
		globalState() = HookState::NOT_CONNECTED;
		UnmapViewOfFile(pBuf);
		CloseHandle(hMemory);  
	}

	inline DWORD getPid() const { return pid; }

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
	inline volatile uint32_t& memoryNum() const { return getRef<uint32_t>(20); }


# undef max  // sb macro
	static constexpr size_t LENGTH = 10;
	static constexpr uint32_t OFFSET_END = std::numeric_limits<uint32_t>::max();
	// 读写内存时的偏移, 如{0x6a9ec0, 0x768, OFFSET_END, ...}, 遇到OFFSET_END停止读取
	inline uint32_t* getOffsets() const { return reinterpret_cast<uint32_t*>(getPtr() + 24); }

	// 占位8个字节, 读写内存时 指向共享内存中写入的内存的内容的指针
	inline void* getWrittenVal() const { return getPtr() + 64; }

	// 占位8个字节, 读写内存时 指向读取内存结果的指针
	inline void* getReadResult() const { return static_cast<void*>(getPtr() + 72); }
	
	// 获得全局状态
	inline volatile HookState& globalState() const { return getRef<HookState>(80); }

	// 读写结果
	inline volatile ExecuteResult& executeResult() const { return getRef<ExecuteResult>(84); }

	// 8字节 返回结果
	inline volatile void* getReturnResult() const { return static_cast<void*>(getPtr() + 88);  }

	// p_board指针
	inline volatile uint32_t& boardPtr() const { return getRef<uint32_t>(96); }

	// pBoard指针效验位
	inline volatile bool& isBoardPtrValid() const { return getRef<bool>(100); }

	// 开10个
	// hook位置的状态
	inline volatile HookState* hookStateArr() const { return reinterpret_cast<HookState*>(getPtr() + 104); }


	// 用来存放asm的指针, 从600开始
	inline void* getAsmPtr() const { return getPtr() + 600; }

	inline volatile PhaseCode& getCurrentPhaseCode() const { return *pCurrentPhaseCode; }

	inline volatile RunState& getCurrentRunState() const { return *pCurrentRunState; }


	// 读取内存, 但是没有杂七杂八的检查
	std::optional<volatile void*> _readMemory(BYTE size, const std::vector<uint32_t>& offsets);

	// 写入内存, 但是没有杂七杂八的检查
	bool _writeMemory(const void* pVal, BYTE size, const std::vector<uint32_t>& offsets);

	template<typename T>
	std::optional<T> _readRemoteMemory(const std::vector<uint32_t>& offsets);

	template<typename T>
	bool _writeRemoteMemory(T&& val, const std::vector<uint32_t>& offsets);

	// 主要接口

	// 跳到下一帧
	inline void next() { getCurrentPhaseCode() = PhaseCode::CONTINUE; }
	
	// 开始跳帧, 若已在跳帧返回false
	bool startJumpFrame();

	// 结束跳帧, 若不在跳帧返回false
	bool endJumpFrame();

	inline bool isBlocked() const { return *pCurrentRunState == RunState::RUNNING || *pCurrentPhaseCode == PhaseCode::CONTINUE; }
	// 形如<int>({0x6a9ec0, 0x768})这样调用
	// 仅支持sizeof(T)<=8且offsets数量不超过10
	template <typename T>
	std::optional<T> readMemory(const std::vector<uint32_t>& offsets);

	// **直接**将传入的val写入游戏指定地址
	// 故请不要传入带有本地指针的对象
	template<typename T>
	bool writeMemory(T&& val, const std::vector<uint32_t>& offsets);

	bool runCode(const char* codes, int num);

	void startControl();

	void endControl();

	void openHook(HookPosition hook);

	void closeHook(HookPosition hook);

	uint32_t getWrittenAddress();

	inline std::tuple<bool, uint32_t> getPBoard() const // 第一位返回0表示无须换新
	{
		auto t = isBoardPtrValid();
		isBoardPtrValid() = true;
		return { t, boardPtr() };
	}
};

template <typename T>
std::optional<T> Memory::_readRemoteMemory(const std::vector<uint32_t>& offsets)
{
	HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	uint64_t basePtr = offsets[0];
	do
	{
		for (size_t i = 1; i < offsets.size(); i++)
		{
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
bool Memory::_writeRemoteMemory(T&& val, const std::vector<uint32_t>& offsets)
{
	HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	uint64_t basePtr = offsets[0];
	do
	{
		for (size_t i = 1; i < offsets.size(); i++)
		{
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
inline std::optional<T> Memory::readMemory(const std::vector<uint32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8. ");
	if (offsets.size() > 10) return {};
	if (globalState() == HookState::NOT_CONNECTED || hookStateArr()[getHookIndex(HookPosition::MAIN_LOOP)] == HookState::NOT_CONNECTED) 
		return _readRemoteMemory<T>(offsets);
	auto p = _readMemory(sizeof(T), offsets);
	if (!p.has_value()) return {};
	return *static_cast<volatile T*>(*p);

}

template<typename T>
inline bool Memory::writeMemory(T&& val, const std::vector<uint32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8.");
	if (offsets.size() > 10) return false;
	if (globalState() == HookState::NOT_CONNECTED || hookStateArr()[getHookIndex(HookPosition::MAIN_LOOP)] == HookState::NOT_CONNECTED) 
		return _writeRemoteMemory(std::forward<T>(val), offsets);
	return _writeMemory(&val, sizeof(T), offsets);
}

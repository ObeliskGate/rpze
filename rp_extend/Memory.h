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
	static constexpr uint32_t BUFFER_OFFSET = 4096;
	static constexpr uint32_t BUFFER_SIZE = SHARED_MEMORY_SIZE - BUFFER_OFFSET;

	explicit Memory(DWORD pid);

	~Memory();

	DWORD getPid() const { return pid; }

	// 怎么运行游戏
	volatile PhaseCode& phaseCode() const { return getRef<PhaseCode>(0); }

	// 游戏运行状态
	volatile RunState& runState() const { return getRef<RunState>(4); }

	// p_board指针
	volatile uint32_t& boardPtr() const { return getRef<uint32_t>(8); }

	//  跳帧时怎么运行游戏
	volatile PhaseCode& jumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// 跳帧时游戏的运行状态
	volatile RunState& jumpingRunState() const { return getRef<RunState>(16); }

	// 读写内存时 要读写的内存的位数
	volatile uint32_t& memoryNum() const { return getRef<uint32_t>(20); }


# undef max  // sb macro
	static constexpr size_t LENGTH = 16;
	static constexpr uint32_t OFFSET_END = std::numeric_limits<uint32_t>::max();
	// 读写内存时的偏移, 如{0x6a9ec0, 0x768, OFFSET_END, ...}, 遇到OFFSET_END停止读取
	inline uint32_t* getOffsets() { return reinterpret_cast<uint32_t*>(getPtr() + 24); }

	// 占位8个字节, 读写内存时 指向值 / 结果的指针
	void* getReadWriteVal() const { return getPtr() + BUFFER_OFFSET; }
	
	// 获得全局状态
	volatile HookState& globalState() const { return getRef<HookState>(90); }

	// 读写结果
	volatile ExecuteResult& executeResult() const { return getRef<ExecuteResult>(94); }

	// 8字节 返回结果
	volatile void* getReturnResult() const { return static_cast<void*>(getPtr() + 98);  }


	// pBoard指针效验位
	volatile bool& isBoardPtrValid() const { return getRef<bool>(106); }

	// 开10个
	// hook位置的状态
	volatile HookState* hookStateArr() { return reinterpret_cast<HookState*>(getPtr() + 112); }

	// 用来存放asm的指针
	void* getAsmPtr() const { return getPtr() + BUFFER_OFFSET; }


	volatile PhaseCode& getCurrentPhaseCode() const { return *pCurrentPhaseCode; }

	volatile RunState& getCurrentRunState() const { return *pCurrentRunState; }


	// 读取内存, 但是没有杂七杂八的检查
	std::optional<volatile void*> _readMemory(uint32_t size, const uint32_t* offsets, uint32_t len);

	// 写入内存, 但是没有杂七杂八的检查
	bool _writeMemory(const void* pVal, uint32_t size, const uint32_t* offsets, uint32_t len);

	template<typename T>
	std::optional<T> _readRemoteMemory(const uint32_t* offsets, uint32_t len);

	template<typename T>
	bool _writeRemoteMemory(T&& val, const uint32_t* offsets, uint32_t len);

	// 主要接口

	// 跳到下一帧
	void next() const { getCurrentPhaseCode() = PhaseCode::CONTINUE; }
	
	// 开始跳帧, 若已在跳帧返回false
	bool startJumpFrame();

	// 结束跳帧, 若不在跳帧返回false
	bool endJumpFrame();

	inline bool isBlocked() const { return *pCurrentRunState == RunState::RUNNING || *pCurrentPhaseCode == PhaseCode::CONTINUE; }
	// 形如<int>({0x6a9ec0, 0x768})这样调用
	// 仅支持sizeof(T)<=8且offsets数量不超过10
	template <typename T>
	std::optional<T> readMemory(const uint32_t* offsets, uint32_t len);

	// **直接**将传入的val写入游戏指定地址
	// 故请不要传入带有本地指针的对象
	template<typename T>
	bool writeMemory(T&& val, const uint32_t* offsets, uint32_t len);

	bool readBytes(char* buffer, uint32_t size, const uint32_t* offsets, uint32_t len);

	bool writeBytes(const char* in, uint32_t size, const uint32_t* offsets, uint32_t len);

	bool runCode(const char* codes, size_t len) const;

	void startControl();

	void endControl();

	void openHook(HookPosition hook);

	void closeHook(HookPosition hook);

	bool hookConnected(HookPosition hook) { return globalState() == HookState::CONNECTED && hookStateArr()[getHookIndex(hook)] == HookState::CONNECTED; }

	uint32_t getWrittenAddress() const { return remoteMemoryAddress + 98; }

	uint32_t getAsmAddress() const { return remoteMemoryAddress + BUFFER_OFFSET; }

	inline std::tuple<bool, uint32_t> getPBoard() const // 第一位返回0表示无须换新
	{
		auto t = isBoardPtrValid();
		isBoardPtrValid() = true;
		return { t, boardPtr() };
	}
};

template <typename T>
std::optional<T> Memory::_readRemoteMemory(const uint32_t* offsets, uint32_t len)
{
	HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	uint64_t basePtr = offsets[0];
	do
	{
		for (size_t i = 1; i < len; i++)
		{
			ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &basePtr, sizeof(uint32_t), nullptr);
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
bool Memory::_writeRemoteMemory(T&& val, const uint32_t* offsets, uint32_t len)
{
	HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	uint64_t basePtr = offsets[0];
	do
	{
		for (size_t i = 1; i < len; i++)
		{
			ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &basePtr, sizeof(uint32_t), nullptr);
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
std::optional<T> Memory::readMemory(const uint32_t* offsets, uint32_t len)
{
	static_assert(sizeof(T) <= BUFFER_SIZE);
	if (len > LENGTH) throw std::exception("readMemory:offsets too long");
	if (!hookConnected(HookPosition::MAIN_LOOP)) return _readRemoteMemory<T>(offsets, len);
	auto p = _readMemory(sizeof(T), offsets, len);
	if (!p.has_value()) return {};
	return *static_cast<volatile T*>(*p);
}

template<typename T>
bool Memory::writeMemory(T&& val, const uint32_t* offsets, uint32_t len)
{
	static_assert(sizeof(T) <= BUFFER_SIZE);
	if (len > LENGTH) throw std::exception("writeMemory: offsets too long");
	if (!hookConnected(HookPosition::MAIN_LOOP)) return _writeRemoteMemory(std::forward<T>(val), offsets, len);
	return _writeMemory(&val, sizeof(T), offsets, len);
}

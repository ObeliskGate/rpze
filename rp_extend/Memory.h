#pragma once
#include "stdafx.h"
#include "Enums.h"

class Memory
{
	void* pBuf;
	HANDLE hMemory;
	HANDLE hPvz;

	// 是否在跳帧
	bool jumpingFrame = false;

	volatile PhaseCode* pCurrentPhaseCode;
	volatile RunState* pCurrentRunState;

	// 在pvz中共享内存的基址
	uint32_t remoteMemoryAddress = 0;

	template<typename T = BYTE>
	inline T* getPtr() const { return static_cast<T*>(pBuf); }

	template<typename T>
	inline T& getRef(const int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }

	void getRemoteMemoryAddress();

	template <typename T>
	std::optional<T*> getRemotePtr(const uint32_t* offsets, uint32_t len);

	// pvz进程id
	DWORD pid = 0;

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
public:
	static constexpr uint32_t BUFFER_OFFSET = 1024 * 4;
	static constexpr uint32_t BUFFER_SIZE = SHARED_MEMORY_SIZE - BUFFER_OFFSET;
	static constexpr uint32_t RESULT_OFFSET = 1024;
	static constexpr uint32_t RESULT_SIZE = BUFFER_OFFSET - RESULT_OFFSET;
	static constexpr size_t OFFSET_LENGTH = 16;
	static constexpr uint32_t OFFSET_END = std::numeric_limits<uint32_t>::max();
private:
	// 读写内存时的偏移, 如{0x6a9ec0, 0x768, OFFSET_END, ...}, 遇到OFFSET_END停止读取
	inline uint32_t* getOffsets() { return reinterpret_cast<uint32_t*>(getPtr() + 24); }

	// 占位8个字节, 读写内存时 指向值 / 结果的指针
	void* getReadWriteVal() const { return getPtr() + BUFFER_OFFSET; }
	
	// 获得全局状态
	volatile HookState& globalState() const { return getRef<HookState>(90); }

	// 读写结果
	volatile ExecuteResult& executeResult() const { return getRef<ExecuteResult>(94); }

	// pBoard指针效验位
	volatile bool& isBoardPtrValid() const { return getRef<bool>(106); }

public:
	static constexpr size_t HOOK_LEN = 16;
private:
	// hook位置的状态
	volatile HookState* hookStateArr() const { return reinterpret_cast<HookState*>(getPtr() + 112); }

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
public:
	explicit Memory(DWORD pid);

	~Memory();

	// 8字节 返回结果
	volatile void* getReturnResult() const { return static_cast<void*>(getPtr() + RESULT_OFFSET); }

	DWORD getPid() const { return pid; }

	// 等到本cs执行
	void before() const;

	// 跳到下一帧
	void next() const { getCurrentPhaseCode() = PhaseCode::CONTINUE; }

	void skipFrames(size_t num = 1) const;

	bool isJumpingFrame() const { return jumpingFrame; }
	
	// 开始跳帧, 若已在跳帧返回false
	bool startJumpFrame();

	// 结束跳帧, 若不在跳帧返回false
	bool endJumpFrame();

	bool isBlocked() const { return *pCurrentRunState == RunState::RUNNING || *pCurrentPhaseCode == PhaseCode::CONTINUE; }

	void untilGameExecuted() const;

	bool isShmPrepared() const { return hookConnected(HookPosition::MAIN_LOOP)
		&& *pCurrentPhaseCode == PhaseCode::WAIT
		&& *pCurrentRunState == RunState::OVER; }

	// 形如<int>({0x6a9ec0, 0x768})这样调用
	// 仅支持sizeof(T)<=8且offsets数量不超过10
	template <typename T>
	std::optional<T> readMemory(const uint32_t* offsets, uint32_t len);

	// **直接**将传入的val写入游戏指定地址
	// 故请不要传入带有本地指针的对象
	template<typename T>
	bool writeMemory(T&& val, const uint32_t* offsets, uint32_t len);

	std::optional<std::unique_ptr<char[]>> readBytes(uint32_t size, const uint32_t* offsets, uint32_t len);

	bool writeBytes(const char* in, uint32_t size, const uint32_t* offsets, uint32_t len);

	bool runCode(const char* codes, size_t len) const;

	void startControl();

	void endControl();

	void openHook(HookPosition hook);

	void closeHook(HookPosition hook);

	bool hookConnected(HookPosition hook) const { return globalState() == HookState::CONNECTED && hookStateArr()[getHookIndex(hook)] == HookState::CONNECTED; }

	uint32_t getWrittenAddress() const { return remoteMemoryAddress + RESULT_OFFSET; }

	uint32_t getAsmAddress() const { return remoteMemoryAddress + BUFFER_OFFSET; }

	std::tuple<bool, uint32_t> getPBoard() const; // 第一位返回0表示无须换新
};

template <typename T>
std::optional<T*> Memory::getRemotePtr(const uint32_t* offsets, uint32_t len)
{
	uint64_t basePtr = offsets[0];
	for (size_t i = 1; i < len; i++)
	{
		ReadProcessMemory(hPvz, 
			reinterpret_cast<LPCVOID>(basePtr), 
			&basePtr, 
			sizeof(uint32_t), 
			nullptr);
		if (!basePtr) return {};
		basePtr += offsets[i];
	}
	return reinterpret_cast<T*>(basePtr);
}

template <typename T>
std::optional<T> Memory::_readRemoteMemory(const uint32_t* offsets, uint32_t len)
{
	auto remotePtr = getRemotePtr<T>(offsets, len);
	if (!remotePtr.has_value()) return {};
	T ret;
	ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(*remotePtr), &ret, sizeof(T), nullptr);
	return ret;
}

template <typename T>
bool Memory::_writeRemoteMemory(T&& val, const uint32_t* offsets, uint32_t len)
{
	auto remotePtr = getRemotePtr<T>(offsets, len);
	if (!remotePtr.has_value()) return false;
	WriteProcessMemory(hPvz, reinterpret_cast<LPVOID>(*remotePtr), &val, sizeof(T), nullptr);
	return true;
}

template<typename T>
std::optional<T> Memory::readMemory(const uint32_t* offsets, uint32_t len)
{
	static_assert(sizeof(T) <= BUFFER_SIZE);
	if (len > OFFSET_LENGTH) throw std::exception("readMemory:offsets too long");
	if (!hookConnected(HookPosition::MAIN_LOOP)) return _readRemoteMemory<T>(offsets, len);
	auto p = _readMemory(sizeof(T), offsets, len);
	if (!p.has_value()) return {};
	return *static_cast<volatile T*>(*p);
}

template<typename T>
bool Memory::writeMemory(T&& val, const uint32_t* offsets, uint32_t len)
{
	static_assert(sizeof(T) <= BUFFER_SIZE);
	if (len > OFFSET_LENGTH) throw std::exception("writeMemory: offsets too long");
	if (!hookConnected(HookPosition::MAIN_LOOP)) return _writeRemoteMemory(std::forward<T>(val), offsets, len);
	return _writeMemory(&val, sizeof(T), offsets, len);
}

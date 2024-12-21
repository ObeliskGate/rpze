#pragma once
#include "stdafx.h"
#include "MemoryException.h"
#include "shm.h" 

template <typename T>
concept offset_range = std::ranges::input_range<T> && std::unsigned_integral<std::ranges::range_value_t<T>>;


class Memory
{
	Shm* pShm;
	HANDLE hMemory;
	HANDLE hPvz;
	HANDLE hMutex;

	// 是否在跳帧
	bool jumpingFrame = false;

	volatile PhaseCode* pCurrentPhaseCode;
	volatile RunState* pCurrentRunState;
	volatile SyncMethod* pCurrentSyncMethod;

	// 在pvz中共享内存的基址
	uint32_t remoteMemoryAddress = 0;
	void getRemoteMemoryAddress();

	void* getRemotePtr(const offset_range auto& offsets);

	// pvz进程id
	DWORD pid = 0;

	static constexpr std::array<uint32_t, 1> LOCALE_OFFSET = { 0x6a66f4 };

	bool localeSetting = true;

	volatile PhaseCode& getCurrentPhaseCode() const { return *pCurrentPhaseCode; }
	
	volatile RunState& getCurrentRunState() const { return *pCurrentRunState; }

	template <offset_range T>
	void setReadWriteOffsets(const T& offsets);

	// 读取内存, 但是没有杂七杂八的检查
	volatile void* _readMemory(uint32_t size, const offset_range auto& offsets);

	// 写入内存, 但是没有杂七杂八的检查
	bool _writeMemory(const void* pVal, uint32_t size, const offset_range auto& offsets);

	template<typename T>
	std::optional<T> _readRemoteMemory(const offset_range auto& offsets);

	template<typename T>
	bool _writeRemoteMemory(T&& val, const offset_range auto& offsets);

	template <bool check_sync = true>
	void waitMutex() const;

	template <bool check_sync = true>
	void releaseMutex() const;

	Shm& shm() const { return *pShm; }

	void waiting(std::string_view callerName) const;


	// 主要接口
public:
	explicit Memory(DWORD pid);

	~Memory();

	volatile void* getReturnResult() const { return shm().getReadWriteBuffer<>(); }

	DWORD getPid() const { return pid; }

	// 等到本cs执行
	void before() const;

	// 跳到下一帧
	void next() const;

	void skipFrames(size_t num = 1) const;

	bool isJumpingFrame() const { return jumpingFrame; }
	
	// 开始跳帧, 若已在跳帧返回false
	bool startJumpFrame();

	// 结束跳帧, 若不在跳帧返回false
	bool endJumpFrame();

	bool isBlocked() const {
			 return *pCurrentRunState == RunState::RUNNING || *pCurrentPhaseCode == PhaseCode::CONTINUE; }

	void untilGameExecuted() const { 
			while (getCurrentPhaseCode() != PhaseCode::WAIT) waiting("untilGameExecuted"); }

	bool isShmPrepared() const { return hookConnected(HookPosition::MAIN_LOOP)
		&& *pCurrentPhaseCode == PhaseCode::WAIT
		&& *pCurrentRunState == RunState::OVER; }

	// 形如<int>({0x6a9ec0, 0x768})这样调用
	// 仅支持sizeof(T)<=8且offsets数量不超过10
	template <typename T>
	requires std::is_standard_layout_v<T> && (sizeof(T) <= Shm::BUFFER_SIZE)
	std::optional<T> readMemory(const offset_range auto& offsets, bool forceRemote = false);

	// **直接**将传入的val写入游戏指定地址
	template<typename T>
	requires std::is_standard_layout_v<std::decay_t<T>> && (sizeof(std::decay_t<T>) <= Shm::BUFFER_SIZE)
	bool writeMemory(T&& val, const offset_range auto& offsets, bool forceRemote = false);

	std::optional<std::unique_ptr<char[]>> 
		readBytes(uint32_t size, const offset_range auto& offsets, bool forceRemote = false);

	bool writeBytes(const std::string_view inputBytes, const offset_range auto& offsets, bool forceRemote = false);

	bool runCode(const std::string_view codes) const;

	void startControl();

	void endControl();

	void openHook(HookPosition hook);

	void closeHook(HookPosition hook);

	bool hookConnected(HookPosition hook) const 
		{ return globalConnected() && shm().hookStateArr[getHookIndex(hook)] == HookState::CONNECTED; }

	bool globalConnected() const { return shm().globalState == HookState::CONNECTED; }

	uint32_t getBufferAddress() const { return remoteMemoryAddress + Shm::BUFFER_OFFSET; }

	uint32_t getAsmAddress() const { return remoteMemoryAddress + Shm::ASM_OFFSET; }

	SyncMethod getSyncMethod() const { return shm().syncMethod; }

	SyncMethod getJumpingSyncMethod() const { return shm().jumpingSyncMethod; }

	void setSyncMethod(SyncMethod val);

	void setJumpingSyncMethod(SyncMethod val);

	std::pair<bool, uint32_t> getPBoard() const; // 第一位返回0表示无须换新
};

template <bool check_sync>
void Memory::waitMutex() const
{
	if constexpr (check_sync)
		if (*pCurrentSyncMethod != SyncMethod::MUTEX) return;

#ifndef NDEBUG
	switch (WaitForSingleObject(hMutex, 5000))
#else
	switch (WaitForSingleObject(hMutex, INFINITE))
#endif // DEBUG
	{
	case WAIT_OBJECT_0: [[likely]]
#ifndef NDEBUG
		std::println("mutex waited");
#endif
		break;
	case WAIT_FAILED:
		throw MemoryException(
			std::format("waitMutex: failed, err: {}", GetLastError()), pid);
	case WAIT_ABANDONED:
		throw MemoryException("waitMutex: abandoned", pid);
#ifndef NDEBUG
	case WAIT_TIMEOUT:
		throw MemoryException("waitMutex: timeout", pid);
#endif // DEBUG
	default:
		throw MemoryException("waitMutex: unexpected behavior", pid);
	}
}

template <bool check_sync>
void Memory::releaseMutex() const
{
	if constexpr (check_sync)
		if (*pCurrentSyncMethod != SyncMethod::MUTEX) return;
	if (!ReleaseMutex(hMutex)) [[unlikely]]
		throw MemoryException(
			std::format("releaseMutex: failed, err: {}", GetLastError()), pid);
#ifndef NDEBUG
	std::println("mutex released");
#endif

}

template <typename T>
std::optional<T> Memory::_readRemoteMemory(const offset_range auto& offsets)
{
	auto remotePtr = getRemotePtr(offsets);
	if (!remotePtr) return {};
	T ret;
	ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(remotePtr), &ret, sizeof(T), nullptr);
	return ret;
}

template <typename T>
bool Memory::_writeRemoteMemory(T&& val, const offset_range auto& offsets)
{
	auto remotePtr = getRemotePtr(offsets);
	if (!remotePtr) return false;
	WriteProcessMemory(hPvz, reinterpret_cast<LPVOID>(remotePtr), &val, sizeof(T), nullptr);
	return true;
}

template<typename T>
requires std::is_standard_layout_v<T> && (sizeof(T) <= Shm::BUFFER_SIZE)
std::optional<T> Memory::readMemory(const offset_range auto& offsets, bool forceRemote)
{
	if (forceRemote || !hookConnected(HookPosition::MAIN_LOOP)) return _readRemoteMemory<T>(offsets);
	if (offsets.size() > Shm::OFFSETS_LEN) [[unlikely]]
		throw std::invalid_argument("readMemory: offsets too long");
	auto p = _readMemory(sizeof(T), offsets);
	if (!p) return {};
	return *static_cast<volatile T*>(p);
}

template<typename T>
requires std::is_standard_layout_v<std::decay_t<T>> && (sizeof(std::decay_t<T>) <= Shm::BUFFER_SIZE)
bool Memory::writeMemory(T&& val, const offset_range auto& offsets, bool forceRemote)
{
	if (forceRemote || !hookConnected(HookPosition::MAIN_LOOP)) 
		return _writeRemoteMemory(std::forward<T>(val), offsets);
	if (offsets.size() > Shm::OFFSETS_LEN) [[unlikely]]
		throw std::invalid_argument("writeMemory: offsets too long");
	return _writeMemory(&val, sizeof(T), offsets);
}


void* Memory::getRemotePtr(const offset_range auto& offsets)
{
	auto it = offsets.begin();
	if (it == offsets.end()) return nullptr;
	uintptr_t basePtr = *it;
	++it;
	for (; it != offsets.end(); ++it)
	{
		if (!basePtr) return nullptr;
		ReadProcessMemory(hPvz, 
			reinterpret_cast<LPCVOID>(basePtr), 
			&basePtr, 
			sizeof(uint32_t),  // for 32bit game process
			nullptr);
		if (!basePtr) return nullptr;
		basePtr += *it;
	}
	return reinterpret_cast<void*>(basePtr);

}

template <offset_range T>
void Memory::setReadWriteOffsets(const T& offsets)
{
	if constexpr (std::ranges::contiguous_range<T> && 
				  std::same_as<std::ranges::range_value_t<T>, uint32_t>)

	{
		auto size = std::ranges::distance(offsets);
		memcpy(const_cast<uint32_t*>(shm().offsets), 
			&(*offsets.begin()), size * sizeof(uint32_t));
		shm().offsets[size] = Shm::OFFSET_END;
	}
	else 
	{
		auto i = 0;
		for (auto it : offsets)
			shm().offsets[i++] = it;

		shm().offsets[i] = Shm::OFFSET_END;
	}
}


volatile void* Memory::_readMemory(uint32_t size, const offset_range auto& offsets)
{
	shm().memoryNum = size;
	setReadWriteOffsets(offsets);
	getCurrentPhaseCode() = PhaseCode::READ_MEMORY;
	untilGameExecuted(); 
	if (shm().executeResult == ExecuteResult::SUCCESS) return shm().getReadWriteBuffer();
	if (shm().executeResult == ExecuteResult::FAIL) return nullptr;
	throw MemoryException("_readMemory: unexpected behavior", this->pid);
}

bool Memory::_writeMemory(const void* pVal, uint32_t size, const offset_range auto& offsets)
{
	shm().memoryNum = size;
	memcpy(const_cast<void*>(shm().getReadWriteBuffer()), pVal, size);
	setReadWriteOffsets(offsets);
	getCurrentPhaseCode() = PhaseCode::WRITE_MEMORY;
	untilGameExecuted();
	if (shm().executeResult == ExecuteResult::SUCCESS) return true;
	if (shm().executeResult == ExecuteResult::FAIL) return false;
	throw MemoryException("_writeMemory: unexpected behavior", this->pid);
}

std::optional<std::unique_ptr<char[]>> Memory::readBytes(uint32_t size, const offset_range auto& offsets, bool forceRemote)
{
	if (forceRemote || !isShmPrepared())
	{
		auto remotePtr = getRemotePtr(offsets);
		if (!remotePtr) return {};
		auto ret = std::make_unique<char[]>(size);
		ReadProcessMemory(hPvz, remotePtr, ret.get(), size, nullptr);
		return ret;
	}
	if (size > Shm::BUFFER_SIZE) [[unlikely]] throw std::invalid_argument("readBytes: too many bytes");
	if (offsets.size() > Shm::OFFSETS_LEN) [[unlikely]] throw std::invalid_argument("readBytes: too many offsets");
	auto p = _readMemory(size, offsets);
	if (!p) return {};
	auto ret = std::make_unique<char[]>(size);
	memcpy(ret.get(), const_cast<const void*>(p), size);
	return ret;
}

bool Memory::writeBytes(const std::string_view inputBytes, const offset_range auto& offsets, bool forceRemote)
{
	if (forceRemote || !isShmPrepared())
	{
		auto remotePtr = getRemotePtr(offsets);
		if (!remotePtr) return false;
		WriteProcessMemory(hPvz, remotePtr, inputBytes.data(), inputBytes.size(), nullptr);
		return true;
	}
	if (inputBytes.size() > Shm::BUFFER_SIZE) [[unlikely]] throw std::invalid_argument("writeBytes: too many bytes");
	if (offsets.size() > Shm::OFFSETS_LEN) [[unlikely]] throw std::invalid_argument("writeBytes: too many offsets");
	return _writeMemory(inputBytes.data(), static_cast<uint32_t>(inputBytes.size()), offsets);
}
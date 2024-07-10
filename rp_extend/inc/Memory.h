#pragma once
#include "stdafx.h"
#include "MemoryException.h"
#include "shm.h" 
#include <stdint.h>
#include <errhandlingapi.h>
#include <span>
#include <type_traits>

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

	void* getRemotePtr(std::span<uint32_t> offsets);

	// pvz进程id
	DWORD pid = 0;

	volatile PhaseCode& getCurrentPhaseCode() const { return *pCurrentPhaseCode; }
	
	volatile RunState& getCurrentRunState() const { return *pCurrentRunState; }\

	void setReadWriteOffsets(std::span<uint32_t> offsets);

	// 读取内存, 但是没有杂七杂八的检查
	volatile void* _readMemory(uint32_t size, std::span<uint32_t> offsets);

	// 写入内存, 但是没有杂七杂八的检查
	bool _writeMemory(const void* pVal, uint32_t size, std::span<uint32_t> offsets);

	template<typename T>
	std::optional<T> _readRemoteMemory(std::span<uint32_t> offsets);

	template<typename T>
	bool _writeRemoteMemory(T&& val, std::span<uint32_t> offsets);

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
	std::optional<T> readMemory(std::span<uint32_t> offsets, bool forceRemote = false);

	// **直接**将传入的val写入游戏指定地址
	template<typename T>
	requires std::is_standard_layout_v<std::decay_t<T>> && (sizeof(std::decay_t<T>) <= Shm::BUFFER_SIZE)
	bool writeMemory(T&& val, std::span<uint32_t> offsets, bool forceRemote = false);

	std::optional<std::unique_ptr<char[]>> 
		readBytes(uint32_t size, std::span<uint32_t> offsets, bool forceRemote = false);

	bool writeBytes(const std::string_view inputBytes, std::span<uint32_t> offsets, bool forceRemote = false);

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
			std::format("waitMutex: failed, error {}", GetLastError()), pid);
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
			std::format("releaseMutex: failed, err {}", GetLastError()), pid);
#ifndef NDEBUG
	std::println("mutex released");
#endif

}

template <typename T>
std::optional<T> Memory::_readRemoteMemory(std::span<uint32_t> offsets)
{
	auto remotePtr = getRemotePtr(offsets);
	if (!remotePtr) return {};
	T ret;
	ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(remotePtr), &ret, sizeof(T), nullptr);
	return ret;
}

template <typename T>
bool Memory::_writeRemoteMemory(T&& val, std::span<uint32_t> offsets)
{
	auto remotePtr = getRemotePtr(offsets);
	if (!remotePtr) return false;
	WriteProcessMemory(hPvz, reinterpret_cast<LPVOID>(remotePtr), &val, sizeof(T), nullptr);
	return true;
}

template<typename T>
requires std::is_standard_layout_v<T> && (sizeof(T) <= Shm::BUFFER_SIZE)
std::optional<T> Memory::readMemory(std::span<uint32_t> offsets, bool forceRemote)
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
bool Memory::writeMemory(T&& val, std::span<uint32_t> offsets, bool forceRemote)
{
	if (forceRemote || !hookConnected(HookPosition::MAIN_LOOP)) 
		return _writeRemoteMemory(std::forward<T>(val), offsets);
	if (offsets.size() > Shm::OFFSETS_LEN) [[unlikely]]
		throw std::invalid_argument("writeMemory: offsets too long");
	return _writeMemory(&val, sizeof(T), offsets);
}

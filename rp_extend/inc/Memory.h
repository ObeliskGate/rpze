#pragma once
#include "stdafx.h"
#include "MemoryException.h"
#include "shm.h" 

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

	template <typename T>
	T* getRemotePtr(const uint32_t* offsets, uint32_t len);

	// pvz进程id
	DWORD pid = 0;

	volatile PhaseCode& getCurrentPhaseCode() const { return *pCurrentPhaseCode; }
	
	volatile RunState& getCurrentRunState() const { return *pCurrentRunState; }


	// 读取内存, 但是没有杂七杂八的检查
	volatile void* _readMemory(uint32_t size, const uint32_t* offsets, uint32_t len);

	// 写入内存, 但是没有杂七杂八的检查
	bool _writeMemory(const void* pVal, uint32_t size, const uint32_t* offsets, uint32_t len);

	template<typename T>
	std::optional<T> _readRemoteMemory(const uint32_t* offsets, uint32_t len);

	template<typename T>
	bool _writeRemoteMemory(T&& val, const uint32_t* offsets, uint32_t len);

	template <bool check_sync = true>
	void waitMutex() const;

	template <bool check_sync = true>
	void releaseMutex() const;


	Shm& shm() const { return *pShm; }

	// 主要接口
public:
	explicit Memory(DWORD pid);

	~Memory();

	// 8字节 返回结果
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

	bool isBlocked() const { return *pCurrentRunState == RunState::RUNNING || *pCurrentPhaseCode == PhaseCode::CONTINUE; }

	void untilGameExecuted() const;

	bool isShmPrepared() const { return hookConnected(HookPosition::MAIN_LOOP)
		&& *pCurrentPhaseCode == PhaseCode::WAIT
		&& *pCurrentRunState == RunState::OVER; }

	// 形如<int>({0x6a9ec0, 0x768})这样调用
	// 仅支持sizeof(T)<=8且offsets数量不超过10
	template <typename T>
	std::optional<std::enable_if_t<std::is_trivially_copyable_v<T>, T>>
		readMemory(const uint32_t* offsets, uint32_t len);

	// **直接**将传入的val写入游戏指定地址
	template<typename T>
	std::enable_if_t<std::is_trivially_copyable_v<std::remove_reference_t<T>>, bool>
		writeMemory(T&& val, const uint32_t* offsets, uint32_t len);

	std::optional<std::unique_ptr<char[]>> readBytes(uint32_t size, const uint32_t* offsets, uint32_t len);

	bool writeBytes(const char* in, uint32_t size, const uint32_t* offsets, uint32_t len);

	bool runCode(const char* codes, size_t len) const;

	void startControl();

	void endControl();

	void openHook(HookPosition hook);

	void closeHook(HookPosition hook);

	bool hookConnected(HookPosition hook) const { return globalConnected() && shm().hookStateArr[getHookIndex(hook)] == HookState::CONNECTED; }

	bool globalConnected() const { return shm().globalState == HookState::CONNECTED; }

	uint32_t getBufferAddress() const { return remoteMemoryAddress + Shm::BUFFER_OFFSET; }

	uint32_t getAsmAddress() const { return remoteMemoryAddress + Shm::ASM_OFFSET; }

	SyncMethod getSyncMethod() const { return shm().syncMethod; }

	SyncMethod getJumpingSyncMethod() const { return shm().jumpingSyncMethod; }

	void setSyncMethod(SyncMethod val);

	void setJumpingSyncMethod(SyncMethod val);

	std::pair<bool, uint32_t> getPBoard() const; // 第一位返回0表示无须换新
};

template <typename T>
T* Memory::getRemotePtr(const uint32_t* offsets, uint32_t len)
{
	uint64_t basePtr = offsets[0];
	for (size_t i = 1; i < len; i++)
	{
		ReadProcessMemory(hPvz, 
			reinterpret_cast<LPCVOID>(basePtr), 
			&basePtr, 
			sizeof(uint32_t), 
			nullptr);
		if (!basePtr) return nullptr;
		basePtr += offsets[i];
	}
	return reinterpret_cast<T*>(basePtr);
}

template <bool check_sync>
void Memory::waitMutex() const
{
	if constexpr (check_sync)
		if (*pCurrentSyncMethod != SyncMethod::MUTEX) return;

#ifndef NDEBUG
	switch (WaitForSingleObject(hMutex, 500))
#else
	switch (WaitForSingleObject(hMutex, INFINITE))
#endif // DEBUG
	{
	case WAIT_OBJECT_0:
#ifndef NDEBUG
		std::cout << "mutex waited" << std::endl;
#endif
		break;
	case WAIT_FAILED:
		throw MemoryException(
			("waitMutex: failed, error " + std::to_string(GetLastError())).c_str(), pid);
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
	if (!ReleaseMutex(hMutex))
		throw MemoryException(
			("releaseMutex: failed, error " + std::to_string(GetLastError())).c_str(), pid);
#ifndef NDEBUG
	std::cout << "mutex released" << std::endl;
#endif

}

template <typename T>
std::optional<T> Memory::_readRemoteMemory(const uint32_t* offsets, uint32_t len)
{
	auto remotePtr = getRemotePtr<T>(offsets, len);
	if (!remotePtr) return {};
	T ret;
	ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(remotePtr), &ret, sizeof(T), nullptr);
	return ret;
}

template <typename T>
bool Memory::_writeRemoteMemory(T&& val, const uint32_t* offsets, uint32_t len)
{
	auto remotePtr = getRemotePtr<T>(offsets, len);
	if (!remotePtr) return false;
	WriteProcessMemory(hPvz, reinterpret_cast<LPVOID>(remotePtr), &val, sizeof(T), nullptr);
	return true;
}

template<typename T>
std::optional<std::enable_if_t<std::is_trivially_copyable_v<T>, T>>
	Memory::readMemory(const uint32_t* offsets, uint32_t len)
{
	static_assert(sizeof(T) <= Shm::BUFFER_SIZE);
	if (len > Shm::OFFSETS_LEN) throw std::invalid_argument("readMemory: offsets too long");
	if (!hookConnected(HookPosition::MAIN_LOOP)) return _readRemoteMemory<T>(offsets, len);
	auto p = _readMemory(sizeof(T), offsets, len);
	if (!p) return {};
	return *static_cast<volatile T*>(p);
}

template<typename T>
std::enable_if_t<std::is_trivially_copyable_v<std::remove_reference_t<T>>, bool>
	Memory::writeMemory(T&& val, const uint32_t* offsets, uint32_t len)
{
	static_assert(sizeof(T) <= Shm::BUFFER_SIZE);
	if (len > Shm::OFFSETS_LEN) throw std::invalid_argument("writeMemory: offsets too long");
	if (!hookConnected(HookPosition::MAIN_LOOP)) return _writeRemoteMemory(std::forward<T>(val), offsets, len);
	return _writeMemory(&val, sizeof(T), offsets, len);
}

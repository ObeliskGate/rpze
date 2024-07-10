#pragma once
#include "stdafx.h"
#include "SharedMemory.h"
#include "dllexport.h"
#include <stdint.h>
#include <optional>

constexpr char ERR_FILE_NAME[] = "rpze_err.log";

// 设置
void init(InitArgs args);

// 根据PhaseCode控制本帧应该做什么
void doAsPhaseCode(volatile PhaseCode& phaseCode, const SharedMemory* pSharedMemory);

template <std::integral T>
inline uintptr_t __get_offset_impl(T base) { return base; }

template <std::integral T, std::integral U>
inline uintptr_t __get_offset_impl(T base, U offset)
{
	// if (!base) return 0;
	auto t = *reinterpret_cast<uintptr_t*>(base);
	if (!t) return 0;
	return t + offset;
}

template <std::integral T, std::integral U, std::integral... Args>
inline uintptr_t __get_offset_impl(T base, U offset, Args... args)
{
	return __get_offset_impl(__get_offset_impl(base, offset), args...);
}

template <typename T, std::integral U, std::integral... Args>
std::optional<T> readMemory(U base, Args... offsets)
{
	auto ptr = __get_offset_impl(base, offsets...);
	if (!ptr) return {};
	return *reinterpret_cast<T*>(ptr);
}

template <typename T, std::integral U, std::integral... Args>
bool writeMemory(T&& val, U base, Args... offsets)
{
	auto ptr = __get_offset_impl(base, offsets...);
	if (!ptr) return false;
	*reinterpret_cast<T*>(ptr) = std::forward<T>(val);
	return true;
}

// 被注入到主流程游戏中的函数 isInGame==0时为LawnApp; ==1时为跳帧
template<DWORD isInGame>
void mainHook(const SharedMemory* pSharedMemory)
{
	pSharedMemory->shm().boardPtr = readMemory<DWORD>(0x6a9ec0, 0x768).value_or(0);
	if (pSharedMemory->shm().globalState == HookState::NOT_CONNECTED ||
		pSharedMemory->shm().hookStateArr[getHookIndex(HookPosition::MAIN_LOOP)] == HookState::NOT_CONNECTED) return;
	volatile PhaseCode* pPhaseCode;
	volatile RunState* pRunState;
	volatile SyncMethod* pSyncMethod;
	if constexpr (isInGame)
	{
		pPhaseCode = &pSharedMemory->shm().jumpingPhaseCode;
		pRunState = &pSharedMemory->shm().jumpingRunState;
		pSyncMethod = &pSharedMemory->shm().jumpingSyncMethod;
	}
	else
	{
		pPhaseCode = &pSharedMemory->shm().phaseCode;
		pRunState = &pSharedMemory->shm().runState;
		pSyncMethod = &pSharedMemory->shm().syncMethod;
	}
	if (*pSyncMethod == SyncMethod::MUTEX)
		pSharedMemory->releaseMutex();
	
	*pPhaseCode = PhaseCode::WAIT;
	*pRunState = RunState::OVER;
#ifndef NDEBUG
	std::println("start a main frame, sync mode: {}", (DWORD)*pSyncMethod);
#endif
	doAsPhaseCode(*pPhaseCode, pSharedMemory);
#ifndef NDEBUG
	std::println("end a main frame");
#endif
	if (*pSyncMethod == SyncMethod::MUTEX)
		pSharedMemory->waitMutex();
		
	*pRunState = RunState::RUNNING;
}

void doWhenJmpFrame(volatile PhaseCode& phaseCode);

// 可关闭的hook, 不与remote交互但是控制行为
// 返回true则建议do nothing，false则不执行被hook的函数
bool closableHook(const SharedMemory* pSharedMemory, HookPosition hook);

void initInThread(const SharedMemory* pSharedMemory);

void dllExit();
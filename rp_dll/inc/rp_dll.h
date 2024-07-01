#pragma once
#include "stdafx.h"
#include "SharedMemory.h"
#include <optional>
#include <array>

extern volatile uint32_t initOptions;

// 设置
void init();

// 根据PhaseCode控制本帧应该做什么
void doAsPhaseCode(volatile PhaseCode& phaseCode, const SharedMemory* pSharedMemory);

template <typename T, typename... Args>
requires (sizeof...(Args) >= 1) && (std::is_integral_v<Args> && ...)
std::optional<T> readMemory(Args... offsets)
{
	auto offsets_ = std::array { static_cast<uintptr_t>(offsets)... };
	auto base = offsets_[0];
	for (size_t i = 1; i < sizeof...(Args); i++)
	{
		if (base == 0) return {};
		base = *reinterpret_cast<uintptr_t*>(base) + offsets_[i];
	}
	if (base == 0) return {};
	return *reinterpret_cast<T*>(base);
}

template <typename T, typename... Args>
requires (sizeof...(Args) >= 1) && (std::is_integral_v<Args> && ...)
bool writeMemory(T&& val, Args... offsets)
{
	auto offsets_ = std::array { static_cast<uintptr_t>(offsets)... };
	auto base = offsets_[0];
	for (size_t i = 1; i < sizeof...(Args); i++)
	{
		if (base == 0) return false;
		base = *reinterpret_cast<uintptr_t*>(base) + offsets_[i];
	}
	if (base == 0) return false;
	*reinterpret_cast<T*>(base) = std::forward<T>(val);
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

void exit();
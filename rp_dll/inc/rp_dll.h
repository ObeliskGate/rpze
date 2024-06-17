#pragma once
#include "stdafx.h"
#include "SharedMemory.h"
#include <optional>
#include <array>

// 设置
void init();

// 根据PhaseCode控制本帧应该做什么
void doAsPhaseCode(volatile PhaseCode& phaseCode, const SharedMemory* pSharedMemory);

template <typename T, typename... Args>
std::optional<T> readMemory(Args&&... offsets)
{
	static_assert(sizeof...(Args) >= 1, "at least one offset is required");
	auto offsets_ = std::array<uintptr_t, sizeof...(Args)> {uintptr_t(std::forward<Args>(offsets))...};
	auto base = offsets_[0];
	for (size_t i = 1; i < sizeof...(Args); i++)
	{
		if (base == 0) return {};
		base = *reinterpret_cast<uintptr_t*>(base) + offsets_[i];
	}
	if (base == 0) return {};
	return T(*reinterpret_cast<T*>(base));
}

template <typename T, typename... Args>
bool writeMemory(T&& val, Args&&... offsets)
{
	static_assert(sizeof...(Args) >= 1, "at least one offset is required");
	auto offsets_ = std::array<uintptr_t, sizeof...(Args)> {uintptr_t(std::forward<Args>(offsets))...};
	auto base = offsets_[0];
	for (size_t i = 1; i < sizeof...(Args); i++)
	{
		if (base == 0) return false;
		base = *reinterpret_cast<uintptr_t*>(base) + offsets_[i];
	}
	if (base == 0) return false;
	*reinterpret_cast<T*>(base) = T(std::forward<T>(val));
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
	std::cout << "start a control frame, sync mode: " << (DWORD)*pSyncMethod << std::endl;
#endif
	doAsPhaseCode(*pPhaseCode, pSharedMemory);
#ifndef NDEBUG
	std::cout << "end a control frame" << std::endl;
#endif
	if (*pSyncMethod == SyncMethod::MUTEX)
		pSharedMemory->waitMutex();
		
	*pRunState = RunState::RUNNING;
}

void doWhenJmpFrame(volatile PhaseCode& phaseCode);

// 可关闭的hook, 不与remote交互但是控制行为
// 返回true则建议do nothing，false则不执行被hook的函数
bool closableHook(const SharedMemory* pSharedMemory, HookPosition hook);
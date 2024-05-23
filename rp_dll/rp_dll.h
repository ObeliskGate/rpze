#pragma once
#include "pch.h"
#include "SharedMemory.h"

// 设置控制台
void init();

// 根据PhaseCode控制本帧应该做什么
void doAsPhaseCode(volatile PhaseCode& phaseCode, const SharedMemory* pSharedMemory);

// 被注入到主流程游戏中的函数 isInGame==0时为LawnApp; ==1时为跳帧
template<DWORD isInGame>
void mainHook(const SharedMemory* pSharedMemory)
{
	pSharedMemory->boardPtr() = readMemory<DWORD>(0x6a9ec0, { 0x768 }).value_or(0);
	if (pSharedMemory->globalState() == HookState::NOT_CONNECTED ||
		pSharedMemory->hookStateArr()[getHookIndex(HookPosition::MAIN_LOOP)] == HookState::NOT_CONNECTED) return;
	volatile PhaseCode* pPhaseCode;
	volatile RunState* pRunState;
	volatile SyncMethod* pSyncMethod;
	if constexpr (isInGame)
	{
		pPhaseCode = &pSharedMemory->jumpingPhaseCode();
		pRunState = &pSharedMemory->jumpingRunState();
		pSyncMethod = &pSharedMemory->jumpingSyncMethod();
	}
	else
	{
		pPhaseCode = &pSharedMemory->phaseCode();
		pRunState = &pSharedMemory->runState();
		pSyncMethod = &pSharedMemory->syncMethod();
	}
	if (*pSyncMethod == SyncMethod::MUTEX)
		pSharedMemory->releaseMutex();
	
	*pPhaseCode = PhaseCode::WAIT;
	*pRunState = RunState::OVER;
	doAsPhaseCode(*pPhaseCode, pSharedMemory);
	if (*pSyncMethod == SyncMethod::MUTEX)
		pSharedMemory->waitMutex();
		
	*pRunState = RunState::RUNNING;
}

void doWhenJmpFrame(volatile PhaseCode& phaseCode);

// 可关闭的hook, 不与remote交互但是控制行为
// 返回true则建议do nothing，false则不执行被hook的函数
bool closableHook(const SharedMemory* pSharedMemory, HookPosition hook);

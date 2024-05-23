#pragma once
#include "pch.h"
#include "SharedMemory.h"

// ���ÿ���̨
void init();

// ����PhaseCode���Ʊ�֡Ӧ����ʲô
void doAsPhaseCode(volatile PhaseCode& phaseCode, const SharedMemory* pSharedMemory);

// ��ע�뵽��������Ϸ�еĺ��� isInGame==0ʱΪLawnApp; ==1ʱΪ��֡
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

// �ɹرյ�hook, ����remote�������ǿ�����Ϊ
// ����true����do nothing��false��ִ�б�hook�ĺ���
bool closableHook(const SharedMemory* pSharedMemory, HookPosition hook);

#pragma once
#include "pch.h"
#include "SharedMemory.h"

// ���ÿ���̨
void init();

// ����PhaseCode���Ʊ�֡Ӧ����ʲô
void doAsPhaseCode(volatile PhaseCode& phaseCode, const SharedMemory* pSharedMemory);

// ��ע�뵽��������Ϸ�еĺ���, һʽ���ݷֱ���LawnApp::UpdateFrames��IZUpdate
template<DWORD isInGame>
void mainHook(const SharedMemory* pSharedMemory)
{
	pSharedMemory->boardPtr() = readMemory<DWORD>(0x6a9ec0, { 0x768 }).value_or(0);
	if (pSharedMemory->globalState() == HookState::NOT_CONNECTED ||
		pSharedMemory->hookStateArr()[getHookIndex(HookPosition::MAIN_LOOP)] == HookState::NOT_CONNECTED) return;
	volatile PhaseCode* pPhaseCode;
	volatile RunState* pRunState;
	if constexpr (isInGame)
	{
		pPhaseCode = &pSharedMemory->jumpingPhaseCode();
		pRunState = &pSharedMemory->jumpingRunState();
	}
	else
	{
		pPhaseCode = &pSharedMemory->phaseCode();
		pRunState = &pSharedMemory->runState();
	}
	*pPhaseCode = PhaseCode::WAIT;
	*pRunState = RunState::OVER;
	doAsPhaseCode(*pPhaseCode, pSharedMemory);
	*pRunState = RunState::RUNNING;
}

void doWhenJmpFrame(volatile PhaseCode& phaseCode);

// �ɹرյ�hook, ����remote�������ǿ�����Ϊ
// ����true����do nothing��false��ִ�б�hook�ĺ���
bool closableHook(const SharedMemory* pSharedMemory, HookPosition hook);

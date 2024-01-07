#pragma once
#include "pch.h"
#include "SharedMemory.h"

// ���ÿ���̨
void init();

// ����PhaseCode���Ʊ�֡Ӧ����ʲô
void doAsPhaseCode(volatile PhaseCode& phaseCode, const SharedMemory* pSharedMemory);

// ��ע�뵽��������Ϸ�еĺ���, һʽ���ݷֱ���LawnApp::UpdateFrames��IZUpdate
void mainHook(DWORD isInGame, const SharedMemory* pSharedMemory);

void doWhenJmpFrame(volatile PhaseCode& phaseCode);

// �ɹرյ�hook, ����remote�������ǿ�����Ϊ
// ����true����do nothing��false��ִ�б�hook�ĺ���
bool closableHook(const SharedMemory* pSharedMemory, HookPosition hook);

// ��remote������hook
bool interactHook(const SharedMemory* pSharedMemory, HookPosition hook);
#pragma once
#include "pch.h"
#include "SharedMemory.h"

// ���ÿ���̨
void setConsole();

// ����PhaseCode���Ʊ�֡Ӧ����ʲô
void doAsPhaseCode(volatile PhaseCode& phaseCode);

// ��ע�뵽��Ϸ�еĺ���, һʽ���ݷֱ���LawnApp::UpdateFrames��IZUpdate
void __stdcall script(DWORD isInIZombie, SharedMemory* pSharedMemory);

// ע�뺯��
void injectScript(SharedMemory* pSharedMemory);
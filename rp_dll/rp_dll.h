#pragma once
#include "pch.h"
#include "SharedMemory.h"

// ���ÿ���̨
void init();

// ����PhaseCode���Ʊ�֡Ӧ����ʲô
void doAsPhaseCode(volatile PhaseCode& phaseCode);

// ��ע�뵽��Ϸ�еĺ���, һʽ���ݷֱ���LawnApp::UpdateFrames��IZUpdate
void script(DWORD isInGame, const SharedMemory* pSharedMemory);
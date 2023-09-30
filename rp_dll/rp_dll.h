#pragma once
#include "pch.h"
#include "SharedMemory.h"

// 设置控制台
void setConsole();

// 根据PhaseCode控制本帧应该做什么
void doAsPhaseCode(volatile PhaseCode& phaseCode);

// 被注入到游戏中的函数, 一式两份分别在LawnApp::UpdateFrames和IZUpdate
void __stdcall script(DWORD isInIZombie, SharedMemory* pSharedMemory);

// 注入函数
void injectScript(SharedMemory* pSharedMemory);
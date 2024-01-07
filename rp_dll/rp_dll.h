#pragma once
#include "pch.h"
#include "SharedMemory.h"

// 设置控制台
void init();

// 根据PhaseCode控制本帧应该做什么
void doAsPhaseCode(volatile PhaseCode& phaseCode, const SharedMemory* pSharedMemory);

// 被注入到主流程游戏中的函数, 一式两份分别在LawnApp::UpdateFrames和IZUpdate
void mainHook(DWORD isInGame, const SharedMemory* pSharedMemory);

void doWhenJmpFrame(volatile PhaseCode& phaseCode);

// 可关闭的hook, 不与remote交互但是控制行为
// 返回true则建议do nothing，false则不执行被hook的函数
bool closableHook(const SharedMemory* pSharedMemory, HookPosition hook);

// 与remote交互的hook
bool interactHook(const SharedMemory* pSharedMemory, HookPosition hook);
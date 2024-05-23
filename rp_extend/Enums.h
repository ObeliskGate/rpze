#pragma once
#include "stdafx.h"

enum class PhaseCode : int32_t
{
	CONTINUE = 0, // 让游戏继续执行
	WAIT, // 暂停游戏, 以读写操作
	RUN_CODE, // 执行汇编码
	JUMP_FRAME, // 跳帧
	READ_MEMORY, // 读内存
	WRITE_MEMORY, // 写内存
	READ_MEMORY_PTR // 读取sharedMemory在pvz进程中的位置
};

enum class RunState : int32_t
{
	RUNNING = 0, // 游戏正在运行中
	OVER // 游戏开始被阻塞
};

enum class ExecuteResult : int32_t
{
	END = 0, // 没在执行
	SUCCESS, // 执行成功
	FAIL // 执行失败
};

enum class HookState : int32_t
{
	NOT_CONNECTED = 0, // 未连接
	CONNECTED, // 已连接
};

enum class HookPosition : int32_t 
{
	MAIN_LOOP = 0,
	ZOMBIE_PICK_RANDOM_SPEED,
	CHALLENGE_I_ZOMBIE_SCORE_BRAIN,
	CHALLENGE_I_ZOMBIE_PLACE_PLANTS
};

enum class SyncMethod : int32_t
{
	SPIN = 0,
	MUTEX = 1
};

inline size_t getHookIndex(HookPosition pos) { return static_cast<size_t>(pos); }
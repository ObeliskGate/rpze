#pragma once
#include "pch.h"

enum class PhaseCode : int32_t
{
	CONTINUE = 0, // 让游戏继续执行
	WAIT, // 暂停游戏, 以读写操作
	RUN_CODE, // 执行汇编码
	JUMP_FRAME, // 跳帧
	READ_MEMORY, // 读内存
	WRITE_MEMORY, // 写内存
	READ_MEMORY_PTR
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

enum class GlobalState : int32_t
{
	NOT_CONNECTED = 0, // 未连接
	CONNECTED, // 已连接
};

enum class HookPosition : int32_t // 这个应该是作为index用的
{
	MAIN_LOOP = 0,
	ZOMBIE_PICK_RANDOM_SPEED
};

inline int32_t getIndex(HookPosition pos) { return static_cast<int32_t>(pos); }
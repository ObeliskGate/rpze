#pragma once
#include "stdafx.h"

enum class PhaseCode : int32_t
{
	CONTINUE = 0, // ����Ϸ����ִ��
	WAIT, // ��ͣ��Ϸ, �Զ�д����
	RUN_CODE, // ִ�л����
	JUMP_FRAME, // ��֡
	READ_MEMORY, // ���ڴ�
	WRITE_MEMORY, // д�ڴ�
	READ_MEMORY_PTR // ��ȡsharedMemory��pvz�����е�λ��
};

enum class RunState : int32_t
{
	RUNNING = 0, // ��Ϸ����������
	OVER // ��Ϸ��ʼ������
};

enum class ExecuteResult : int32_t
{
	END = 0, // û��ִ��
	SUCCESS, // ִ�гɹ�
	FAIL // ִ��ʧ��
};

enum class HookState : int32_t
{
	NOT_CONNECTED = 0, // δ����
	CONNECTED, // ������
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
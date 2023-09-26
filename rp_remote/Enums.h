#pragma once
#include "stdafx.h"

enum class PhaseCode : int32_t
{
	CONTINUE = 0, // ����Ϸ����ִ��
	WAIT, // ��ͣ��Ϸ, �Զ�д����
	RUN_CODE, // ִ�л����
	JUMP_FRAME, // ��֡
	READ_MEMORY, // ���ڴ�
	WRITE_MEMORY // д�ڴ�
};

enum class RunState : int32_t
{
	RUNNING = 0, // ��Ϸ����������
	OVER // ��Ϸ��ʼ������
};

enum class ReadWriteState : int32_t
{
	READY = 0, // �����ٴζ�д
	FUNCTIONING, // ��д��
	SUCCESS,  // ��д�ɹ�
	FAIL, // ��дʧ��
};
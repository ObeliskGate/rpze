#pragma once
#include "pch.h"

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

class SharedMemory
{
	static SharedMemory* instancePtr;

	void* sharedMemoryPtr;
	HANDLE hMapFile;
	std::wstring sharedMemoryName;
	SharedMemory();
	~SharedMemory() { CloseHandle(hMapFile); }

	template<typename T = BYTE>
	inline T* getPtr() const { return reinterpret_cast<T*>(sharedMemoryPtr); }

	template<typename T>
	inline T& getRef(int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }

	// ��������read��write��ָ��
	std::optional<void*> getReadWritePtr() const;

public:
	static SharedMemory* const getInstance();

	static bool deleteInstance();

	// �����ڴ�����
	inline std::wstring getName() const { return sharedMemoryName; }

	// ��ô������Ϸ
	inline volatile PhaseCode& getPhaseCode() const { return getRef<PhaseCode>(0); }

	// ��Ϸ����״̬
	inline RunState& getRunState() const { return getRef<RunState>(4); }

	// ��Ϸ��ǰʱ��
	inline uint32_t& getGameTime() const { return getRef<uint32_t>(8); }

	//  ��֡ʱ��ô������Ϸ
	inline volatile PhaseCode& getJumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// ��֡ʱ��Ϸ������״̬
	inline RunState& getJumpingRunState() const { return getRef<RunState>(16); }

	// ��д�ڴ�ʱ Ҫ��д���ڴ��λ��, ���Ϊ8
	inline volatile const uint32_t& getMemoryNum() const { return getRef<uint32_t>(20); }


	static constexpr size_t LENGTH = 10;
	static constexpr int32_t OFFSET_END = -1;
	// ��д�ڴ�ʱ��ƫ��, ��{0x6a9ec0, 0x768, OFFSET_END, ...}, ����OFFSET_ENDֹͣ��ȡ
	inline volatile int32_t* getOffsets() const { return reinterpret_cast<int32_t*>(getPtr() + 24); }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ��д����ڴ�����ݵ�ָ��
	inline volatile const void* const getWrittenVal() const { return static_cast<void*>(getPtr() + 64); }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ���ȡ�ڴ�����ָ��
	inline void* const getReadResult() const { return static_cast<void*>(getPtr() + 72); }

	// ��д״̬
	inline volatile ReadWriteState& getReadWriteState() const { return getRef<ReadWriteState>(80); }

	bool readMemory();

	bool writeMemory();
};
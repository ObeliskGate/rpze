#pragma once
#include "pch.h"
#include "Enums.h"

class SharedMemory
{
	static SharedMemory* instancePtr;

	void* sharedMemoryPtr;
	HANDLE hMapFile;
	std::wstring sharedMemoryName;
	SharedMemory();
	~SharedMemory() { CloseHandle(hMapFile); }

	template<typename T = BYTE>
	inline T* getPtr() const { return static_cast<T*>(sharedMemoryPtr); }

	template<typename T>
	inline T& getRef(const int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }

	// ��������read��write��ָ��
	std::optional<void*> getReadWritePtr() const;

public:
	void* getSharedMemoryPtr() const { return sharedMemoryPtr; }

	static SharedMemory* getInstance();

	static bool deleteInstance();

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
	inline volatile const void* getWrittenVal() const { return static_cast<void*>(getPtr() + 64); }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ���ȡ�ڴ�����ָ��
	inline volatile void* getReadResult() const { return static_cast<void*>(getPtr() + 72); }

	// ȫ��״̬
	inline volatile GlobalState& getGlobalState() const { return getRef<GlobalState>(80); }

	// ִ�н��
	inline ExecuteResult& getExecuteResult() const { return getRef<ExecuteResult>(84); }

	// 8�ֽ� ���ؽ��
	inline volatile void* getReturnResult() const { return static_cast<void*>(getPtr() + 88); }

	// �������asm��ָ��, ��600��ʼ
	inline void* getAsmPtr() const { return getPtr() + 600; }

	// ���ڴ�
	bool readMemory();

	// д�ڴ�
	bool writeMemory();
};
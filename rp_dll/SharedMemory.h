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
	~SharedMemory();

	template<typename T = BYTE>
	T* getPtr() const { return static_cast<T*>(sharedMemoryPtr); }

	template<typename T>
	T& getRef(const int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }

	// ��������read��write��ָ��
	std::optional<void*> getReadWritePtr() const;

public:
	static constexpr uint32_t BUFFER_OFFSET = 1024 * 4;
	static constexpr uint32_t BUFFER_SIZE = SHARED_MEMORY_SIZE - BUFFER_OFFSET;
	static constexpr uint32_t RESULT_OFFSET = 1024;
	static constexpr uint32_t RESULT_SIZE = BUFFER_OFFSET - RESULT_OFFSET;

	void* getSharedMemoryPtr() const { return sharedMemoryPtr; }

	static SharedMemory* getInstance();

	static bool deleteInstance();

	// ��ô������Ϸ
	volatile PhaseCode& phaseCode() const { return getRef<PhaseCode>(0); }

	// ��Ϸ����״̬
	volatile RunState& runState() const { return getRef<RunState>(4); }

	// pBoardָ��
	volatile uint32_t& boardPtr() const { return getRef<uint32_t>(8); }


	//  ��֡ʱ��ô������Ϸ
	volatile PhaseCode& jumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// ��֡ʱ��Ϸ������״̬
	volatile RunState& jumpingRunState() const { return getRef<RunState>(16); }

	// ��д�ڴ�ʱ Ҫ��д���ڴ��λ��
	volatile const uint32_t& memoryNum() const { return getRef<uint32_t>(20); }


#undef max
	static constexpr size_t OFFSETS_LEN = 16;
	static constexpr uint32_t OFFSET_END = std::numeric_limits<uint32_t>::max();
	// ��д�ڴ�ʱ��ƫ��, ��{0x6a9ec0, 0x768, OFFSET_END, ...}, ����OFFSET_ENDֹͣ��ȡ
	volatile uint32_t* getOffsets() const { return reinterpret_cast<uint32_t*>(getPtr() + 24); }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ��ֵ / �����ָ��
	void* getReadWriteVal() const { return getPtr() + BUFFER_OFFSET; }

	// ȫ��״̬
	volatile HookState& globalState() const { return getRef<HookState>(90); }

	// ִ�н��
	volatile ExecuteResult& executeResult() const { return getRef<ExecuteResult>(94); }

	// pBoardָ��Ч��λ
	volatile bool& isBoardPtrValid() const { return getRef<bool>(106); }

	static constexpr size_t HOOK_LEN = 16;
	// hookλ�õ�״̬
	volatile HookState* hookStateArr() const { return reinterpret_cast<HookState*>(getPtr() + 112); }

	// �������asm��ָ��, ��1024��ʼ
	void* getAsmPtr() const { return getPtr() + BUFFER_OFFSET; }

	// ���ڴ�
	bool readMemory() const;

	// д�ڴ�
	bool writeMemory() const;
};
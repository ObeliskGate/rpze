#pragma once
#include "stdafx.h"
#include "Enums.h"

class Memory
{
	void* pBuf;
	HANDLE hMemory;

	// �Ƿ�����֡
	bool isJumpingFrame = false;

	volatile PhaseCode* pCurrentPhaseCode;
	volatile RunState* pCurrentRunState;

	// ��pvz�й����ڴ��ַ
	uint32_t remoteMemoryAddress = 0;

	template<typename T = BYTE>
	inline T* getPtr() const { return static_cast<T*>(pBuf); }

	template<typename T>
	inline T& getRef(const int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }

	void getRemoteMemoryAddress();
public:
	explicit Memory(DWORD pid);

	~Memory() { endControl(); CloseHandle(hMemory);  }

	// ��ô������Ϸ
	inline volatile PhaseCode& getPhaseCode() const { return getRef<PhaseCode>(0); }

	// ��Ϸ����״̬
	inline volatile RunState& getRunState() const { return getRef<RunState>(4); }

	// ��Ϸ��ǰʱ��
	inline volatile uint32_t& getGameTime() const { return getRef<uint32_t>(8); }

	//  ��֡ʱ��ô������Ϸ
	inline volatile PhaseCode& getJumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// ��֡ʱ��Ϸ������״̬
	inline volatile RunState& getJumpingRunState() const { return getRef<RunState>(16); }

	// ��д�ڴ�ʱ Ҫ��д���ڴ��λ��, ���Ϊ8
	inline uint32_t& getMemoryNum() const { return getRef<uint32_t>(20); }


	static constexpr size_t LENGTH = 10;
	static constexpr int32_t OFFSET_END = -1;
	// ��д�ڴ�ʱ��ƫ��, ��{0x6a9ec0, 0x768, OFFSET_END, ...}, ����OFFSET_ENDֹͣ��ȡ
	inline int32_t* getOffsets() const { return reinterpret_cast<int32_t*>(getPtr() + 24); }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ�����ڴ���д����ڴ�����ݵ�ָ��
	inline void* getWrittenVal() const { return static_cast<void*>(getPtr() + 64); }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ���ȡ�ڴ�����ָ��
	inline volatile void* getReadResult() const { return static_cast<void*>(getPtr() + 72); }
	
	// ���ȫ��״̬
	inline volatile GlobalState& getGlobalState() const { return getRef<GlobalState>(80); }

	// ��д���
	inline volatile ExecuteResult& getExecuteResult() const { return getRef<ExecuteResult>(84); }

	// �������asm��ָ��, ��600��ʼ
	inline void* getAsmPtr() const { return getPtr() + 600; }

	inline volatile PhaseCode& getCurrentPhaseCode() const { return *pCurrentPhaseCode; }

	inline volatile RunState& getCurrentRunState() const { return *pCurrentRunState; }


	// ��ȡ�ڴ�, ����û�������Ӱ˵ļ��
	std::optional<volatile void*> _readMemory(BYTE size, const std::vector<int32_t>& offsets);

	// д���ڴ�, ����û�������Ӱ˵ļ��
	bool _writeMemory(const void* pVal, BYTE size, const std::vector<int32_t>& offsets);


	// ��Ҫ�ӿ�

	// ������һ֡
	inline void next() { getCurrentPhaseCode() = PhaseCode::CONTINUE; }
	
	// ��ʼ��֡, ��������֡����false
	bool startJumpFrame();

	// ������֡, ��������֡����false
	bool endJumpFrame();

	inline volatile bool isBlocked() const { return *pCurrentRunState == RunState::RUNNING; }
	// ����<int>({0x6a9ec0, 0x768})��������
	// ��֧��sizeof(T)<=8��offsets����������10
	template <typename T>
	std::optional<T> readMemory(const std::vector<int32_t>& offsets);

	// **ֱ��**�������valд����Ϸָ����ַ
	// ���벻Ҫ������б���ָ��Ķ���
	template<typename T>
	bool writeMemory(T&& val, const std::vector<int32_t>& offsets);

	bool runCode(const char* codes, int num);

	void endControl();

	uint32_t getWrittenAddress();
};

template<typename T>
inline std::optional<T> Memory::readMemory(const std::vector<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8. ");
	if (offsets.size() > 10) return {};
	auto p = _readMemory(sizeof(T), offsets);
	if (!p.has_value()) return {};
	return *static_cast<volatile T*>(p.value());
}

template<typename T>
inline bool Memory::writeMemory(T&& val, const std::vector<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8.");
	if (offsets.size() > 10) return false;
	return _writeMemory(&val, sizeof(T), offsets);
}

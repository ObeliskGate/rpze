#pragma once
#include "stdafx.h"
#include "Enums.h"

class Memory
{
	void* pBuf;
	HANDLE hMemory;
	HANDLE hPvz;

	// �Ƿ�����֡
	bool jumpingFrame = false;

	volatile PhaseCode* pCurrentPhaseCode;
	volatile RunState* pCurrentRunState;

	// ��pvz�й����ڴ�Ļ�ַ
	uint32_t remoteMemoryAddress = 0;

	template<typename T = BYTE>
	inline T* getPtr() const { return static_cast<T*>(pBuf); }

	template<typename T>
	inline T& getRef(const int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }

	void getRemoteMemoryAddress();

	template <typename T>
	std::optional<T*> getRemotePtr(const uint32_t* offsets, uint32_t len);

	// pvz����id
	DWORD pid = 0;

	// ��ô������Ϸ
	volatile PhaseCode& phaseCode() const { return getRef<PhaseCode>(0); }

	// ��Ϸ����״̬
	volatile RunState& runState() const { return getRef<RunState>(4); }

	// p_boardָ��
	volatile uint32_t& boardPtr() const { return getRef<uint32_t>(8); }

	//  ��֡ʱ��ô������Ϸ
	volatile PhaseCode& jumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// ��֡ʱ��Ϸ������״̬
	volatile RunState& jumpingRunState() const { return getRef<RunState>(16); }

	// ��д�ڴ�ʱ Ҫ��д���ڴ��λ��
	volatile uint32_t& memoryNum() const { return getRef<uint32_t>(20); }


# undef max  // sb macro
public:
	static constexpr uint32_t BUFFER_OFFSET = 1024 * 4;
	static constexpr uint32_t BUFFER_SIZE = SHARED_MEMORY_SIZE - BUFFER_OFFSET;
	static constexpr uint32_t RESULT_OFFSET = 1024;
	static constexpr uint32_t RESULT_SIZE = BUFFER_OFFSET - RESULT_OFFSET;
	static constexpr size_t OFFSET_LENGTH = 16;
	static constexpr uint32_t OFFSET_END = std::numeric_limits<uint32_t>::max();
private:
	// ��д�ڴ�ʱ��ƫ��, ��{0x6a9ec0, 0x768, OFFSET_END, ...}, ����OFFSET_ENDֹͣ��ȡ
	inline uint32_t* getOffsets() { return reinterpret_cast<uint32_t*>(getPtr() + 24); }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ��ֵ / �����ָ��
	void* getReadWriteVal() const { return getPtr() + BUFFER_OFFSET; }
	
	// ���ȫ��״̬
	volatile HookState& globalState() const { return getRef<HookState>(90); }

	// ��д���
	volatile ExecuteResult& executeResult() const { return getRef<ExecuteResult>(94); }

	// pBoardָ��Ч��λ
	volatile bool& isBoardPtrValid() const { return getRef<bool>(106); }

public:
	static constexpr size_t HOOK_LEN = 16;
private:
	// hookλ�õ�״̬
	volatile HookState* hookStateArr() const { return reinterpret_cast<HookState*>(getPtr() + 112); }

	// �������asm��ָ��
	void* getAsmPtr() const { return getPtr() + BUFFER_OFFSET; }


	volatile PhaseCode& getCurrentPhaseCode() const { return *pCurrentPhaseCode; }

	volatile RunState& getCurrentRunState() const { return *pCurrentRunState; }


	// ��ȡ�ڴ�, ����û�������Ӱ˵ļ��
	std::optional<volatile void*> _readMemory(uint32_t size, const uint32_t* offsets, uint32_t len);

	// д���ڴ�, ����û�������Ӱ˵ļ��
	bool _writeMemory(const void* pVal, uint32_t size, const uint32_t* offsets, uint32_t len);

	template<typename T>
	std::optional<T> _readRemoteMemory(const uint32_t* offsets, uint32_t len);

	template<typename T>
	bool _writeRemoteMemory(T&& val, const uint32_t* offsets, uint32_t len);

	// ��Ҫ�ӿ�
public:
	explicit Memory(DWORD pid);

	~Memory();

	// 8�ֽ� ���ؽ��
	volatile void* getReturnResult() const { return static_cast<void*>(getPtr() + RESULT_OFFSET); }

	DWORD getPid() const { return pid; }

	// �ȵ���csִ��
	void before() const;

	// ������һ֡
	void next() const { getCurrentPhaseCode() = PhaseCode::CONTINUE; }

	void skipFrames(size_t num = 1) const;

	bool isJumpingFrame() const { return jumpingFrame; }
	
	// ��ʼ��֡, ��������֡����false
	bool startJumpFrame();

	// ������֡, ��������֡����false
	bool endJumpFrame();

	bool isBlocked() const { return *pCurrentRunState == RunState::RUNNING || *pCurrentPhaseCode == PhaseCode::CONTINUE; }

	void untilGameExecuted() const;

	bool isShmPrepared() const { return hookConnected(HookPosition::MAIN_LOOP)
		&& *pCurrentPhaseCode == PhaseCode::WAIT
		&& *pCurrentRunState == RunState::OVER; }

	// ����<int>({0x6a9ec0, 0x768})��������
	// ��֧��sizeof(T)<=8��offsets����������10
	template <typename T>
	std::optional<T> readMemory(const uint32_t* offsets, uint32_t len);

	// **ֱ��**�������valд����Ϸָ����ַ
	// ���벻Ҫ������б���ָ��Ķ���
	template<typename T>
	bool writeMemory(T&& val, const uint32_t* offsets, uint32_t len);

	std::optional<std::unique_ptr<char[]>> readBytes(uint32_t size, const uint32_t* offsets, uint32_t len);

	bool writeBytes(const char* in, uint32_t size, const uint32_t* offsets, uint32_t len);

	bool runCode(const char* codes, size_t len) const;

	void startControl();

	void endControl();

	void openHook(HookPosition hook);

	void closeHook(HookPosition hook);

	bool hookConnected(HookPosition hook) const { return globalState() == HookState::CONNECTED && hookStateArr()[getHookIndex(hook)] == HookState::CONNECTED; }

	uint32_t getWrittenAddress() const { return remoteMemoryAddress + RESULT_OFFSET; }

	uint32_t getAsmAddress() const { return remoteMemoryAddress + BUFFER_OFFSET; }

	std::tuple<bool, uint32_t> getPBoard() const; // ��һλ����0��ʾ���뻻��
};

template <typename T>
std::optional<T*> Memory::getRemotePtr(const uint32_t* offsets, uint32_t len)
{
	uint64_t basePtr = offsets[0];
	for (size_t i = 1; i < len; i++)
	{
		ReadProcessMemory(hPvz, 
			reinterpret_cast<LPCVOID>(basePtr), 
			&basePtr, 
			sizeof(uint32_t), 
			nullptr);
		if (!basePtr) return {};
		basePtr += offsets[i];
	}
	return reinterpret_cast<T*>(basePtr);
}

template <typename T>
std::optional<T> Memory::_readRemoteMemory(const uint32_t* offsets, uint32_t len)
{
	auto remotePtr = getRemotePtr<T>(offsets, len);
	if (!remotePtr.has_value()) return {};
	T ret;
	ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(*remotePtr), &ret, sizeof(T), nullptr);
	return ret;
}

template <typename T>
bool Memory::_writeRemoteMemory(T&& val, const uint32_t* offsets, uint32_t len)
{
	auto remotePtr = getRemotePtr<T>(offsets, len);
	if (!remotePtr.has_value()) return false;
	WriteProcessMemory(hPvz, reinterpret_cast<LPVOID>(*remotePtr), &val, sizeof(T), nullptr);
	return true;
}

template<typename T>
std::optional<T> Memory::readMemory(const uint32_t* offsets, uint32_t len)
{
	static_assert(sizeof(T) <= BUFFER_SIZE);
	if (len > OFFSET_LENGTH) throw std::exception("readMemory:offsets too long");
	if (!hookConnected(HookPosition::MAIN_LOOP)) return _readRemoteMemory<T>(offsets, len);
	auto p = _readMemory(sizeof(T), offsets, len);
	if (!p.has_value()) return {};
	return *static_cast<volatile T*>(*p);
}

template<typename T>
bool Memory::writeMemory(T&& val, const uint32_t* offsets, uint32_t len)
{
	static_assert(sizeof(T) <= BUFFER_SIZE);
	if (len > OFFSET_LENGTH) throw std::exception("writeMemory: offsets too long");
	if (!hookConnected(HookPosition::MAIN_LOOP)) return _writeRemoteMemory(std::forward<T>(val), offsets, len);
	return _writeMemory(&val, sizeof(T), offsets, len);
}

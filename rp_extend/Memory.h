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

	// ��pvz�й����ڴ�Ļ�ַ
	uint32_t remoteMemoryAddress = 0;

	template<typename T = BYTE>
	inline T* getPtr() const { return static_cast<T*>(pBuf); }

	template<typename T>
	inline T& getRef(const int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }

	void getRemoteMemoryAddress();

	// pvz����id
	DWORD pid = 0;
public:
	explicit Memory(DWORD pid);

	~Memory() { 
		endControl();
		globalState() = HookState::NOT_CONNECTED;
		UnmapViewOfFile(pBuf);
		CloseHandle(hMemory);  
	}

	inline DWORD getPid() const { return pid; }

	// ��ô������Ϸ
	inline volatile PhaseCode& phaseCode() const { return getRef<PhaseCode>(0); }

	// ��Ϸ����״̬
	inline volatile RunState& runState() const { return getRef<RunState>(4); }

	// ��Ϸ��ǰʱ��
	inline volatile int32_t& gameTime() const { return getRef<int32_t>(8); }

	//  ��֡ʱ��ô������Ϸ
	inline volatile PhaseCode& jumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// ��֡ʱ��Ϸ������״̬
	inline volatile RunState& jumpingRunState() const { return getRef<RunState>(16); }

	// ��д�ڴ�ʱ Ҫ��д���ڴ��λ��, ���Ϊ8
	inline volatile uint32_t& memoryNum() const { return getRef<uint32_t>(20); }


# undef max  // sb macro
	static constexpr size_t LENGTH = 10;
	static constexpr uint32_t OFFSET_END = std::numeric_limits<uint32_t>::max();
	// ��д�ڴ�ʱ��ƫ��, ��{0x6a9ec0, 0x768, OFFSET_END, ...}, ����OFFSET_ENDֹͣ��ȡ
	inline uint32_t* getOffsets() const { return reinterpret_cast<uint32_t*>(getPtr() + 24); }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ�����ڴ���д����ڴ�����ݵ�ָ��
	inline void* getWrittenVal() const { return getPtr() + 64; }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ���ȡ�ڴ�����ָ��
	inline void* getReadResult() const { return static_cast<void*>(getPtr() + 72); }
	
	// ���ȫ��״̬
	inline volatile HookState& globalState() const { return getRef<HookState>(80); }

	// ��д���
	inline volatile ExecuteResult& executeResult() const { return getRef<ExecuteResult>(84); }

	// 8�ֽ� ���ؽ��
	inline volatile void* getReturnResult() const { return static_cast<void*>(getPtr() + 88);  }

	// p_boardָ��
	inline volatile uint32_t& boardPtr() const { return getRef<uint32_t>(96); }

	// pBoardָ��Ч��λ
	inline volatile bool& isBoardPtrValid() const { return getRef<bool>(100); }

	// ��10��
	// hookλ�õ�״̬
	inline volatile HookState* hookStateArr() const { return reinterpret_cast<HookState*>(getPtr() + 104); }


	// �������asm��ָ��, ��600��ʼ
	inline void* getAsmPtr() const { return getPtr() + 600; }

	inline volatile PhaseCode& getCurrentPhaseCode() const { return *pCurrentPhaseCode; }

	inline volatile RunState& getCurrentRunState() const { return *pCurrentRunState; }


	// ��ȡ�ڴ�, ����û�������Ӱ˵ļ��
	std::optional<volatile void*> _readMemory(BYTE size, const std::vector<uint32_t>& offsets);

	// д���ڴ�, ����û�������Ӱ˵ļ��
	bool _writeMemory(const void* pVal, BYTE size, const std::vector<uint32_t>& offsets);

	template<typename T>
	std::optional<T> _readRemoteMemory(const std::vector<uint32_t>& offsets);

	template<typename T>
	bool _writeRemoteMemory(T&& val, const std::vector<uint32_t>& offsets);

	// ��Ҫ�ӿ�

	// ������һ֡
	inline void next() { getCurrentPhaseCode() = PhaseCode::CONTINUE; }
	
	// ��ʼ��֡, ��������֡����false
	bool startJumpFrame();

	// ������֡, ��������֡����false
	bool endJumpFrame();

	inline bool isBlocked() const { return *pCurrentRunState == RunState::RUNNING || *pCurrentPhaseCode == PhaseCode::CONTINUE; }
	// ����<int>({0x6a9ec0, 0x768})��������
	// ��֧��sizeof(T)<=8��offsets����������10
	template <typename T>
	std::optional<T> readMemory(const std::vector<uint32_t>& offsets);

	// **ֱ��**�������valд����Ϸָ����ַ
	// ���벻Ҫ������б���ָ��Ķ���
	template<typename T>
	bool writeMemory(T&& val, const std::vector<uint32_t>& offsets);

	bool runCode(const char* codes, int num);

	void startControl();

	void endControl();

	void openHook(HookPosition hook);

	void closeHook(HookPosition hook);

	uint32_t getWrittenAddress();

	inline std::tuple<bool, uint32_t> getPBoard() const // ��һλ����0��ʾ���뻻��
	{
		auto t = isBoardPtrValid();
		isBoardPtrValid() = true;
		return { t, boardPtr() };
	}
};

template <typename T>
std::optional<T> Memory::_readRemoteMemory(const std::vector<uint32_t>& offsets)
{
	HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	uint64_t basePtr = offsets[0];
	do
	{
		for (size_t i = 1; i < offsets.size(); i++)
		{
			ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &basePtr, sizeof(int32_t), nullptr);
			if (!basePtr) break;
			basePtr += offsets[i];
		}
		if (!basePtr) break;
		T ret;
		ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &ret, sizeof(T), nullptr);
		CloseHandle(hPvz);
		return ret;
	} while (false);
	CloseHandle(hPvz);
	return {};
}

template <typename T>
bool Memory::_writeRemoteMemory(T&& val, const std::vector<uint32_t>& offsets)
{
	HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	uint64_t basePtr = offsets[0];
	do
	{
		for (size_t i = 1; i < offsets.size(); i++)
		{
			ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &basePtr, sizeof(int32_t), nullptr);
			if (!basePtr) break;
			basePtr += offsets[i];
		}
		if (!basePtr) break;
		WriteProcessMemory(hPvz, reinterpret_cast<LPVOID>(basePtr), &val, sizeof(T), nullptr);
		CloseHandle(hPvz);
		return true;
	} while (false);
	CloseHandle(hPvz);
	return false;
}

template<typename T>
inline std::optional<T> Memory::readMemory(const std::vector<uint32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8. ");
	if (offsets.size() > 10) return {};
	if (globalState() == HookState::NOT_CONNECTED || hookStateArr()[getHookIndex(HookPosition::MAIN_LOOP)] == HookState::NOT_CONNECTED) 
		return _readRemoteMemory<T>(offsets);
	auto p = _readMemory(sizeof(T), offsets);
	if (!p.has_value()) return {};
	return *static_cast<volatile T*>(*p);

}

template<typename T>
inline bool Memory::writeMemory(T&& val, const std::vector<uint32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8.");
	if (offsets.size() > 10) return false;
	if (globalState() == HookState::NOT_CONNECTED || hookStateArr()[getHookIndex(HookPosition::MAIN_LOOP)] == HookState::NOT_CONNECTED) 
		return _writeRemoteMemory(std::forward<T>(val), offsets);
	return _writeMemory(&val, sizeof(T), offsets);
}

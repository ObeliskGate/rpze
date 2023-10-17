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

	~Memory() { endControl(); CloseHandle(hMemory);  }

	inline DWORD getPid() const { return pid; }

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
	inline void* getWrittenVal() const { return getPtr() + 64; }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ���ȡ�ڴ�����ָ��
	inline volatile void* getReadResult() const { return static_cast<void*>(getPtr() + 72); }
	
	// ���ȫ��״̬
	inline GlobalState& getGlobalState() const { return getRef<GlobalState>(80); }

	// ��д���
	inline volatile ExecuteResult& getExecuteResult() const { return getRef<ExecuteResult>(84); }

	// 8�ֽ� ���ؽ��
	inline volatile void* getReturnResult() const { return static_cast<void*>(getPtr() + 88);  }

	// �������asm��ָ��, ��600��ʼ
	inline void* getAsmPtr() const { return getPtr() + 600; }

	inline volatile PhaseCode& getCurrentPhaseCode() const { return *pCurrentPhaseCode; }

	inline volatile RunState& getCurrentRunState() const { return *pCurrentRunState; }


	// ��ȡ�ڴ�, ����û�������Ӱ˵ļ��
	std::optional<volatile void*> _readMemory(BYTE size, const std::vector<int32_t>& offsets);

	// д���ڴ�, ����û�������Ӱ˵ļ��
	bool _writeMemory(const void* pVal, BYTE size, const std::vector<int32_t>& offsets);

	template<typename T>
	std::optional<T> _readRemoteMemory(const std::vector<int32_t>& offsets);

	template<typename T>
	bool _writeRemoteMemory(T&& val, const std::vector<int32_t>& offsets);

	// ��Ҫ�ӿ�

	// ������һ֡
	inline void next() { getCurrentPhaseCode() = PhaseCode::CONTINUE; }
	
	// ��ʼ��֡, ��������֡����false
	bool startJumpFrame();

	// ������֡, ��������֡����false
	bool endJumpFrame();

	inline bool isBlocked() const { return *pCurrentRunState == RunState::RUNNING; }
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

template <typename T>
std::optional<T> Memory::_readRemoteMemory(const std::vector<int32_t>& offsets)
{
	HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	int32_t basePtr = offsets[0];
	do
	{
		for (size_t i = 1; i < offsets.size(); i++)
		{
			if (!basePtr) break;
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
bool Memory::_writeRemoteMemory(T&& val, const std::vector<int32_t>& offsets)
{
	HANDLE hPvz = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	int32_t basePtr = offsets[0];
	do
	{
		for (size_t i = 1; i < offsets.size(); i++)
		{
			if (!basePtr) break;
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
inline std::optional<T> Memory::readMemory(const std::vector<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8. ");
	if (offsets.size() > 10) return {};
	if (getGlobalState() == GlobalState::NOT_CONNECTED) return _readRemoteMemory<T>(offsets);
	auto p = _readMemory(sizeof(T), offsets);
	if (!p.has_value()) return {};
	return *static_cast<volatile T*>(p.value());
}

template<typename T>
inline bool Memory::writeMemory(T&& val, const std::vector<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "Please assert sizeof(T) <= 8.");
	if (offsets.size() > 10) return false;
	if (getGlobalState() == GlobalState::NOT_CONNECTED) return _writeRemoteMemory(std::forward<T>(val), offsets);
	return _writeMemory(&val, sizeof(T), offsets);
}

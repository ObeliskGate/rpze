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
	static constexpr uint32_t BUFFER_OFFSET = 4096;
	static constexpr uint32_t BUFFER_SIZE = SHARED_MEMORY_SIZE - BUFFER_OFFSET;

	explicit Memory(DWORD pid);

	~Memory() { 
		endControl();
		globalState() = HookState::NOT_CONNECTED;
		UnmapViewOfFile(pBuf);
		CloseHandle(hMemory);  
	}

	DWORD getPid() const { return pid; }

	// ��ô������Ϸ
	volatile PhaseCode& phaseCode() const { return getRef<PhaseCode>(0); }

	// ��Ϸ����״̬
	volatile RunState& runState() const { return getRef<RunState>(4); }

	// // ��Ϸ��ǰʱ��
	// volatile int32_t& gameTime() const { return getRef<int32_t>(8); }

	//  ��֡ʱ��ô������Ϸ
	volatile PhaseCode& jumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// ��֡ʱ��Ϸ������״̬
	volatile RunState& jumpingRunState() const { return getRef<RunState>(16); }

	// ��д�ڴ�ʱ Ҫ��д���ڴ��λ��
	volatile uint32_t& memoryNum() const { return getRef<uint32_t>(20); }


# undef max  // sb macro
	static constexpr size_t LENGTH = 10;
	static constexpr uint32_t OFFSET_END = std::numeric_limits<uint32_t>::max();
	// ��д�ڴ�ʱ��ƫ��, ��{0x6a9ec0, 0x768, OFFSET_END, ...}, ����OFFSET_ENDֹͣ��ȡ
	inline uint32_t* getOffsets() { return reinterpret_cast<uint32_t*>(getPtr() + 24); }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ��ֵ / �����ָ��
	void* getReadWriteVal() const { return getPtr() + BUFFER_OFFSET; }
	
	// ���ȫ��״̬
	volatile HookState& globalState() const { return getRef<HookState>(80); }

	// ��д���
	volatile ExecuteResult& executeResult() const { return getRef<ExecuteResult>(84); }

	// 8�ֽ� ���ؽ��
	volatile void* getReturnResult() const { return static_cast<void*>(getPtr() + 88);  }

	// p_boardָ��
	volatile uint32_t& boardPtr() const { return getRef<uint32_t>(96); }

	// pBoardָ��Ч��λ
	volatile bool& isBoardPtrValid() const { return getRef<bool>(100); }

	// ��10��
	// hookλ�õ�״̬
	volatile HookState* hookStateArr() { return reinterpret_cast<HookState*>(getPtr() + 104); }


	// �������asm��ָ��
	void* getAsmPtr() const { return getPtr() + BUFFER_OFFSET; }

	volatile PhaseCode& getCurrentPhaseCode() const { return *pCurrentPhaseCode; }

	volatile RunState& getCurrentRunState() const { return *pCurrentRunState; }


	// ��ȡ�ڴ�, ����û�������Ӱ˵ļ��
	std::optional<volatile void*> _readMemory(uint32_t size, const std::vector<uint32_t>& offsets);

	// д���ڴ�, ����û�������Ӱ˵ļ��
	bool _writeMemory(const void* pVal, uint32_t size, const std::vector<uint32_t>& offsets);

	template<typename T>
	std::optional<T> _readRemoteMemory(const std::vector<uint32_t>& offsets);

	template<typename T>
	bool _writeRemoteMemory(T&& val, const std::vector<uint32_t>& offsets);

	// ��Ҫ�ӿ�

	// ������һ֡
	void next() const { getCurrentPhaseCode() = PhaseCode::CONTINUE; }
	
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

	std::optional<std::string> readBytes(uint32_t size, const std::vector<uint32_t>& offsets);

	bool writeBytes(const std::string& in, const std::vector<uint32_t>& offsets);

	bool runCode(const std::string& codes) const;

	void startControl();

	void endControl();

	void openHook(HookPosition hook);

	void closeHook(HookPosition hook);

	bool hookConnected(HookPosition hook) { return globalState() == HookState::CONNECTED && hookStateArr()[getHookIndex(hook)] == HookState::CONNECTED; }

	uint32_t getWrittenAddress() const;

	uint32_t getAsmAddress() const { return remoteMemoryAddress + BUFFER_OFFSET; }

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
			ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &basePtr, sizeof(uint32_t), nullptr);
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
			ReadProcessMemory(hPvz, reinterpret_cast<LPCVOID>(basePtr), &basePtr, sizeof(uint32_t), nullptr);
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
	static_assert(sizeof(T) <= BUFFER_SIZE);
	if (offsets.size() > 10) return {};
	if (!hookConnected(HookPosition::MAIN_LOOP)) return _readRemoteMemory<T>(offsets);
	auto p = _readMemory(sizeof(T), offsets);
	if (!p.has_value()) return {};
	return *static_cast<volatile T*>(*p);
}

template<typename T>
inline bool Memory::writeMemory(T&& val, const std::vector<uint32_t>& offsets)
{
	static_assert(sizeof(T) <= BUFFER_SIZE);
	if (offsets.size() > 10) return false;
	if (!hookConnected(HookPosition::MAIN_LOOP)) return _writeRemoteMemory(std::forward<T>(val), offsets);
	return _writeMemory(&val, sizeof(T), offsets);
}

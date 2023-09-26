#pragma once
#include "stdafx.h"
#include "Enums.h"

class Memory
{
	void* pBuf;
	HANDLE hMemory;

	template<typename T = BYTE>
	inline T* getPtr() const { return reinterpret_cast<T*>(pBuf); }

	template<typename T>
	inline T& getRef(int offset) const { return *reinterpret_cast<T*>(getPtr() + offset); }
public:
	Memory(HANDLE hPvz);

	~Memory() { CloseHandle(hMemory); }

	// ��ô������Ϸ
	inline volatile PhaseCode& getPhaseCode() const { return getRef<PhaseCode>(0); }

	// ��Ϸ����״̬
	inline volatile RunState& getRunState() const { return getRef<RunState>(4); }

	// ��Ϸ��ǰʱ��
	inline volatile uint32_t& getGameTime() const { return getRef<uint32_t>(8); }

	//  ��֡ʱ��ô������Ϸ
	inline volatile PhaseCode& getJumpingPhaseCode() const { return getRef<PhaseCode>(12); }

	// ��֡ʱ��Ϸ������״̬
	inline RunState& getJumpingRunState() const { return getRef<RunState>(16); }

	// ��д�ڴ�ʱ Ҫ��д���ڴ��λ��, ���Ϊ8
	inline uint32_t& getMemoryNum() const { return getRef<uint32_t>(20); }


	static constexpr size_t LENGTH = 10;
	static constexpr int32_t OFFSET_END = -1;
	// ��д�ڴ�ʱ��ƫ��, ��{0x6a9ec0, 0x768, OFFSET_END, ...}, ����OFFSET_ENDֹͣ��ȡ
	inline int32_t* getOffsets() const { return reinterpret_cast<int32_t*>(getPtr() + 24); }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ�����ڴ���д����ڴ�����ݵ�ָ��
	inline void* const getWrittenVal() const { return static_cast<void*>(getPtr() + 64); }

	// ռλ8���ֽ�, ��д�ڴ�ʱ ָ���ȡ�ڴ�����ָ��
	inline volatile void* const getReadResult() const { return static_cast<void*>(getPtr() + 72); }

	// ��д״̬
	inline volatile ReadWriteState& getReadWriteState() const { return getRef<ReadWriteState>(80); }

	// ��ȡ�ڴ�, ����û�������Ӱ˵ļ��
	std::optional<volatile void*> _readMemory(BYTE size, const std::initializer_list<int32_t>& offsets);

	// д���ڴ�, ����û�������Ӱ˵ļ��
	bool _writeMemory(const void* pVal, BYTE size, const std::initializer_list<int32_t>& offsets);

	// ����<int>({0x6a9ec0, 0x768})��������
	// ��֧��sizeof(T)<=8��offsets������10
	template <typename T>
	std::optional<T> readMemory(const std::initializer_list<int32_t>& offsets);

	template<typename T>
	bool writeMemory(T val, const std::initializer_list<int32_t>& offsets);
};

template<typename T>
inline std::optional<T> Memory::readMemory(const std::initializer_list<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "sizeof(T)<=8");
	auto p = _readMemory(sizeof(T), offsets);
	if (!p.has_value()) return {};
	return *(T*)(p.value());
}

template<typename T>
inline bool Memory::writeMemory(T val, const std::initializer_list<int32_t>& offsets)
{
	static_assert(sizeof(T) <= 8, "sizeof(T)<=8");
	return _writeMemory(&val, sizeof(T), offsets);
}

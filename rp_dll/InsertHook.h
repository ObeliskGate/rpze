#pragma once
#include "pch.h"
#include "ExecutableUniquePtr.h"
#include <cstddef>

constexpr size_t REGISTERS_SIZE = 0x24;

class Registers
{
	BYTE* data = nullptr;

	template<int N, typename T = int32_t>
	const T& get() const { return *reinterpret_cast<const T*>(data + N); }

	template<int N, typename T = int32_t>
	T& get() { return *reinterpret_cast<T*>(data + N); }
public:
	const BYTE* getBase() const { return data; }

	BYTE*& getBase() { return data; }

	uint32_t efl() const { return get<0, uint32_t>(); }
	int32_t edi() const { return get<4>(); }
	int32_t esi() const { return get<8>(); }
	int32_t ebp() const { return get<12>(); }
	int32_t esp() const { return get<16>(); }
	int32_t ebx() const { return get<20>(); }
	int32_t edx() const { return get<24>(); }
	int32_t ecx() const { return get<28>(); }
	int32_t eax() const { return get<32>(); }

	BYTE bl() const { return get<20, BYTE>(); }
	BYTE dl() const { return get<24, BYTE>(); }
	BYTE cl() const { return get<28, BYTE>(); }
	BYTE al() const { return get<32, BYTE>(); }

	uint32_t& efl() { return get<0, uint32_t>(); }
	int32_t& edi() { return get<4>(); }
	int32_t& esi() { return get<8>(); }
	int32_t& ebp() { return get<12>(); }
	int32_t& esp() { return get<16>(); }
	int32_t& ebx() { return get<20>(); }
	int32_t& edx() { return get<24>(); }
	int32_t& ecx() { return get<28>(); }
	int32_t& eax() { return get<32>(); }

	BYTE& bl() { return get<20, BYTE>(); }
	BYTE& dl() { return get<24, BYTE>(); }
	BYTE& cl() { return get<28, BYTE>(); }
	BYTE& al() { return get<32, BYTE>(); }

	Registers(BYTE* stackTopPtr) : data(stackTopPtr) {}
	Registers() : Registers(nullptr) {}
};

using InsertHookFunc = void(Registers&);  
using ReplaceHookFunc = std::optional<int32_t>(Registers&, void*);
// ����{}��ʾ����ִ��ԭ����, ����������ʾԭ��������ֵ

class InsertHook
{
	static constexpr char INIT_CODE[] = "`"		  // pushad
		"\xb9\xcc\xcc\x00\x00"				  // mov ecx, InsertHookPtr(����this)
		"\xb8\xcc\xcc\x00\x00"				  // mov eax, hookStub
		"\xff\xe0";							  // jmp eax

	static constexpr char AFTER_CODE[] = "\x9d\x61"		  // popfd popad
		"\xe9\xcc\xcc\xcc\xcc";				  // jmp originalCode

	static constexpr char RETURN_CODE[] = "\x9d\x61\xc2\xdd\xdd"; // popfd popad ret N

	void* pInsert; // ��ע��λ��

	ExecutableUniquePtr<char> beforeCode;  // ���滻�Ĵ����, ��jmp������ִ��

	size_t replacedSize;  // ���滻�Ĵ���δ�С

	std::unique_ptr<char[]> replacedCode; // ���滻�ĺ�����

	ExecutableUniquePtr<char> afterCode; // ���汻ע�������������ʱ��Ҫִ�еĴ���� ����Ϊpopfd popad jmp originalCode

	ExecutableUniquePtr<char> returnCode; // �ڰ���ԭ��������ʱ��Ҫִ�еĴ����, ����Ϊpopfd popad ret N

	Registers registers;  // ���ڱ���Ĵ���״̬�Ķ���

	std::function<ReplaceHookFunc> hookFunctor;

	bool __fastcall hookFunc(BYTE* stackTopPtr); // ��ʼ��registers �Լ�����InsertHookFunc

	DWORD __thiscall getAfterCodePtr() { return reinterpret_cast<DWORD>(afterCode.get()); }

	DWORD __thiscall getReturnCodePtr() { return reinterpret_cast<DWORD>(returnCode.get()); }

	ExecutableUniquePtr<char> originalCode; // ��������ԭ�����Ĵ����, ����jmp��ԭ����
	
	void setOriginalCode();

	InsertHook(void* pInsert, size_t replacedSize, WORD popStackNum, std::function<ReplaceHookFunc> hookFunc);

	~InsertHook();

	inline static std::vector<InsertHook*> hooks{};

public:
	int32_t returnVal; // replaceHook ����ֵ�Ĳ���.

	static const InsertHook& addReplace(
		void* pInsert, 
		size_t replacedSize, 
		const std::function<ReplaceHookFunc>& hookFunc,
		WORD popStackNum = 0);

	static const InsertHook& addInsert(
		void* pInsert, 
		size_t replacedSize, 
		const std::function<InsertHookFunc>& hookFunc);

	static void deleteAll();

	void* getOriginalFuncPtr() { return originalCode.get(); } // ����callԭ������ָ��
};

inline void __declspec(naked) hookStub() // ����Ϊecx = InsertHook* ��jmp���� ������Ҫ�ֶ�popfd popad��naked����. ���ܻ���ϼ�����һ��ret.
{
	__asm
	{
		pushfd
		push ecx
		lea edx, [esp + 4]
		call offset InsertHook::hookFunc
		pop ecx
		test al, al
		je LReturnEnd
		call offset InsertHook::getAfterCodePtr
		jmp eax

		LReturnEnd :
		call offset InsertHook::getReturnCodePtr
		jmp eax
	}
}
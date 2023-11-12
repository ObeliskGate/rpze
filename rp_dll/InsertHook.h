#pragma once
#include "pch.h"
#include "VirtualUniquePtr.h"
#include <cstddef>

constexpr size_t REGISTERS_SIZE = 0x24; // 还有一个字节是

class Registers
{
	BYTE data[REGISTERS_SIZE] = {};

	template<int N, typename T = int32_t>
	T get() const { return *reinterpret_cast<const T*>(data + N); }
public:
	BYTE* getBase() { return data; }

	uint32_t efl() const { return get<0>(); }
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
};

using InsertHookFunc = void(Registers&);  // 返回true表示继续执行原函数, 返回false表示不执行原函数
using ReplaceHookFunc = bool(Registers&);

class InsertHook
{
	static constexpr char INIT_CODE[] = "`"		  // pushad
		"\xb9\xcc\xcc\x00\x00"				  // mov ecx, InsertHookPtr(就是this)
		"\xb8\xcc\xcc\x00\x00"				  // mov eax, hookStub
		"\xff\xe0";							  // jmp eax

	static constexpr char END_CODE[] = "\x9d\x61"		  // popfd popad
		"\xe9\xcc\xcc\xcc\xcc";				  // jmp pInsert + replacedSize

	void* pInsert; // 被注入位置

	VirtualUniquePtr<char> originalCode;  // 被替换的代码段, 在jmp结束后执行

	size_t replacedSize;  // 被替换的代码段大小

	VirtualUniquePtr<char> afterCode; // 在替被注入的主函数返回时需要执行的代码段 内容为endcode清栈 popad jmp pInsert + replacedSize

	Registers registers{};  // 用于保存寄存器状态的对象

	std::function<ReplaceHookFunc> hookFunctor;

	bool __thiscall hookFunc(DWORD stackTopPtr); // 初始化registers 以及调用InsertHookFunc

	InsertHook(void* pInsert, size_t replacedSize, DWORD popStackNum, std::function<ReplaceHookFunc> hookFunc);

	~InsertHook();

	inline static std::vector<InsertHook*> hooks{};

public:
	DWORD popStackNum; // replaceHook 描述清理栈几次的参数.

	static const InsertHook& addReplace(void* pInsert, size_t replacedSize, std::function<ReplaceHookFunc> hookFunc, DWORD popStackNum = 0);

	static const InsertHook& addInsert(void* pInsert, size_t replacedSize, std::function<InsertHookFunc> hookFunc);
	static void deleteAll();

	DWORD __fastcall getAfterCodePtr() { return reinterpret_cast<DWORD>(afterCode.get()); }
};

constexpr size_t POP_STACK_NUM_OFFSET = offsetof(InsertHook, popStackNum);

inline void __declspec(naked) hookStub() // 参数为ecx = InsertHook* 用jmp调用 并且需要手动popfd popad的naked函数. 可能会帮上级函数一起ret.
{
	__asm
	{
		pushfd
		push ecx
		lea eax, [esp + 4]
		push eax
		call offset InsertHook::hookFunc
		pop ecx
		test al, al
		jz LReturnEnd
		call offset InsertHook::getAfterCodePtr
		jmp eax

		LReturnEnd :
		mov eax, 0x6b0200
		mov [eax], ecx
		popfd
		popad
		mov ecx, [0x6b0200]
		mov eax, [POP_STACK_NUM_OFFSET]
		mov eax, [ecx + eax]
		LReturnLoop :
			test eax, eax
			jz LReturnLoopEnd
			inc eax
			pop ecx
			jmp LReturnLoop

			LReturnLoopEnd:
			ret
	}
}
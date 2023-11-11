#pragma once
#include "pch.h"
#include "VirtualUniquePtr.h"
#include <cstddef>

constexpr size_t REGISTERS_SIZE = 0x24; // 还有一个字节是

class Registers
{
	BYTE data[REGISTERS_SIZE] = {};

	template<int N, typename T = int32_t>
	T get() { return *reinterpret_cast<T*>(data + N * sizeof(T)); }
public:
	BYTE* getBase() { return data; }

	uint32_t efl() { return get<0>(); }
	int32_t edi() { return get<4>(); }
	int32_t esi() { return get<8>(); }
	int32_t ebp() { return get<12>(); }
	int32_t esp() { return get<16>(); }
	int32_t ebx() { return get<20>(); }
	int32_t edx() { return get<24>(); }
	int32_t ecx() { return get<28>(); }
	int32_t eax() { return get<32>(); }

	BYTE bl() { return get<20, BYTE>(); }
	BYTE dl() { return get<24, BYTE>(); }
	BYTE cl() { return get<28, BYTE>(); }
	BYTE al() { return get<32, BYTE>(); }
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

	VirtualUniquePtr<char> originalCode;  // 被替换的代码段, 在jmp开始时执行

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

inline constexpr size_t POP_STACK_NUM_OFFSET = offsetof(InsertHook, popStackNum);

inline void __declspec(naked) __fastcall hookStub(InsertHook* pInsertHook) // 用jmp调用 并且需要手动popfd popad的naked函数. 可能会帮上级函数一起ret.
{
	__asm
	{
		pushfd
		push ecx
		lea eax, [ebp + 4]
		push eax
		call offset InsertHook::hookFunc
		pop ecx
		test al, al
		jz LOriginalEnd
		jmp LReturnEnd

		LOriginalEnd :
		call offset InsertHook::getAfterCodePtr
		jmp eax

		LReturnEnd :
		mov eax, [ecx + POP_STACK_NUM_OFFSET]
		jmp LReturnLoop

			LReturnLoop :
			test eax, eax
			jz LReturnLoopEnd
			inc eax
			pop ecx
			jmp LReturnLoop

			LReturnLoopEnd:
			popfd
			popad
			ret
	}
}
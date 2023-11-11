#pragma once
#include "pch.h"

constexpr char REGISTER_INIT_CODE[] = "`" // pushad 下面这段注释的r是0xbbbbbb, 代表reg base ptr
	"\xa3\xbb\xbb\x0b\x00"				  // mov [r], eax
	"\x89\r\xbb\xbb\x0b\x00"			  // mov [r], ecx
	"\x89\x15\xbb\xbb\x0b\x00"			  // mov [r], edx
	"\x89\x1d\xbb\xbb\x0b\x00"			  // mov [r], ebx
	"\x89%\xbb\xbb\x0b\x00"				  // mov [r], esp	
	"\x89-\xbb\xbb\x0b\x00"				  // mov [r], ebp
	"\x89""5\xbb\xbb\x0b\x00"			  // mov [r], esi
	"\x89=\xbb\xbb\x0b\x00"				  // mov [r], edi
	"\x68\xbb\xbb\x0b\x00"				  // push r
	"\xb9\xcc\xcc\x00\x00"				  // mov ecx, ptr
	"\xff\xd1"							  // call ecx
	"a";                                  // popad

class Registers
{
	BYTE data[0x20] = {};

	template<int N, typename T = int32_t>
	inline T get() { return *reinterpret_cast<T*>(data + N * sizeof(T)); }
public:
	int32_t eax() { return get<0>(); }
	int32_t ecx() { return get<4>(); }
	int32_t edx() { return get<8>(); }
	int32_t ebx() { return get<12>(); }
	int32_t esp() { return get<16>(); }
	int32_t ebp() { return get<20>(); }
	int32_t esi() { return get<24>(); }
	int32_t edi() { return get<28>(); }

	BYTE al() { return get<0, BYTE>(); }
	BYTE cl() { return get<4, BYTE>(); }
	BYTE dl() { return get<8, BYTE>(); }
	BYTE bl() { return get<12, BYTE>(); }

	BYTE* getBase() { return data; }

	static void 
};

using InsertHookFuncType = void(__stdcall*)(const Registers&);

class InsertHook
{
	char* code;
	Registers regs{};
	char originalCode[5];
	InsertHookFuncType hookFunc;
	void* pHook;

	InsertHook(DWORD hookPtr, InsertHookFuncType hookFunc);

	~InsertHook();
public:
	inline static std::vector<InsertHook*> hooks{};

	static const InsertHook& addInsertHook(DWORD hookPtr, InsertHookFuncType hookFunc);

	static void disableInsertHooks();
};


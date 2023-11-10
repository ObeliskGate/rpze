#include "pch.h"
#include "Hook.h"

Hook::Hook(DWORD hookPtr, HookFuncType hookFunc)
{
	pHook = reinterpret_cast<void*>(hookPtr);
	constexpr size_t SIZE = sizeof(REGISTER_INIT_CODE) - 1 + 5 * 2;
	this->code = static_cast<char*>(VirtualAlloc(NULL, SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	if (this->code == NULL) // virtualalloc真的会NULL吗
	{
		std::cout << "VirtualAlloc failed when creating hook: " << GetLastError() << std::endl;
		throw std::exception("VirtualAlloc failed when creating hook: ");
	}
	this->hookFunc = hookFunc;
	auto registersPtr = reinterpret_cast<DWORD>(regs.getBase());
	CopyMemory(this->code + sizeof(REGISTER_INIT_CODE) - 1, pHook, 5);
	CopyMemory(this->originalCode, pHook, 5);
	CopyMemory(this->code, REGISTER_INIT_CODE, sizeof(REGISTER_INIT_CODE) - 1);

	*reinterpret_cast<DWORD*>(this->code + 2) = registersPtr; // 修改reg ptr
	for (size_t i = 0; i < 7; i++)
	{
		*reinterpret_cast<DWORD*>(this->code + 2 + 6 + 6 * i) = registersPtr + 4 + 4 * i; // 修改reg ptr
	}
	*reinterpret_cast<DWORD*>(this->code + 49) = reinterpret_cast<DWORD>(&regs);
	*reinterpret_cast<DWORD*>(this->code + 54) = reinterpret_cast<DWORD>(this->hookFunc);


	// jmp hookPtr + 5
	this->code[5 + sizeof(REGISTER_INIT_CODE) - 1] = '\xe9';
	*reinterpret_cast<DWORD*>(this->code + 5 + sizeof(REGISTER_INIT_CODE)) =
		hookPtr + 5 - reinterpret_cast<DWORD>(this->code + 5 + sizeof(REGISTER_INIT_CODE) + 5 - 1);

	// hookPtr处 jmp hookPoint
	writeMemory<BYTE>(0xe9, hookPtr);
	writeMemory<DWORD>(reinterpret_cast<DWORD>(this->code) - hookPtr - 5, hookPtr + 1);
}

const Hook& Hook::addHook(DWORD hookPtr, HookFuncType hookFunc)
{
	auto hook = new Hook(hookPtr, hookFunc);
	hooks.push_back(hook);
	return *hook;
}

void Hook::disableHooks()
{
	for (auto hook : hooks)
	{
		delete hook;
	}
	hooks.clear();
}

Hook::~Hook()
{
	CopyMemory(this->pHook, this->originalCode, 5);
	VirtualFree(code, 0, MEM_RELEASE);
}

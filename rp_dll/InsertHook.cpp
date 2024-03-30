#include "pch.h"
#include "InsertHook.h"

inline DWORD getJmpVal(void* pTo, void* pFrom)
{
	return reinterpret_cast<DWORD>(pTo) - reinterpret_cast<DWORD>(pFrom) - 5;
}


bool InsertHook::hookFunc(BYTE* stackTopPtr)
{
	registers = Registers(stackTopPtr);
	auto ret = hookFunctor(registers, getOriginalFuncPtr());
	if (ret.has_value())
	{
		registers.eax() = *ret;
		return false;
	}
	return true;
}

InsertHook::InsertHook(void* pInsert, size_t replacedSize, WORD popStackNum, std::function<ReplaceHookFunc> hookFunc)
	: pInsert(pInsert), replacedSize(replacedSize), hookFunctor(std::move(hookFunc))
{

	// beforeCode赋值
	beforeCode = ExecutableUniquePtr<char>(sizeof(INIT_CODE) - 1);
	CopyMemory(beforeCode.get(), INIT_CODE, sizeof(INIT_CODE) - 1);
	*reinterpret_cast<DWORD*>(&beforeCode[2]) = reinterpret_cast<DWORD>(this);
	*reinterpret_cast<DWORD*>(&beforeCode[7]) = reinterpret_cast<DWORD>(&hookStub);

	// originalCode赋值
	originalCode = ExecutableUniquePtr<char>(replacedSize + 5);
	CopyMemory(originalCode.get(), pInsert, replacedSize);
	originalCode[replacedSize] = '\xe9'; // jmp pInsert + replacedSize
	*reinterpret_cast<DWORD*>(&originalCode[replacedSize + 1])
		= getJmpVal(static_cast<BYTE*>(pInsert) + replacedSize, originalCode.get() + replacedSize);

	// afterCode赋值
	this->afterCode = ExecutableUniquePtr<char>(replacedSize + sizeof(AFTER_CODE) - 1);
	afterCode[0] = '\x9d'; // popfd
	afterCode[1] = '\x61'; // popad
	CopyMemory(&afterCode[2], pInsert, replacedSize);
	afterCode[replacedSize + 2] = '\xe9'; // jmp originalCode
	*reinterpret_cast<DWORD*>(&afterCode[replacedSize + 3]) =
		getJmpVal(static_cast<BYTE*>(pInsert) + replacedSize, this->afterCode.get() + replacedSize + 2);

	// returnCode赋值
	returnCode = ExecutableUniquePtr<char>(sizeof(RETURN_CODE) - 1);
	CopyMemory(returnCode.get(), RETURN_CODE, sizeof(RETURN_CODE) - 1);
	if (popStackNum == 0)
	{
		returnCode[2] = '\xc3';
	}
	else
	{
		*reinterpret_cast<WORD*>(&returnCode[3]) = popStackNum; // ret num
	}

	// 注入
	auto injectCode = std::make_unique<char[]>(replacedSize);
	injectCode[0] = '\xe9';
	 // jmp originalCode
	for (size_t i = 5; i < replacedSize; ++i)
	{
		injectCode[i] = '\x90'; // nop
	}
	*reinterpret_cast<DWORD*>(&injectCode[1]) = getJmpVal(beforeCode.get(), pInsert);
	CopyMemory(pInsert, injectCode.get(), replacedSize);
}

InsertHook::~InsertHook()
{
	CopyMemory(pInsert, originalCode.get(), replacedSize);
}

const InsertHook& InsertHook::addReplace(void* pInsert, size_t replacedSize, std::function<ReplaceHookFunc> hookFunc, WORD popStackNum)
{
	auto pHook = new InsertHook(pInsert, replacedSize, popStackNum, std::move(hookFunc));
	hooks.push_back(pHook);
	return *pHook;
}

const InsertHook& InsertHook::addInsert(void* pInsert, size_t replacedSize, std::function<InsertHookFunc> hookFunc)
{
	auto pHook = new InsertHook(pInsert, replacedSize, 0, 
		[hookFunc = std::move(hookFunc)](const Registers& reg, void* rawFuncPtr) -> std::optional<int>
	{
		hookFunc(reg);
		return {};
	});
	hooks.push_back(pHook);
	return *pHook;
}

void InsertHook::deleteAll()
{
	for (auto it : hooks)
	{
		delete it;
	}
	hooks.clear();
}

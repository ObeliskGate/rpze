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

InsertHook::InsertHook(void* pInsert, size_t replacedSize, BYTE popStackNum, std::function<ReplaceHookFunc> hookFunc)
	: pInsert(pInsert), replacedSize(replacedSize), hookFunctor(std::move(hookFunc)) , popStackNum(popStackNum)
{

	// beforeCode��ֵ
	beforeCode = VirtualUniquePtr<char>(sizeof(INIT_CODE) - 1);
	CopyMemory(beforeCode.get(), INIT_CODE, sizeof(INIT_CODE) - 1);
	*reinterpret_cast<DWORD*>(beforeCode.get() + 2) = reinterpret_cast<DWORD>(this);
	*reinterpret_cast<DWORD*>(beforeCode.get() + 7) = reinterpret_cast<DWORD>(&hookStub);

	// originalCode��ֵ
	originalCode = VirtualUniquePtr<char>(replacedSize + 5);
	CopyMemory(originalCode.get(), pInsert, replacedSize);
	originalCode[replacedSize] = '\xe9'; // jmp pInsert + replacedSize
	*reinterpret_cast<DWORD*>(originalCode.get() + replacedSize + 1)
		= getJmpVal(static_cast<BYTE*>(pInsert) + replacedSize, originalCode.get() + replacedSize);

	// afterCode��ֵ
	this->afterCode = VirtualUniquePtr<char>(replacedSize + sizeof(AFTER_CODE) - 1);
	afterCode[0] = '\x9d'; // popfd
	afterCode[1] = '\x61'; // popad
	CopyMemory(this->afterCode.get() + 2, pInsert, replacedSize);
	afterCode[replacedSize + 2] = '\xe9'; // jmp originalCode
	*reinterpret_cast<DWORD*>(this->afterCode.get() + replacedSize + 3) =
		getJmpVal(static_cast<BYTE*>(pInsert) + replacedSize, this->afterCode.get() + replacedSize + 2);

	// returnCode��ֵ
	returnCode = VirtualUniquePtr<char>(sizeof(RETURN_CODE) - 1);
	CopyMemory(returnCode.get(), RETURN_CODE, sizeof(RETURN_CODE) - 1);
	if (popStackNum == 0)
	{
		returnCode[2] = '\xc3';
	}
	else
	{
		returnCode[3] = popStackNum;
	}

	// ע��
	char* injectCode = new char[replacedSize];
	injectCode[0] = '\xe9';
	 // jmp originalCode
	for (size_t i = 5; i < replacedSize; ++i)
	{
		injectCode[i] = '\x90'; // nop
	}
	*reinterpret_cast<DWORD*>(injectCode + 1) = getJmpVal(beforeCode.get(), pInsert);
	CopyMemory(pInsert, injectCode, replacedSize);
	delete[] injectCode;
}

InsertHook::~InsertHook()
{
	CopyMemory(pInsert, originalCode.get(), replacedSize);
}

const InsertHook& InsertHook::addReplace(void* pInsert, size_t replacedSize, std::function<ReplaceHookFunc> hookFunc, BYTE popStackNum)
{
	auto pHook = new InsertHook(pInsert, replacedSize, popStackNum, std::move(hookFunc));
	hooks.push_back(pHook);
	return *pHook;
}

const InsertHook& InsertHook::addInsert(void* pInsert, size_t replacedSize, std::function<InsertHookFunc> hookFunc)
{
	auto pHook = new InsertHook(pInsert, replacedSize, 0, 
		[hookFunc = std::move(hookFunc)](const Registers& registers, void* rawFuncPtr) -> std::optional<int>
	{
		hookFunc(registers);
		return std::nullopt;
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

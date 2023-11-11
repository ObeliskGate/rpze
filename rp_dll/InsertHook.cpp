#include "pch.h"
#include "InsertHook.h"

inline DWORD getJmpVal(void* pTo, void* pFrom)
{
	return reinterpret_cast<DWORD>(pTo) - reinterpret_cast<DWORD>(pFrom) - 5;
}


bool InsertHook::hookFunc(DWORD stackTopPtr)
{
	std::cout << std::hex << reinterpret_cast<DWORD>(this) << std::endl;
	std::cout << std::hex << reinterpret_cast<DWORD>(this->afterCode.get()) << std::endl;
	CopyMemory(registers.getBase(), reinterpret_cast<void*>(stackTopPtr + REGISTERS_SIZE), REGISTERS_SIZE);
	return hookFunctor(registers);
}

InsertHook::InsertHook(void* pInsert, size_t replacedSize, DWORD popStackNum, std::function<ReplaceHookFunc> hookFunc)
	: pInsert(pInsert), replacedSize(replacedSize), popStackNum(popStackNum) , hookFunctor(std::move(hookFunc))
{

	// originalCode¸³Öµ
	originalCode = VirtualUniquePtr<char>(replacedSize + sizeof(INIT_CODE) - 1);
	CopyMemory(originalCode.get(), pInsert, replacedSize);
	CopyMemory(originalCode.get() + replacedSize, INIT_CODE, sizeof(INIT_CODE) - 1);
	*reinterpret_cast<DWORD*>(originalCode.get() + replacedSize + 2) = reinterpret_cast<DWORD>(this);
	*reinterpret_cast<DWORD*>(originalCode.get() + replacedSize + 7) = reinterpret_cast<DWORD>(&hookStub);



	// afterCode¸³Öµ
	this->afterCode = VirtualUniquePtr<char>(sizeof(END_CODE) - 1);
	CopyMemory(this->afterCode.get(), END_CODE, sizeof(END_CODE) - 1);
	*reinterpret_cast<DWORD*>(this->afterCode.get() + 3) =
		getJmpVal(static_cast<BYTE*>(pInsert) + replacedSize, this->afterCode.get() + 2);

	// ×¢Èë
	char* injectCode = new char[replacedSize];
	injectCode[0] = '\xe9';
	 // jmp originalCode
	for (size_t i = 5; i < replacedSize; ++i)
	{
		injectCode[i] = '\x90'; // nop
	}
	*reinterpret_cast<DWORD*>(injectCode + 1) = getJmpVal(originalCode.get(), pInsert);
	CopyMemory(pInsert, injectCode, replacedSize);
	delete injectCode;
}

InsertHook::~InsertHook()
{
	CopyMemory(pInsert, originalCode.get(), replacedSize);
}

const InsertHook& InsertHook::addReplace(void* pInsert, size_t replacedSize, std::function<ReplaceHookFunc> hookFunc, DWORD popStackNum)
{
	auto pHook = new InsertHook(pInsert, replacedSize, popStackNum, std::move(hookFunc));
	hooks.push_back(pHook);
	return *pHook;
}

const InsertHook& InsertHook::addInsert(void* pInsert, size_t replacedSize, std::function<InsertHookFunc> hookFunc)
{
	auto pHook = new InsertHook(pInsert, replacedSize, 0, [hookFunc = std::move(hookFunc)](Registers& registers) -> bool
	{
		hookFunc(registers);
		return true;
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

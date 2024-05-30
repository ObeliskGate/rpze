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

void InsertHook::setOriginalCode()
{
	originalCode = ExecutableUniquePtr<char>(replacedSize + 5);
	CopyMemory(originalCode.get(), pInsert, replacedSize);
	originalCode[replacedSize] = '\xe9'; // jmp pInsert + replacedSize
	*reinterpret_cast<DWORD*>(&originalCode[replacedSize + 1])
		= getJmpVal(static_cast<BYTE*>(pInsert) + replacedSize, originalCode.get() + replacedSize);

	// 特判jmp call等hook点
	DWORD toSetIdx;

	switch (replacedSize)
	{
	case 5:
		if (static_cast<unsigned char>(originalCode[0]) == 0xe9 || // jmp
			static_cast<unsigned char>(originalCode[0]) == 0xe8) // call
		{
			toSetIdx = 1;
			break;
		}
		return;
	case 6:
		if (static_cast<unsigned char>(originalCode[0] == 0x0f))
		{
			auto t = static_cast<unsigned char>(originalCode[1]);
			if (t <= 0x8f && t >= 0x80)
			{
				toSetIdx = 2;
				break;
			}
		}
	default:
		return;
	}
	auto toJmp = reinterpret_cast<DWORD>(pInsert) + toSetIdx + 4 + *reinterpret_cast<DWORD*>(&originalCode[toSetIdx]);
	*reinterpret_cast<DWORD*>(&originalCode[toSetIdx]) = toJmp - (reinterpret_cast<DWORD>(&originalCode[toSetIdx]) + 4);
}

InsertHook::InsertHook(
	void* pInsert, 
	size_t replacedSize, 
	WORD popStackNum, 
	std::function<ReplaceHookFunc> hookFunc)
	: pInsert(pInsert), replacedSize(replacedSize), hookFunctor(std::move(hookFunc))
{
	// 执行流程 beforeCode -> hookStub -> (afterCode -> originalCode)或returnCode
	// beforeCode赋值
	beforeCode = ExecutableUniquePtr<char>(sizeof(INIT_CODE) - 1);
	CopyMemory(beforeCode.get(), INIT_CODE, sizeof(INIT_CODE) - 1);
	*reinterpret_cast<DWORD*>(&beforeCode[2]) = reinterpret_cast<DWORD>(this);
	*reinterpret_cast<DWORD*>(&beforeCode[7]) = reinterpret_cast<DWORD>(&hookStub);

	replacedCode = std::make_unique<char[]>(10);
	CopyMemory(replacedCode.get(), pInsert, replacedSize);

	// originalCode赋值
	setOriginalCode();

	// afterCode赋值 
	this->afterCode = ExecutableUniquePtr<char>(sizeof(AFTER_CODE) - 1);
	CopyMemory(afterCode.get(), AFTER_CODE, sizeof(AFTER_CODE) - 1);
	*reinterpret_cast<DWORD*>(&afterCode[3]) = getJmpVal(
		originalCode.get(), this->afterCode.get() + 2);

	// returnCode赋值
	returnCode = ExecutableUniquePtr<char>(sizeof(RETURN_CODE) - 1);
	CopyMemory(returnCode.get(), RETURN_CODE, sizeof(RETURN_CODE) - 1);
	if (popStackNum == 0)
		returnCode[2] = '\xc3';
	else
		*reinterpret_cast<WORD*>(&returnCode[3]) = popStackNum; // ret num
	

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
	CopyMemory(pInsert, replacedCode.get(), replacedSize);
}

const InsertHook& InsertHook::addReplace(
	void* pInsert, 
	size_t replacedSize, 
	const std::function<ReplaceHookFunc>& hookFunc, 
	WORD popStackNum)
{
	auto pHook = new InsertHook(pInsert, replacedSize, popStackNum, hookFunc);
	hooks.push_back(pHook);
	return *pHook;
}

const InsertHook& InsertHook::addInsert(
	void* pInsert, 
	size_t replacedSize, 
	const std::function<InsertHookFunc>& hookFunc)
{
	auto pHook = new InsertHook(pInsert, replacedSize, 0, 
		[hookFunc](Registers& reg, void*) -> std::optional<int>
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

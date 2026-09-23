#pragma once
#include "stdafx.h"

class HeapWrapper
{
	HANDLE hHeap;

public:
	HANDLE heap() const { return hHeap; }
	explicit HeapWrapper(DWORD flOptions);
	~HeapWrapper() { HeapDestroy(hHeap); }
	void* alloc(size_t size, bool zeroMemory = false);
	void* realloc(void* p, size_t size, bool zeroMemory = false);
	void free(void* p);
};

#pragma pack(push, 1)
struct HookContext
{
	DWORD addr;
	DWORD efl;
	DWORD edi;
	DWORD esi;
	DWORD ebp;
	DWORD esp;
	DWORD ebx;
	DWORD edx;
	DWORD ecx;
	DWORD eax;
	DWORD eip;

	HookContext() = delete;
};
#pragma pack(pop)

namespace rpdetail
{
	template <typename T>
	struct is_optional_unsigned_integral : std::false_type {};


	template <std::unsigned_integral Val>
	struct is_optional_unsigned_integral<std::optional<Val>> : std::true_type {};
};

template<typename T>
concept optional_unsigned_integral = rpdetail::is_optional_unsigned_integral<T>::value;

class InsertHook
{
public:
	using CallBack = void(HookContext&);

	template <typename T>
	static void addInsert(void* addr, T&& callback);

	template <std::invocable<HookContext&> T>
	requires optional_unsigned_integral<std::invoke_result_t<T, HookContext&>>
	static void addReplace(void* addr, void* pEip, T&& callback);

	template <std::invocable<HookContext&> T>
	requires std::same_as<std::remove_cvref_t<std::invoke_result_t<T, HookContext&>>, std::optional<uint32_t>>
	static void addFloatReplace(void* addr, void* pEip, T&& callback);

	static void deleteAt(void* addr);

	static void deleteAll() { hooks.clear(); }

	~InsertHook();

private:
#pragma pack(push, 1)
	struct HookCode
	{
		uint8_t pushRet = 0x68;  // push retAddr
		uintptr_t retAddr = 0x0;
		uint8_t pushad = 0x60;  // pushad
		uint8_t pushfd = 0x9c;  // pushfd
		uint8_t addEspPlus10_4[5] =  // add [esp+0x10], 4
			{0x83, 0x44, 0x24, 0x10, 0x04};
		uint8_t pushOri = 0x68;  // push oriAddr
		uintptr_t oriAddr = 0x0;
		uint8_t movEcxThis = 0xb9;  // mov ecx, this
		uintptr_t thisPtr = 0;
		uint8_t movEdxEsp[2] = {0x8b, 0xd4};  // mov edx, esp
		uint8_t call = 0xe8;  // call callAddr
		uintptr_t callAddr = 0x0;
		uint8_t addEsp4[3] = {0x83, 0xc4, 0x4};  // add esp, 4

		uint8_t popfd = 0x9d;  // popfd
		uint8_t popad = 0x61;  // popad
		uint8_t ret = 0xc3;  // ret
	};

	struct FloatHookFrame
	{
		HookContext context;
		uint32_t valueBits;
		uint32_t hasValue;
	};

	struct FloatHookCode
	{
		uint8_t leaEspMinus8[4] = {0x8d, 0x64, 0x24, 0xf8};
		uint8_t pushRet = 0x68;
		uintptr_t retAddr = 0;
		uint8_t pushad = 0x60;
		uint8_t pushfd = 0x9c;
		uint8_t addEspPlus10_12[5] = {0x83, 0x44, 0x24, 0x10, 0x0c};
		uint8_t pushOri = 0x68;
		uintptr_t oriAddr = 0;
		uint8_t movEbxEsp[2] = {0x8b, 0xdc};
		uint8_t movEcxThis = 0xb9;
		uintptr_t thisPtr = 0;
		uint8_t movEdxEbx[2] = {0x8b, 0xd3};
		uint8_t andEspMinus16[3] = {0x83, 0xe4, 0xf0};
		uint8_t call = 0xe8;
		uintptr_t callAddr = 0;
		uint8_t movEspEbx[2] = {0x8b, 0xe3};
		uint8_t cmpHasValue[5] = {0x83, 0x7c, 0x24, 0x30, 0x00};
		uint8_t jzSkipFld[2] = {0x74, 0x04};
		uint8_t fldValue[4] = {0xd9, 0x44, 0x24, 0x2c};
		uint8_t addEsp4[3] = {0x83, 0xc4, 0x04};
		uint8_t popfd = 0x9d;
		uint8_t popad = 0x61;
		uint8_t ret8[3] = {0xc2, 0x08, 0x00};
	};
#pragma pack(pop)

	static_assert(offsetof(HookContext, eip) == 40);
	static_assert(sizeof(HookContext) == 44);
	static_assert(offsetof(FloatHookFrame, context) == 0);
	static_assert(offsetof(FloatHookFrame, valueBits) == 44);
	static_assert(offsetof(FloatHookFrame, hasValue) == 48);
	static_assert(sizeof(FloatHookFrame) == 52);
	static_assert(sizeof(FloatHookCode) == 59);
	enum class StubKind
	{
		Standard,
		FloatBits
	};

	inline static auto executableHeap = HeapWrapper(HEAP_CREATE_ENABLE_EXECUTE);

	static void __fastcall callBackFunc(InsertHook* this_, HookContext* context);

	std::move_only_function<CallBack> callFunc;

	void* addr;

	void* hookCode;

	void* pTrampoline = nullptr;

	inline static std::unordered_map<void*, InsertHook> hooks = {};

public:
	template <std::convertible_to<std::move_only_function<CallBack>> T>
	InsertHook(void* addr_, T&& callback, StubKind stubKind = StubKind::Standard)
		: callFunc(std::forward<T>(callback)), addr(addr_),
			hookCode(executableHeap.alloc(stubKind == StubKind::FloatBits
			? sizeof(FloatHookCode) : sizeof(HookCode)))
	{
	#ifndef NDEBUG
		std::println("generating hook at {}", addr_);
	#endif
		if (stubKind == StubKind::Standard)
		{
			auto* code = new (hookCode) HookCode();
			code->callAddr = reinterpret_cast<DWORD>(&InsertHook::callBackFunc)
				- reinterpret_cast<DWORD>(&code->addEsp4[0]);
			code->oriAddr = reinterpret_cast<DWORD>(addr);
			code->thisPtr = reinterpret_cast<DWORD>(this);
		}
		else
		{
			auto* code = new (hookCode) FloatHookCode();
			code->callAddr = reinterpret_cast<DWORD>(&InsertHook::callBackFunc)
				- (reinterpret_cast<DWORD>(&code->callAddr) + sizeof(code->callAddr));
			code->oriAddr = reinterpret_cast<DWORD>(addr);
			code->thisPtr = reinterpret_cast<DWORD>(this);
		}

		const auto createStatus = MH_CreateHook(addr, hookCode, &pTrampoline);
		if (createStatus != MH_OK)
			throw std::runtime_error(
				std::format("MH_CreateHook failed (status {}): {}",
					static_cast<int>(createStatus), addr));

		if (stubKind == StubKind::Standard)
			reinterpret_cast<HookCode*>(hookCode)->retAddr = reinterpret_cast<DWORD>(pTrampoline);
		else
			reinterpret_cast<FloatHookCode*>(hookCode)->retAddr = reinterpret_cast<DWORD>(pTrampoline);
		const auto enableStatus = MH_EnableHook(addr);
		if (enableStatus != MH_OK)
			throw std::runtime_error(
				std::format("MH_EnableHook failed (status {}): {}",
					static_cast<int>(enableStatus), addr));
	#ifndef NDEBUG
		std::println("hooked, trampoline: {}", pTrampoline);
	#endif
	}
private:
	template <typename T>
	static void addInsertWithKind(void* addr, T&& callback, StubKind stubKind);
};

template <typename T>
void InsertHook::addInsert(void* addr, T&& callback)
{
	addInsertWithKind(addr, std::forward<T>(callback), StubKind::Standard);
}

template <typename T>
void InsertHook::addInsertWithKind(void* addr, T&& callback, StubKind stubKind)
{
	auto [_, success] = hooks.try_emplace(addr, addr, std::forward<T>(callback), stubKind);
	static_assert(std::same_as<decltype(success), bool>);
	if (!success)
		throw std::runtime_error("hook already exists");
}

template <std::invocable<HookContext&> T>
requires optional_unsigned_integral<std::invoke_result_t<T, HookContext&>>
void InsertHook::addReplace(void* addr, void* pEip, T&& callback)
{
	InsertHook::addInsert(addr, [cb = std::forward<T>(callback), pEip](HookContext& context)
		{
			auto ret = cb(context);
			if (ret.has_value())
			{
				context.eax = static_cast<uint32_t>(*ret);
				context.eip = reinterpret_cast<DWORD>(pEip);
			}
	});
}

template <std::invocable<HookContext&> T>
requires std::same_as<std::remove_cvref_t<std::invoke_result_t<T, HookContext&>>, std::optional<uint32_t>>
void InsertHook::addFloatReplace(void* addr, void* pEip, T&& callback)
{
	addInsertWithKind(addr,
		[cb = std::forward<T>(callback), pEip](HookContext& context)
		{
			auto& frame = *reinterpret_cast<FloatHookFrame*>(&context);
			frame.hasValue = 0;
			auto ret = cb(context);
			if (ret.has_value())
			{
				frame.valueBits = static_cast<uint32_t>(*ret);
				context.eip = reinterpret_cast<DWORD>(pEip);
				frame.hasValue = 1;
			}
		}, StubKind::FloatBits);
}

#pragma once
#include "stdafx.h"
#include <functional>
#include <memory>
#include <optional>
#include <concepts>
#include <print>
#include <unordered_map>
#include <MinHook.h>


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

template<typename T>
struct __is_optional_integral { static constexpr bool value = false; };

template<std::integral Val>
struct __is_optional_integral<std::optional<Val>> { static constexpr bool value = true; };

template<typename T>
concept optional_integral = __is_optional_integral<T>::value;

class InsertHook
{

public:
	using CallBack = void(HookContext&);

	template <typename T>
	static void addInsert(void* addr, T&& callback);

	template <std::invocable<HookContext&> T>
	requires optional_integral<std::invoke_result_t<T, HookContext&>>
	static void addReplace(void* addr, void* pEip, T&& callback);

	static void deleteAt(void* addr);

	static void deleteAll() { hooks.clear(); }

	~InsertHook();

private:
#pragma pack(push, 1)
	struct HookCode
	{
        uint8_t pushRet = 0x68;  // push retAddr
        DWORD retAddr = 0x0;
        uint8_t pushad = 0x60;  // pushad
        uint8_t pushfd = 0x9c;  // pushfd
        uint8_t addEspPlus10_4[5] =  // add [esp+0x10], 4
            {0x83, 0x44, 0x24, 0x10, 0x04};
        uint8_t pushOri = 0x68;  // push oriAddr
        DWORD oriAddr = 0x0;
		uint8_t movEcxThis = 0xb9;  // mov ecx, this
		DWORD thisPtr = 0;
		uint8_t movEdxEsp[2] = {0x8b, 0xd4};  // mov edx, esp
        // uint8_t pushEsp = 0x54;  // push esp
        uint8_t call = 0xe8;  // call callAddr
        DWORD callAddr = 0x0;
        uint8_t popEax = 0x58;  // pop eax
        uint8_t popfd = 0x9d;  // popfd
        uint8_t popad = 0x61;  // popad
        uint8_t ret = 0xc3;  // ret
	};
#pragma pack(pop)

	inline static auto executableHeap = HeapWrapper(HEAP_CREATE_ENABLE_EXECUTE);

	static void __fastcall callBackFunc(InsertHook* this_, HookContext* context);

	std::function<CallBack> callFunc;

	HookCode* hookCode;

	void* addr;

	void* pTrampoline = nullptr;

	inline static std::unordered_map<void*, std::unique_ptr<InsertHook>> hooks = {};

public:
	template <std::convertible_to<std::function<CallBack>> T>
	InsertHook(void* addr_, T&& callback)
		: callFunc(std::forward<T>(callback)), addr(addr_),  
	hookCode(new (executableHeap.alloc(sizeof(HookCode))) HookCode())
	{
	#ifndef NDEBUG
		std::println("generating hook at {}", addr_);
	#endif
		hookCode->callAddr = reinterpret_cast<DWORD>(&InsertHook::callBackFunc) 
			- reinterpret_cast<DWORD>(&hookCode->popEax);
		hookCode->oriAddr = reinterpret_cast<DWORD>(addr);
		hookCode->thisPtr = reinterpret_cast<DWORD>(this);

		if (MH_CreateHook(addr, hookCode, &pTrampoline) != MH_OK) 
			throw std::runtime_error(std::format("MH_CreateHook failed: {}", addr));
		

		if (MH_EnableHook(addr) != MH_OK) 
			throw std::runtime_error(std::format("MH_EmableHook failed: {}", addr));
		
		hookCode->retAddr = reinterpret_cast<DWORD>(pTrampoline);
	#ifndef NDEBUG
		std::println("hooked, trampoline: {}", pTrampoline);
	#endif
	}
};


template <typename T>
void InsertHook::addInsert(void* addr, T&& callback)
{
	auto it = hooks.find(addr);
	if (it != hooks.end())
		throw std::invalid_argument(std::format("hook already exists: {}", addr));
	
	hooks[addr] = std::make_unique<InsertHook>(addr, std::forward<T>(callback));
}

template <std::invocable<HookContext&> T>
requires optional_integral<std::invoke_result_t<T, HookContext&>>
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
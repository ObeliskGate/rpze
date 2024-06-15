#pragma once
#include "stdafx.h"
#include <functional>
#include <memory>
#include <new>
#include <optional>
#include <unordered_map>
#include <iostream>
#include <stdexcept>
#include <MinHook.h>
#include <winnt.h>


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

class InsertHook
{
public:
	using CallBack = std::function<void(HookContext&)>;

	using ReplaceFunc = std::function<std::optional<uint32_t>(HookContext&)>;

	template <typename T, typename Target = CallBack>
	using void_if_convertible = std::enable_if_t<std::is_convertible_v<std::remove_reference_t<T>, Target>>;

	template <typename T>
	static void_if_convertible<T> addInsert(void* addr, T&& callback);

	template <typename T>
	static void_if_convertible<T, ReplaceFunc> addReplace(void* addr, void* pEip, T&& callback);

	static void deleteAt(void* addr);

	static void deleteAll();
	
	template <typename T>
	InsertHook(void_if_convertible<T>* addr_, T&& callback);

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
	class HeapWrapper
	{
		HANDLE hHeap;
	public:
		HANDLE heap() const { return hHeap; }
		explicit HeapWrapper(DWORD flOptions) : hHeap(HeapCreate(flOptions, 0, 0))
		{
			if (hHeap == nullptr)
			{
				std::cerr << "HeapCreate failed" << std::endl;
				throw std::runtime_error("HeapCreate failed");
			}
		}
		~HeapWrapper() { HeapDestroy(hHeap); }
		void* alloc(size_t size, bool zero_memory = false) 
		{ 	
			auto ret = HeapAlloc(hHeap, zero_memory ? HEAP_ZERO_MEMORY : 0, size); 
			if (ret == nullptr) throw std::bad_alloc();
			return ret;
		}
		void realloc(void* p, size_t size, bool zero_memory = false)
		{
			auto ret = HeapReAlloc(hHeap, zero_memory ? HEAP_ZERO_MEMORY : 0, p, size);
			if (ret == nullptr) throw std::bad_alloc();
		}
		void free(void* p) { HeapFree(hHeap, 0, p); }
	};

	inline static auto __executableHeap = HeapWrapper(HEAP_CREATE_ENABLE_EXECUTE | HEAP_GENERATE_EXCEPTIONS);

#pragma pack(pop)
	static void __fastcall callBackFunc(InsertHook* this_, HookContext* context);

	CallBack callFunc;

	HookCode* hookCode;

	void* addr;

	void* pTrampoline = nullptr;

	inline static std::unordered_map<void*, std::unique_ptr<InsertHook>> hooks = {};
};

template <typename T>
InsertHook::InsertHook(void_if_convertible<T>* addr_, T&& callback)
	: callFunc(std::forward<T>(callback)), addr(addr_),  hookCode(new (__executableHeap.alloc(sizeof(HookCode))) HookCode())
{
#ifndef NDEBUG
	std::cout << "generating hook at " << addr_ << std::endl;
#endif
	hookCode->callAddr = reinterpret_cast<DWORD>(&InsertHook::callBackFunc) 
		- reinterpret_cast<DWORD>(&hookCode->popEax);
	hookCode->oriAddr = reinterpret_cast<DWORD>(addr);
	hookCode->thisPtr = reinterpret_cast<DWORD>(this);

	if (MH_CreateHook(addr, hookCode, &pTrampoline) != MH_OK) {
		std::cerr << "MH_CreateHook failed, addr: " << addr << std::endl;
		throw std::runtime_error("MH_CreateHook failed");
	}

	if (MH_EnableHook(addr) != MH_OK) {
		std::cerr << "MH_EnableHook failed, addr: " << addr << std::endl;
		throw std::runtime_error("MH_EnableHook failed");
	}
	hookCode->retAddr = reinterpret_cast<DWORD>(pTrampoline);
#ifndef NDEBUG
	std::cout << "hooked  " << pTrampoline <<  std::endl;
#endif
}

template <typename T>
InsertHook::void_if_convertible<T> InsertHook::addInsert(void* addr, T&& callback)
{
	auto it = hooks.find(addr);
	if (it != hooks.end())
	{
		std::cerr << "hook already exists, addr: " << addr << std::endl;
		throw std::runtime_error("hook already exists");
	}
	hooks[addr] = std::make_unique<InsertHook>(addr, std::forward<T>(callback));
}

template <typename T>
InsertHook::void_if_convertible<T, InsertHook::ReplaceFunc> 
	InsertHook::addReplace(void* addr, void* pEip, T&& callback)
{
	InsertHook::addInsert(addr, [cb = std::forward<T>(callback), pEip](HookContext& context) {
		auto ret = cb(context);
		static_assert(std::is_same_v<decltype(ret), std::optional<uint32_t>>);
		if (ret.has_value())
		{
			context.eax = *ret;
			context.eip = reinterpret_cast<DWORD>(pEip);
		}	
	});
}
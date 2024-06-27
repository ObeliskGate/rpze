#include "InsertHook.h"
#include <print>
#include <stdexcept>

void InsertHook::callBackFunc(InsertHook* this_, HookContext* hookContext)
{
    this_->callFunc(*hookContext);
}

InsertHook::~InsertHook()
{
    if (MH_DisableHook(addr) != MH_OK)
    {
        std::println(std::cerr, "failed to disable hook at {}", addr);
    }
    if (MH_RemoveHook(addr) != MH_OK)
    {
        std::println(std::cerr, "failed to remove hook at {}", addr);
    }
#ifndef NDEBUG
    std::println("hook removed at {}", addr);
#endif
    executableHeap.free(hookCode);
}

void InsertHook::deleteAt(void* addr)
{
    auto it = hooks.find(addr);
    if (it == hooks.end())
        return;
    hooks.erase(it);
}

HeapWrapper::HeapWrapper(DWORD flOptions)  : hHeap(HeapCreate(flOptions, 0, 0))
{
    if (hHeap == nullptr)
        throw std::runtime_error(std::format("HeapCreate failed, err {}", GetLastError()));
    
}

void* HeapWrapper::alloc(size_t size, bool zeroMemory)		
{ 	
    auto ret = HeapAlloc(hHeap, zeroMemory ? HEAP_ZERO_MEMORY : 0, size); 
    if (ret == nullptr) throw std::bad_alloc();
    return ret;
}

void* HeapWrapper::realloc(void* p, size_t size, bool zeroMemory)		
{
    auto ret = HeapReAlloc(hHeap, zeroMemory ? HEAP_ZERO_MEMORY : 0, p, size);
    if (ret == nullptr) throw std::bad_alloc();
    return ret;
}

void HeapWrapper::free(void* p)
{ 
    auto ret = HeapFree(hHeap, 0, p); 
    if (!ret)
        throw std::runtime_error(std::format("HeapFree failed, err {}", GetLastError()));
    
}
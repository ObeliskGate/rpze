#include "InsertHook.h"
#include <stdexcept>

void InsertHook::callBackFunc(InsertHook* this_, HookContext* hookContext)
{
    this_->callFunc(*hookContext);
}

InsertHook::~InsertHook()
{
    if (MH_DisableHook(addr) != MH_OK)
    {
        std::cerr << "unexpected behavior: failed to disable hook" << std::endl;
    }
    if (MH_RemoveHook(addr) != MH_OK)
    {
        std::cerr << "unexpected behavior: failed to remove hook" << std::endl;
    }
#ifndef NDEBUG
    std::cout << "hook removed at " << addr << std::endl;
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

void InsertHook::deleteAll()
{
    hooks.clear();
}

HeapWrapper::HeapWrapper(DWORD flOptions)  : hHeap(HeapCreate(flOptions, 0, 0))
{
    if (hHeap == nullptr)
    {
        std::cerr << "HeapCreate failed: " << GetLastError() << std::endl;
        throw std::runtime_error("HeapCreate failed");
    }
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
    {
        std::cerr << "HeapFree failed: " << GetLastError() << std::endl;
        throw std::runtime_error("HeapFree failed");
    }
}
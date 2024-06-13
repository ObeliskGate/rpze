#include "InsertHook.h"
#include "MinHook.h"

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
    __executableHeap.free(hookCode);
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
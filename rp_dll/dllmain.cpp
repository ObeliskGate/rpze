// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "rp_dll.h"
#include "SharedMemory.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        setConsole();
        auto s = SharedMemory::getInstance();
        injectScript(s);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        SharedMemory::deleteInstance();
        break;
    }
    return TRUE;
}


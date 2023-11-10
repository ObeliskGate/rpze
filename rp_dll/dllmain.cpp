// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "pch.h"
#include "rp_dll.h"
#include "Hook.h"
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
        SharedMemory::getInstance();
		Hook::addHook(0x452732, [](const Registers&)
        {
	         script(0, SharedMemory::getInstance());
        });
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        SharedMemory::deleteInstance();
        Hook::disableHooks();
        break;
    }
    return TRUE;
}


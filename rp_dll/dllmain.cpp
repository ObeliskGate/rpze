// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "rp_dll.h"
#include "InsertHook.h"
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
		InsertHook::addInsert(reinterpret_cast<void*>(0x45272b), 7, [](const Registers&)
	        {
				script(0, SharedMemory::getInstance());
	        });
        InsertHook::addReplace(reinterpret_cast<void*>(0x524a70), 7, [](const Registers& regs)
            {
                auto zombie = regs.eax();
				std::cout << "zombie: " << std::hex << zombie << std::endl;
				if (zombie && readMemory<int32_t>(zombie + 0x24) == 2)
				{
                    writeMemory(400, zombie + 0xc);
                    return false;
				}
                std::cout << "no zombie" << std::endl;
                return true;
            });
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        SharedMemory::deleteInstance();
        InsertHook::deleteAll();
        break;
    }
    return TRUE;
}


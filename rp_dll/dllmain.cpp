// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "rp_dll.h"
#include "InsertHook.h"
#include "SharedMemory.h"

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		init();
		SharedMemory::getInstance();
		InsertHook::addInsert(reinterpret_cast<void*>(0x45272b), 7,
          [](const Registers&) // main loop LawnApp::UpdateFrames 
          {
              script(0, SharedMemory::getInstance());
          });
		InsertHook::addReplace(reinterpret_cast<void*>(0x524a70), 7,
           [](const Registers& regs) // Zombie::PickRandomSpeed
           {
               auto zombie = regs.eax();
               // if (readMemory<int32_t>(zombie + 0x24) == 2)
               // {
               //     writeMemory(400, zombie + 0x8);
               //     return false;
               // }
               return true;
           });
		InsertHook::addInsert(reinterpret_cast<void*>(0x407b52), 5, [](const Registers& regs)
		{
			auto boardPtr = regs.eax();
			SharedMemory::getInstance()->getBoardPtr() = boardPtr;
			SharedMemory::getInstance()->isBoardPtrValid() = false;
		});
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		InsertHook::deleteAll();
		SharedMemory::deleteInstance();
		break;
	}
	return TRUE;
}

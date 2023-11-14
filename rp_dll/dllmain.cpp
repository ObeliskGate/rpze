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
			InsertHook::addInsert(reinterpret_cast<void*>(0x45272b), 7, [](const Registers&) // main loop LawnApp::UpdateFrames 
			{
				script(0, SharedMemory::getInstance());
			});

			// InsertHook::addReplace(reinterpret_cast<void*>(0x524a70), 7, 
			// 	[](const Registers&, void*) -> std::optional<int32_t> // Zombie::PickRandomSpeed
			// 	{
			// 		return 0;
			// 	});
			InsertHook::addInsert(reinterpret_cast<void*>(0x407b52), 5, [](const Registers& regs) // Board::Board
			{
				auto boardPtr = regs.eax();
				SharedMemory::getInstance()->boardPtr() = boardPtr;
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

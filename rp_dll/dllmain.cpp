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
				mainHook(0, SharedMemory::getInstance());
			});
			InsertHook::addInsert(reinterpret_cast<void*>(0x407b52), 5, 
			 	[](const Registers&) // Board::Board
			 	{
			 		SharedMemory::getInstance()->isBoardPtrValid() = false;
			 	});
			InsertHook::addReplace(reinterpret_cast<void*>(0x42B8B0), 9,
				[](const Registers&, void*) -> std::optional<int32_t> 
				{
					if (closableHook(SharedMemory::getInstance(), HookPosition::CHALLENGE_I_ZOMBIE_SCORE_BRAIN))
					{
						return {};
					}
					return 0;
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

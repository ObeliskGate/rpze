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
			auto pSharedMemory = SharedMemory::getInstance();
			InsertHook::addInsert(reinterpret_cast<void*>(0x45272b), 7, 
				[pSharedMemory](const Registers&) // main loop LawnApp::UpdateFrames 
				{
					static bool flag = false; // at the first time, we need to get the mutex
					if (!flag)
					{
						pSharedMemory->waitMutex();
						flag = true;
					}
					mainHook<0>(pSharedMemory);
				});
			InsertHook::addInsert(reinterpret_cast<void*>(0x407b52), 5, 
			 	[pSharedMemory](const Registers& reg) // Board::Board
			 	{
					pSharedMemory->isBoardPtrValid() = false;
					pSharedMemory->boardPtr() = *reinterpret_cast<uint32_t*>(reg.esp() + 8); // stack is (... pBoard rta -01) now
			 	});
			InsertHook::addReplace(reinterpret_cast<void*>(0x42B8B0), 9,
				[pSharedMemory](const Registers&, void*) -> std::optional<int32_t>
				{
					if (closableHook(pSharedMemory, HookPosition::CHALLENGE_I_ZOMBIE_SCORE_BRAIN))
						return {};
					return 0;
				});
			InsertHook::addReplace(reinterpret_cast<void*>(0x42A6C0), 6,
				[pSharedMemory](const Registers&, void*) -> std::optional<int32_t>
				{
					if (closableHook(pSharedMemory, HookPosition::CHALLENGE_I_ZOMBIE_PLACE_PLANTS))
						return {};
					return 0;
				}, 12);
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

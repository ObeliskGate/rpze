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
			InsertHook::addInsert(reinterpret_cast<void*>(0x452650),
				[pSharedMemory](const HookContext&)  // main loop LawnApp::UpdateFrames 
				{
					static bool flag = false; // at the first time, we need to get the mutex
					if (!flag)
					{
						pSharedMemory->waitMutex();
						flag = true;
					}
					mainHook<0>(pSharedMemory);
				});
			InsertHook::addInsert(reinterpret_cast<void*>(0x407b52), 
			 	[pSharedMemory](const HookContext& reg) // Board::Board
			 	{
					pSharedMemory->shm().isBoardPtrValid = false;
					pSharedMemory->shm().boardPtr = *reinterpret_cast<uint32_t*>(reg.esp + 8); // stack is (... pBoard rta -1) now	
			 	});
			InsertHook::addReplace(reinterpret_cast<void*>(0x42B8B0), reinterpret_cast<void*>(0x42b967),
				[pSharedMemory](const HookContext&) -> std::optional<uint32_t>
				{
					if (closableHook(pSharedMemory, HookPosition::CHALLENGE_I_ZOMBIE_SCORE_BRAIN))
						return {};
					return 0;
				});
			InsertHook::addReplace(reinterpret_cast<void*>(0x42A6C0), reinterpret_cast<void*>(0x42a889),
				[pSharedMemory](const HookContext&) -> std::optional<uint32_t>
				{
					if (closableHook(pSharedMemory, HookPosition::CHALLENGE_I_ZOMBIE_PLACE_PLANTS))
						return {};
					return 0;
				});

			InsertHook::addInsert(reinterpret_cast<void*>(0x5A4760), 
			[pSharedMemory](HookContext& reg)
				{
					pSharedMemory->shm().error = ShmError::CAUGHT_SEH;
					SharedMemory::deleteInstance();
				});
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		SharedMemory::deleteInstance();
		InsertHook::deleteAll();
		MH_Uninitialize();
		break;
	}
	return TRUE;
}

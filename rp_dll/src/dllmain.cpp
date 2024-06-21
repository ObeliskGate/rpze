#include "rp_dll.h"
#include "InsertHook.h"
#include "SharedMemory.h"
#include <stacktrace>

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
						initInThread(pSharedMemory);
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
					exit();
				});
			InsertHook::addInsert(reinterpret_cast<void*>(0x420150),
				[](HookContext& reg)
				{
					throw std::exception(std::to_string(std::stacktrace::current()).c_str());
				});
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		exit();
		break;
	}
	return TRUE;
}

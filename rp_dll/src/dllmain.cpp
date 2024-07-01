#include "rp_dll.h"
#include "InsertHook.h"
#include "SharedMemory.h"
#include "RpDllException.h"

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
			InsertHook::addInsert(reinterpret_cast<void*>(0x452650),
				[](const HookContext&)  // main loop LawnApp::UpdateFrames 
				{
					static bool flag = false; // at the first time, we need to get the mutex
					static auto pSharedMemory = SharedMemory::getInstance();
					if (!flag)
					{
						initInThread(pSharedMemory);
						flag = true;
						
					}
					mainHook<0>(pSharedMemory);
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

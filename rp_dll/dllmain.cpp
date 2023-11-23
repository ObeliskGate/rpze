// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "rp_dll.h"
#include "InsertHook.h"
#include "SharedMemory.h"

void eaxFunc(int32_t eax_, void* rawFunc)
{
	__asm {
		mov eax, eax_
		call rawFunc
	}
}

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
				auto pSharedMemory = SharedMemory::getInstance();
				pSharedMemory->gameTime() = readMemory<int32_t>(0x6a9ec0, { 0x768 , 0x556c }).value_or(INT32_MIN);
				pSharedMemory->boardPtr() = readMemory<DWORD>(0x6a9ec0, { 0x768 }).value_or(0);
				script(0, SharedMemory::getInstance());
			});

			InsertHook::addReplace(reinterpret_cast<void*>(0x524a70), 7, 
				[](const Registers& registers, void* rawPtr) -> std::optional<int32_t> // Zombie::PickRandomSpeed
				{
					auto pZombie = registers.eax();
					eaxFunc(pZombie, rawPtr);
					return 0;
				});
			 InsertHook::addInsert(reinterpret_cast<void*>(0x407b52), 5, 
			 	[](const Registers&) // Board::Board
			 	{
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

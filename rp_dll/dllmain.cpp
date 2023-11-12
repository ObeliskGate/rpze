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
			InsertHook::addInsert(reinterpret_cast<void*>(0x45272b), 7, [](const Registers&) // main loop LawnApp::UpdateFrames 
			{
				script(0, SharedMemory::getInstance());
			});

			//InsertHook::addReplace(reinterpret_cast<void*>(0x524a70), 7, [](const Registers& regs) // Zombie::PickRandomSpeed
			//{
			//	auto pSharedMemory = SharedMemory::getInstance();
			//	if (pSharedMemory->globalState() == GlobalState::NOT_CONNECTED) return true;
			//	pSharedMemory->hookPosition() = HookPosition::ZOMBIE_PICK_RANDOM_SPEED;
			//	auto zombie = static_cast<uint32_t>(regs.eax());
			//	*static_cast<volatile uint32_t*>(pSharedMemory->returnResult()) = zombie;
			//	auto& phaseCode = pSharedMemory->phaseCode() == PhaseCode::JUMP_FRAME ? pSharedMemory->jumpingPhaseCode() : pSharedMemory->phaseCode();
			//	auto& runState = pSharedMemory->phaseCode() == PhaseCode::JUMP_FRAME ? pSharedMemory->jumpingRunState() : pSharedMemory->runState();
			//	phaseCode = PhaseCode::WAIT;
			//	runState = RunState::OVER;
			//	doAsPhaseCode(phaseCode);
			//	return *static_cast<volatile bool*>(pSharedMemory->returnResult());
			//});
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

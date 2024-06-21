#include "stdafx.h"
#include "SharedMemory.h"
#include "rp_dll.h"
#include "InsertHook.h"

#include <cstdint>
#include <MinHook.h>
#include <exception>
#include <sstream>
#include <string.h>


#define __until(expr) do {} while (!(expr))

void init()
{
	DWORD tmp;
	VirtualProtect(reinterpret_cast<void*>(0x400000), 0x394000, PAGE_EXECUTE_READWRITE, &tmp);
	AllocConsole();
	FILE* _;
	freopen_s(&_, "CONOUT$", "w", stdout);
	freopen_s(&_, "CONOUT$", "w", stderr);
	freopen_s(&_, "CONIN$", "r", stdin);
	std::ios::sync_with_stdio();
	std::cout << "console set" << std::endl;
	auto p = SharedMemory::getInstance();
	MH_Initialize();
#ifndef NDEBUG
	std::cout << "debug mode, base ptr: " << (DWORD)p->getSharedMemoryPtr() << std::endl;
#endif
}

void doAsPhaseCode(volatile PhaseCode& phaseCode, const SharedMemory* pSharedMemory)
{
	while (true)
	{
		switch (phaseCode)
		{
		case PhaseCode::CONTINUE:
			return;
		case PhaseCode::WAIT:
			__until(phaseCode != PhaseCode::WAIT);
			continue;
		case PhaseCode::RUN_CODE:
			{
#ifndef NDEBUG
				std::cout << "start run code" << std::endl;
#endif
				auto p = pSharedMemory->shm().getAsmBuffer();
				__asm
				{
					mov edx, p
					call edx
				}
				pSharedMemory->shm().executeResult = ExecuteResult::SUCCESS;
				phaseCode = PhaseCode::WAIT;
#ifndef NDEBUG
				std::cout << "run code success" << std::endl;
#endif
				continue;
			}
		case PhaseCode::JUMP_FRAME:
			if (pSharedMemory->shm().syncMethod == SyncMethod::MUTEX &&
				pSharedMemory->shm().jumpingSyncMethod == SyncMethod::MUTEX)
				pSharedMemory->waitMutex();
			doWhenJmpFrame(phaseCode);
			if (pSharedMemory->shm().syncMethod == SyncMethod::MUTEX &&
				pSharedMemory->shm().jumpingSyncMethod == SyncMethod::MUTEX)
				pSharedMemory->releaseMutex();
#ifndef NDEBUG
			std::cout << "end jmp frame" << std::endl;
#endif

			continue;
		case PhaseCode::READ_MEMORY:
#ifndef NDEBUG
			std::cout << "read memory" << std::endl;
#endif
			pSharedMemory->readMemory();
			phaseCode = PhaseCode::WAIT;
#ifndef NDEBUG
			std::cout << "read memory success" << std::endl;
#endif
			continue;
		case PhaseCode::WRITE_MEMORY:
			pSharedMemory->writeMemory();
			phaseCode = PhaseCode::WAIT;
			continue;

		case PhaseCode::READ_MEMORY_PTR:
			{
#ifndef NDEBUG
				std::cout << "read memory ptr" << std::endl;
#endif
				*pSharedMemory->shm().getReadWriteBuffer<uint32_t>() = 
					reinterpret_cast<uint32_t>(&pSharedMemory->shm());
				pSharedMemory->shm().executeResult = ExecuteResult::SUCCESS;
				phaseCode = PhaseCode::WAIT;
				continue;
			}
		}
	}
}

void doWhenJmpFrame(volatile PhaseCode& phaseCode)
{
	auto pSharedMemory = SharedMemory::getInstance();
	while (phaseCode == PhaseCode::JUMP_FRAME)
	{
		mainHook<1>(pSharedMemory);
		__asm
			{
			mov edi, ds:[0x6a9ec0]
			inc dword ptr [edi + 0x838] // mjClock++
			mov esi, [edi + 0x768]
			mov edx, 0x41BAD0 // Board::ProcessDeleteQueue
			call edx
			mov ecx, esi
			mov edx, [esi]
			mov edx, [edx + 0x58] // Board::Update
			call edx
			mov esi, edi
			push dword ptr [esi + 0x820]
			mov edx, 0x445680 // EffectSystem::ProcessDeleteQueue
			call edx
			mov eax, esi
			mov edx, 0x4524F0 // LawnApp::CheckForGameEnd
			call edx
			}
		if (!(time(nullptr) % 5))
		{
			MSG msg;
			while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE))
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
	}
}

bool closableHook(const SharedMemory* pSharedMemory, HookPosition hook)
{
	if (pSharedMemory->shm().globalState == HookState::NOT_CONNECTED ||
		pSharedMemory->shm().hookStateArr[getHookIndex(hook)] == HookState::NOT_CONNECTED)
		return true;
	return false;
}

static void* pTrampoline = nullptr;
void __fastcall hookUpdateApp(DWORD lawnAppAddr)
{
	try 
	{
		__asm
		{
			mov ecx, lawnAppAddr
			mov eax, pTrampoline
			call eax
		}
	} 
	catch (const std::exception& e) 
	{
		std::stringstream ss;
		ss << "std::exception: " << e.what() << std::endl;
		auto& shm = SharedMemory::getInstance()->shm();
		auto str = ss.str();
		shm.error = ShmError::CAUGHT_STD_EXCEPTION;
		auto copySize = std::min(str.size(), Shm::BUFFER_SIZE - 1) + 1; // for \0
		std::copy_n(str.c_str(), copySize, const_cast<char*>(shm.getReadWriteBuffer<char>()));
 		exit();
		std::terminate();
	}
}

void initInThread(const SharedMemory* pSharedMemory)
{
	pSharedMemory->waitMutex();

	auto pUpdateApp = readMemory<void*>(0x6a9ec0, 0x0, 0x180).value();
	if (MH_CreateHook(pUpdateApp, 
			reinterpret_cast<void*>(&hookUpdateApp), &pTrampoline) != MH_OK)
	{
		std::cerr << "LawnApp::UpdateApp hook failed" << std::endl;
		return;
	}
	if (MH_EnableHook(pUpdateApp) != MH_OK)
	{
		std::cerr << "LawnApp::UpdateApp enable hook failed" << std::endl;
		return;
	}
}

void exit()
{
	SharedMemory::deleteInstance();
	InsertHook::deleteAll();
	MH_Uninitialize();
}

#undef __until

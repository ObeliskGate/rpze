#include "stdafx.h"
#include "SharedMemory.h"
#include "rp_dll.h"

#define __until(expr) do {} while (!(expr))

void init()
{
	DWORD tmp;
	VirtualProtect(reinterpret_cast<void*>(0x400000), 0x394000, PAGE_EXECUTE_READWRITE, &tmp);
	AllocConsole();
	FILE* _;
	freopen_s(&_, "CONOUT$", "w", stdout);
	freopen_s(&_, "CONIN$", "r", stdin);
	std::ios::sync_with_stdio();
	std::cout << "console set" << std::endl;
	SharedMemory::getInstance();
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
				auto p = pSharedMemory->getAsmPtr();
				__asm
				{
					mov edx, p
					call edx
				}
				pSharedMemory->executeResult() = ExecuteResult::SUCCESS;
				phaseCode = PhaseCode::WAIT;
				continue;
			}
		case PhaseCode::JUMP_FRAME:
			if (pSharedMemory->syncMethod() == SyncMethod::MUTEX &&
				pSharedMemory->jumpingSyncMethod() == SyncMethod::MUTEX)
				pSharedMemory->waitMutex();
			doWhenJmpFrame(phaseCode);
			if (pSharedMemory->syncMethod() == SyncMethod::MUTEX &&
				pSharedMemory->jumpingSyncMethod() == SyncMethod::MUTEX)
				pSharedMemory->releaseMutex();
#ifdef _DEBUG
			std::cout << "end jmp frame" << std::endl;
#endif

			continue;
		case PhaseCode::READ_MEMORY:
#ifdef _DEBUG	
			std::cout << "read memory" << std::endl;
#endif
			pSharedMemory->readMemory();
			phaseCode = PhaseCode::WAIT;
			continue;
		case PhaseCode::WRITE_MEMORY:
			pSharedMemory->writeMemory();
			phaseCode = PhaseCode::WAIT;
			continue;

		case PhaseCode::READ_MEMORY_PTR:
			{
				*static_cast<volatile uint32_t*>(pSharedMemory->getReadWriteVal()) = reinterpret_cast<uint32_t>(
					pSharedMemory->getSharedMemoryPtr());
				pSharedMemory->executeResult() = ExecuteResult::SUCCESS;
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
		mainHook<1>(pSharedMemory);
	}
}

bool closableHook(const SharedMemory* pSharedMemory, HookPosition hook)
{
	if (pSharedMemory->globalState() == HookState::NOT_CONNECTED ||
		pSharedMemory->hookStateArr()[getHookIndex(hook)] == HookState::NOT_CONNECTED)
		return true;
	return false;
}

#undef __until

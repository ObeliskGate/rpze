#include "pch.h"
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
		{
			doWhenJmpFrame(phaseCode);
			continue;
		}
		case PhaseCode::READ_MEMORY:
			pSharedMemory->readMemory();
			phaseCode = PhaseCode::WAIT;
			continue;
		case PhaseCode::WRITE_MEMORY:
			pSharedMemory->writeMemory();
			phaseCode = PhaseCode::WAIT;
			continue;

		case PhaseCode::READ_MEMORY_PTR:
		{
			*static_cast<volatile uint32_t*>(pSharedMemory->getReadWriteVal()) = reinterpret_cast<uint32_t>(pSharedMemory->getSharedMemoryPtr());
			pSharedMemory->executeResult() = ExecuteResult::SUCCESS;
			phaseCode = PhaseCode::WAIT;
			continue;
		}
		}
	}
}

void mainHook(const DWORD isInGame, const SharedMemory* pSharedMemory)
{
	pSharedMemory->boardPtr() = readMemory<DWORD>(0x6a9ec0, { 0x768 }).value_or(0);
	if (pSharedMemory->globalState() == HookState::NOT_CONNECTED || 
		pSharedMemory->hookStateArr()[getHookIndex(HookPosition::MAIN_LOOP)] == HookState::NOT_CONNECTED) return;
	volatile PhaseCode* pPhaseCode;
	volatile RunState* pRunState;
	if (isInGame)
	{
		if (pSharedMemory->phaseCode() != PhaseCode::JUMP_FRAME) return;
		pPhaseCode = &pSharedMemory->jumpingPhaseCode();
		pRunState = &pSharedMemory->jumpingRunState();
	}
	else
	{
		pPhaseCode = &pSharedMemory->phaseCode();
		pRunState = &pSharedMemory->runState();
	}
	*pPhaseCode = PhaseCode::WAIT;
	*pRunState = RunState::OVER;
	doAsPhaseCode(*pPhaseCode, pSharedMemory);
	*pRunState = RunState::RUNNING;
}

void doWhenJmpFrame(volatile PhaseCode& phaseCode)
{
	auto pSharedMemory = SharedMemory::getInstance();
	auto pLawnApp = *reinterpret_cast<BYTE**>(0x6a9ec0);
	auto pBoard = *reinterpret_cast<BYTE**>(pLawnApp + 0x768);
	if (!pBoard)
	{
		std::cout << "board ptr invalid, panic!!!" << std::endl;
		throw std::exception();
	}
	while (phaseCode == PhaseCode::JUMP_FRAME)
	{
		*reinterpret_cast<int32_t*>(pLawnApp + 0x838) += 1;  // mjClock++
		__asm
		{
			mov esi, pBoard
			mov edx, 0x41BAD0  // Board::ProcessDeleteQueue
			call edx
			mov ecx, esi
			mov edx, 0x415D40  // Board::Update
			call edx
			mov esi, pLawnApp
			mov eax, [esi + 0x820]
			push eax
			mov edx, 0x445680  // EffectSystem::ProcessDeleteQueue
			call edx
			mov eax, esi
			mov edx, 0x4524F0  // LawnApp::CheckForGameEnd
			call edx
		}
		if (!(time(nullptr) % 5))
		{
			MSG msg;
			while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
		mainHook(1, pSharedMemory);
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

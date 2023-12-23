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

void doAsPhaseCode(volatile PhaseCode& phaseCode)
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
			auto p = SharedMemory::getInstance()->getAsmPtr();
			__asm
			{
				mov edx, p
				call edx
			}
			SharedMemory::getInstance()->executeResult() = ExecuteResult::SUCCESS;
			phaseCode = PhaseCode::WAIT;
			continue;
		}
		case PhaseCode::JUMP_FRAME:
		{
			auto pSharedMemory = SharedMemory::getInstance();
			auto pBoard = pSharedMemory->boardPtr();
			auto pLawnApp = *reinterpret_cast<BYTE**>(0x6a9ec0);
			while (phaseCode == PhaseCode::JUMP_FRAME)
			{
				*reinterpret_cast<int32_t*>(pLawnApp + 0x838) += 1;  // mjClock++
				__asm
				{
					push esi
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
					pop esi
				}
				mainHook(1, pSharedMemory);
			}
			continue;
		}
		case PhaseCode::READ_MEMORY:
			SharedMemory::getInstance()->readMemory();
			phaseCode = PhaseCode::WAIT;
			continue;
		case PhaseCode::WRITE_MEMORY:
			SharedMemory::getInstance()->writeMemory();
			phaseCode = PhaseCode::WAIT;
			continue;

		case PhaseCode::READ_MEMORY_PTR:
		{
			auto s = SharedMemory::getInstance();
			*static_cast<volatile uint32_t*>(s->getReadResult()) = reinterpret_cast<uint32_t>(s->getSharedMemoryPtr());
			s->executeResult() = ExecuteResult::SUCCESS;
			phaseCode = PhaseCode::WAIT;
			continue;
		}
		}
	}
}

void mainHook(const DWORD isInGame, const SharedMemory* pSharedMemory)
{
	pSharedMemory->gameTime() = readMemory<int32_t>(0x6a9ec0, { 0x768 , 0x556c }).value_or(INT32_MIN);
	pSharedMemory->boardPtr() = readMemory<DWORD>(0x6a9ec0, { 0x768 }).value_or(0);
	if (pSharedMemory->globalState() == HookState::NOT_CONNECTED || 
		pSharedMemory->hookStateArr()[getHookIndex(HookPosition::MAIN_LOOP)] == HookState::NOT_CONNECTED) return;
	volatile PhaseCode* pPhaseCode = &pSharedMemory->phaseCode();
	volatile RunState* pRunState = &pSharedMemory->runState();
	if (isInGame)
	{
		if (pSharedMemory->phaseCode() != PhaseCode::JUMP_FRAME) return;
		pPhaseCode = &pSharedMemory->jumpingPhaseCode();
		pRunState = &pSharedMemory->jumpingRunState();
	}
	*pPhaseCode = PhaseCode::WAIT;
	*pRunState = RunState::OVER;
	doAsPhaseCode(*pPhaseCode);
	*pRunState = RunState::RUNNING;
}

bool closableHook(const SharedMemory* pSharedMemory, HookPosition hook)
{
	if (pSharedMemory->globalState() == HookState::NOT_CONNECTED ||
		pSharedMemory->hookStateArr()[getHookIndex(hook)] == HookState::NOT_CONNECTED)
		return true;
	return false;
}

#undef __until

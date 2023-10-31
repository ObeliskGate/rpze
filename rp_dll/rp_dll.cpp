#include "pch.h"
#include "SharedMemory.h"
#include "rp_dll.h"

#define __until(expr) do {} while (!(expr))

void setConsole()
{
	AllocConsole();
	FILE* _;
	freopen_s(&_, "CONOUT$", "w", stdout);
	freopen_s(&_, "CONIN$", "r", stdin);
	std::ios::sync_with_stdio();
	std::cout << "console set" << std::endl;
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
			SharedMemory::getInstance()->getExecuteResult() = ExecuteResult::SUCCESS;
			phaseCode = PhaseCode::WAIT;
			continue;
		}
		case PhaseCode::JUMP_FRAME:
		{
			auto pBoard = readMemory<DWORD>(0x6a9ec0, { 0x768 }).value_or(0);
			while (phaseCode == PhaseCode::JUMP_FRAME)
			{
				__asm
				{
					mov ecx, pBoard
					mov edx, 0x415D40 // Board::Update
					call edx
				}
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
			s->getExecuteResult() = ExecuteResult::SUCCESS;
			phaseCode = PhaseCode::WAIT;
			continue;
		}
		}
	}
}

void __stdcall script(const DWORD isInGame, const SharedMemory* pSharedMemory)
{
	if (pSharedMemory->getGlobalState() == GlobalState::NOT_CONNECTED) return;
	volatile PhaseCode* pPhaseCode = &pSharedMemory->getPhaseCode();
	RunState* pRunState = &pSharedMemory->getRunState();
	if (isInGame)
	{
		if (pSharedMemory->getPhaseCode() != PhaseCode::JUMP_FRAME) return;
		pPhaseCode = &pSharedMemory->getJumpingPhaseCode();
		pRunState = &pSharedMemory->getJumpingRunState();
	}
	*pPhaseCode = PhaseCode::WAIT;
	*pRunState = RunState::OVER;
	auto pBoard = readMemory<DWORD>(0x6a9ec0, { 0x768 });
	if (pBoard.has_value() && pBoard != 0)
	{
		pSharedMemory->getBoardPtr() = *pBoard;
		pSharedMemory->getGameTime() = readMemory<int32_t>(*pBoard + 0x556c ).value_or(INT32_MIN);
	}
	else
	{
		pSharedMemory->getBoardPtr() = 0;
		pSharedMemory->getGameTime() = INT32_MIN;
	}
	doAsPhaseCode(*pPhaseCode);
	*pRunState = RunState::RUNNING;
}

void injectScript(SharedMemory* pSharedMemory)
{

	DWORD tmp;
	VirtualProtect(reinterpret_cast<void*>(0x400000), 0x394000, PAGE_EXECUTE_READWRITE, &tmp);

	// in Board::UpdateGame
	//writeMemory<BYTE>(0x5f, 0x6b0000); // pop edi 
	//writeMemory<BYTE>(0x5e, 0x6b0001); // pop esi
	//writeMemory<BYTE>(0x5d, 0x6b0002); // pop ebp	
	//writeMemory<BYTE>(0x5b, 0x6b0003); // pop ebx
	//writeMemory<BYTE>(0x59, 0x6b0004); // pop ecx

	tmp = 0x6b0006;
	writeMemory<BYTE>(0x68, 0x6b0005);
	writeMemory<DWORD>(reinterpret_cast<DWORD>(pSharedMemory), 0x6b0006);
	tmp += 4; // push pSharedMemory

	writeMemory<BYTE>(0x68, tmp); tmp += 1;
	writeMemory<DWORD>(1, tmp);  tmp += 4; // push 1

	writeMemory<BYTE>(0xe8, tmp); tmp += 1;
	writeMemory<DWORD>(reinterpret_cast<DWORD>(&script) - tmp - 4, tmp);  tmp += 4;// call script

	//writeMemory<BYTE>(0xe9, tmp);  tmp += 1;
	//writeMemory<DWORD>(0x42b52b - tmp - 4, tmp); // jmp 42b52b
	writeMemory<BYTE>(0xc3, tmp); // RET

	// out of Board::UpdateGame
	tmp = 0x6b0100;
	writeMemory<BYTE>(0x68, tmp); tmp += 1;
	writeMemory<DWORD>(reinterpret_cast<DWORD>(pSharedMemory), tmp); tmp += 4; // push pSharedMemory

	writeMemory<BYTE>(0x68, tmp); tmp += 1;
	writeMemory<DWORD>(0, tmp);  tmp += 4; // push 0

	writeMemory<BYTE>(0xe8, tmp); tmp += 1;
	writeMemory<DWORD>(reinterpret_cast<DWORD>(&script) - tmp - 4, tmp);  tmp += 4;// call script

	writeMemory<BYTE>(0xc3, tmp); // RET

	// jmp in Board::UpdateGame
	writeMemory<BYTE>(0xe9, 0x415d3b);
	writeMemory<DWORD>(0x6b0005 - 0x415d3b - 5, 0x415d3c); // jmp 6b0005

	// jmp out of Board::UpdateGame
	writeMemory<BYTE>(0xe9, 0x452732);
	writeMemory<DWORD>(0x6b0100 - 0x452732 - 5, 0x452733); // jmp 6b0100
}

#undef __until
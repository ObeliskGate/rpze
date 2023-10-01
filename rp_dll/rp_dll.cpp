#include "rp_dll.h"
#include "pch.h"
#include "SharedMemory.h"

#define __until(expr) do {} while (!(expr))

void setConsole()
{
	AllocConsole();
	freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
	freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
	std::ios::sync_with_stdio();
	std::cout << "console setted" << std::endl;
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
			auto pBoard = readMemory<DWORD>(0x6a9ec0, { 0x768 }).value();
			while (phaseCode == PhaseCode::JUMP_FRAME)
			{
				__asm
				{
					mov ecx, pBoard
					mov edx, 0x415D40
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
		default:
			return;
		}
	}
}

void __stdcall script(DWORD isInIZombie, SharedMemory* pSharedMemory)
{
	if (isInIZombie)
	{
		if (pSharedMemory->getPhaseCode() != PhaseCode::JUMP_FRAME) return;
		pSharedMemory->getJumpingPhaseCode() = PhaseCode::WAIT;
		pSharedMemory->getJumpingRunState() = RunState::OVER;
		pSharedMemory->getGameTime() = readMemory<uint32_t>(0x6a9ec0, { 0x768, 0x556c }).value_or(0);
		doAsPhaseCode(pSharedMemory->getJumpingPhaseCode());
		pSharedMemory->getJumpingRunState() = RunState::RUNNING;
	}
	else
	{
		pSharedMemory->getPhaseCode() = PhaseCode::WAIT;
		pSharedMemory->getRunState() = RunState::OVER;
		pSharedMemory->getGameTime() = readMemory<uint32_t>(0x6a9ec0, { 0x768, 0x556c }).value_or(0);
		doAsPhaseCode(pSharedMemory->getPhaseCode());
		pSharedMemory->getRunState() = RunState::RUNNING;
	}
}

void injectScript(SharedMemory* pSharedMemory)
{

	DWORD tmp;
	VirtualProtect((void*)0x400000, 0x394000, PAGE_EXECUTE_READWRITE, &tmp);

	// in izupdate
	writeMemory<BYTE>(0x5f, 0x6b0000); // pop edi 
	writeMemory<BYTE>(0x5e, 0x6b0001); // pop esi
	writeMemory<BYTE>(0x5d, 0x6b0002); // pop ebp	
	writeMemory<BYTE>(0x5b, 0x6b0003); // pop ebx
	writeMemory<BYTE>(0x59, 0x6b0004); // pop ecx

	tmp = 0x6b0006;
	writeMemory<BYTE>(0x68, 0x6b0005);
	writeMemory<DWORD>((DWORD)pSharedMemory, 0x6b0006);
	tmp += 4; // push pSharedMemory

	writeMemory<BYTE>(0x68, tmp); tmp += 1;
	writeMemory<DWORD>(1, tmp);  tmp += 4; // push 1

	writeMemory<BYTE>(0xe8, tmp); tmp += 1;
	writeMemory<DWORD>(reinterpret_cast<DWORD>(script) - tmp - 4, tmp);  tmp += 4;// call script

	writeMemory<BYTE>(0xe9, tmp);  tmp += 1;
	writeMemory<DWORD>(0x42b52b - tmp - 4, tmp); // jmp 42b52b

	// out of izupdate
	tmp = 0x6b0100;
	writeMemory<BYTE>(0x68, tmp); tmp += 1;
	writeMemory<DWORD>((DWORD)pSharedMemory, tmp); tmp += 4; // push pSharedMemory

	writeMemory<BYTE>(0x68, tmp); tmp += 1;
	writeMemory<DWORD>(0, tmp);  tmp += 4; // push 0

	writeMemory<BYTE>(0xe8, tmp); tmp += 1;
	writeMemory<DWORD>(reinterpret_cast<DWORD>(script) - tmp - 4, tmp);  tmp += 4;// call script

	writeMemory<BYTE>(0xc3, tmp); // RET

	// jmp in izupdate
	writeMemory<BYTE>(0xe9, 0x42b526);
	writeMemory<DWORD>(0x6b0000 - 0x42b526 - 5, 0x42b527); // jmp 6b0000

	// jmp out of izupdate
	writeMemory<BYTE>(0xe9, 0x452732);
	writeMemory<DWORD>(0x6b0100 - 0x452732 - 5, 0x452733); // jmp 6b0100
}

#undef __until
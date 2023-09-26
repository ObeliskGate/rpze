#include "stdafx.h"
#include "tests.h"

void testWait(Memory& mem)
{
	auto flag = false; // ÊÇ·ñ±»×èÈû

	while (true)
	{

		if (mem.getRunState() == RunState::RUNNING) continue;

		if (_kbhit())
		{
			auto i = _getch();
			if (i == 'p')
			{
				std::cout << "p" << std::endl;
				flag = true;
			}
			else if (i == 'c')
			{
				std::cout << "c" << std::endl;
				flag = false;
			}
		}

		mem.getPhaseCode() = flag ? PhaseCode::WAIT : PhaseCode::CONTINUE;

	}
}

void testJumpFrame(Memory& mem)	
{
	auto bJumping = false; // ÊÇ·ñÌøÖ¡
	uint32_t startTime = 0;
	auto t = time(nullptr);

	while (true)
	{

		if (mem.getRunState() == RunState::RUNNING) continue;

		if (_kbhit())
		{

			auto i = _getch();
			if (i == 'p')
			{
				bJumping = true;
				startTime = mem.getGameTime();
				t = time(nullptr);
				std::cout << "p " << startTime << std::endl;
			}
		}

		if (bJumping && mem.getGameTime() == startTime + 1e6)
		{
			bJumping = false;
			std::cout << mem.getGameTime() << " end " << time(nullptr) - t << std::endl;
		}

		mem.getPhaseCode() = bJumping ? PhaseCode::JUMP_FRAME : PhaseCode::CONTINUE;
		if (!bJumping) mem.getJumpingPhaseCode() = PhaseCode::CONTINUE;

		if (mem.getPhaseCode() == PhaseCode::JUMP_FRAME)
		{
			if (mem.getJumpingRunState() == RunState::RUNNING) continue;
			mem.getJumpingPhaseCode() = PhaseCode::CONTINUE;
		}

	}
}

void testReadWriteMemory(Memory& mem)
{
	while (true)
	{
		if (mem.getRunState() == RunState::RUNNING) continue;

		if (_kbhit())
		{
			auto i = _getch();
			if (i == 'p')
			{
				std::cout << "p" << std::endl;
				auto sun = mem.readMemory<int32_t>({ 0x6a9ec0, 0x768, 0x5560 });
				if (!sun.has_value()) std::cerr << "fail" << std::endl;
				else std::cout << "success  " << sun.value() << std::endl;
			}
			else if (i == 'c')
			{
				std::cout << "c" << std::endl;
				auto b = mem.writeMemory<int32_t>(8000, { 0x6a9ec0, 0x768, 0x5560 });
				if (!b) std::cerr << "fail" << std::endl;
				else std::cout << "success" << std::endl;
			}
		}

		mem.getPhaseCode() = PhaseCode::CONTINUE;
	}
}

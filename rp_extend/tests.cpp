#include "stdafx.h"
#include "tests.h"

void testWait(Memory& mem)
{
	auto flag = true;

	while (true)
	{
		if (mem.isBlocked()) continue;

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

		if (flag) mem.next();
	}
}

void testJumpFrame(Memory& mem)	
{
	auto flag = true;

	while (true)
	{
		if (mem.isBlocked()) continue;

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
			else if (i == 'j')
			{
				std::cout << "j" << std::endl;
				mem.startJumpFrame();
			}
			else if (i == 'q')
			{
				std::cout << "q" << std::endl;
				mem.endJumpFrame();
			}
		}

		if (flag) mem.next();
	}
}

void testReadWriteMemory(Memory& mem)
{
	while (true)
	{
		if (mem.isBlocked()) continue;

		if (_kbhit())
		{
			auto i = _getch();
			if (i == 'p')
			{
				std::cout << "p" << std::endl;
				auto sun = mem.readMemory<int32_t>({ 0x6a9ec0, 0x768, 0x5560 });
				if (!sun.has_value()) std::cerr << "fail" << std::endl;
				else std::cout << "success  " << *sun << std::endl;
			}
			else if (i == 'c')
			{
				std::cout << "c" << std::endl;
				auto b = mem.writeMemory(8000, { 0x6a9ec0, 0x768, 0x5560 });
				if (!b) std::cerr << "fail" << std::endl;
				else std::cout << "success" << std::endl;
			}
		}

		mem.next();
	}
}

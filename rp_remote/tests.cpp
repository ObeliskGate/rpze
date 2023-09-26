#include "stdafx.h"
#include "tests.h"
#include "rp_remote.h"

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
			else if (i == 't')
			{
				std::cout << 't' << std::endl;
				// 没有意义的benchmark
				auto t = time(nullptr);
				for (size_t i = 0; i < 1e8; i++)
				{
					auto a = mem.readMemory<int32_t>({ 0x6a9ec0 });
					a = mem.readMemory<int32_t>({*a + 0x768});
					a = mem.readMemory<int32_t>({*a + 0x5560 });
				}
				std::cout << time(nullptr) - t << std::endl;

				t = time(nullptr);
				int32_t _ = 0;
				auto hPvz = getProcessHandleOfWindow(L"Plants vs. Zombies");
				for (size_t i = 0; i < 1e8; i++)
				{
					ReadProcessMemory(*hPvz, (void*)0x6a9ec0, &_, 4, NULL);
					ReadProcessMemory(*hPvz, (void*)(_ + 0x768), &_, 4, NULL);
					ReadProcessMemory(*hPvz, (void*)(_ + 0x5560), &_, 4, NULL);
				}
				std::cout << time(nullptr) - t << std::endl;
			}
		}

		mem.next();
	}
}

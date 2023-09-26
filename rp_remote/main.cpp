#include "stdafx.h"
#include "rp_remote.h"
#include "Memory.h"
#include "Enums.h"
#include "tests.h"

int main()
{    
	std::locale::global(std::locale(".936"));
	auto hProc = getProcessHandleOfWindow(L"Plants vs. Zombies");
	if (!hProc.has_value()) return 1;

#ifndef _WIN64
	// 32Î»ÏÂ×¢Èëdll
#ifdef _DEBUG
	constexpr auto route = L"C:\\space\\projects\\rpze\\Debug\\rp_dll.dll";
#else
	constexpr auto route  = L"C:\\space\\projects\\rpze\\Release\\rp_dll.dll";
#endif // _DEBUG
	injectDll(hProc.value(), route);

#endif

	auto mem = Memory(hProc.value());

	testReadWriteMemory(mem);
}



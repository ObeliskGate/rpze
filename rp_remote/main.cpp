#include "stdafx.h"
#include "rp_remote.h"
#include "Memory.h"
#include "Enums.h"
#include "tests.h"

int main()
{    

	auto hProc = getProcessHandleOfWindow(L"Plants vs. Zombies");
	if (!hProc.has_value()) return 1;

#ifndef _WIN64
	// 32Î»ÏÂ×¢Èëdll
#ifdef _DEBUG
	constexpr auto route = L"C:\\space\\projects\\rpze\\Debug\\rp_dll.dll";
#else
	constexpr auto route  = L"C:\\space\\projects\\rpze\\Release\\rp_dll.dll";
#endif // _DEBUG
	injectDll(*hProc, route);
#endif // _WIN64

	auto mem = Memory(GetProcessId(*hProc));

	testReadWriteMemory(mem);
}



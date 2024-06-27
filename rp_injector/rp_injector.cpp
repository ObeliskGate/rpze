#define WIN32_LEAN_AND_MEAN 
#include <iostream>
#include <print>
#include <Windows.h>

#ifdef _WIN64
#error please build in x86 mode
#endif

bool injectDll(DWORD pid, LPCSTR dllPath)
{   

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
    {
        std::println(std::cerr, "open process failed, err {}", GetLastError());
        return false;
    }
    HMODULE hKernel32 = GetModuleHandleW(L"KERNEL32.DLL");
    if (!hKernel32)
    {
        std::println(std::cerr, "find kernel32.dll failed, err {}", GetLastError());
        CloseHandle(hProc);
        return false;
    }

    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA)
    {
        std::println(std::cerr, "get LoadLibraryA address failed, err {}", GetLastError());
        CloseHandle(hProc);
        return false;
    }

    const auto size = (lstrlenA(dllPath) + 1) * sizeof(char);

    LPVOID pMemory = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT, PAGE_READWRITE);
    if (!pMemory)
    {
        std::println(std::cerr, "create v-memory failed, err {}", GetLastError());
        CloseHandle(hProc);
        VirtualFreeEx(hProc, pMemory, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, pMemory, dllPath, size, NULL)) 
    {
        std::println(std::cerr, "write failed, err {}", GetLastError());
        CloseHandle(hProc);
        VirtualFreeEx(hProc, pMemory, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pMemory, 0, NULL);
    if (!hRemoteThread)
    {
        std::println(std::cerr, "create remote thread failed, err {}", GetLastError());
        CloseHandle(hProc);
        VirtualFreeEx(hProc, pMemory, 0, MEM_RELEASE);
        return false;
    }

    DWORD ret = WaitForSingleObject(hRemoteThread, INFINITE);
    if (ret == WAIT_OBJECT_0)
    {
        std::println("end control");
    }
    else
    {
        std::println(std::cerr, "wait failed, err {}", GetLastError());
        CloseHandle(hRemoteThread);
        VirtualFreeEx(hProc, pMemory, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProc, pMemory, 0, MEM_RELEASE);
    CloseHandle(hProc);

    return true;
}

// 必须按照 dllAbsolutePath pids 的顺序传参.
int main(int argc, char* argv[])
{
    if (argc <= 2)
    {
        std::println(std::cerr, "expected more than 1 arguments, got {}", argc - 1);
        return 1;
    }
    char* dllAbsolutePath = argv[1];
    for (int i = 0; i < argc - 2; i++)
    {
        DWORD pid = atoi(argv[2 + i]);
        injectDll(pid, dllAbsolutePath);
    }
	return 0;
}
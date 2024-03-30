#define WIN32_LEAN_AND_MEAN 
#include <iostream>
#include <Windows.h>

#ifdef _WIN64
#error 请用32位编译
#endif

bool injectDll(DWORD pid, LPCSTR dllPath)
{   

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
    {
        std::cerr << "open process failed" << std::endl;
        return false;
    }
    HMODULE hKernel32 = GetModuleHandleW(L"KERNEL32.DLL");
    if (!hKernel32)
    {
        std::cerr << "find kernel32.dll failed" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA)
    {
        std::cerr << "get LoadLibraryA address failed" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    const auto size = (lstrlenA(dllPath) + 1) * sizeof(char);

    LPVOID pMemory = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT, PAGE_READWRITE);
    if (!pMemory)
    {
        std::cerr << "create v-memory failed" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    if (!WriteProcessMemory(hProc, pMemory, dllPath, size, NULL)) {
        std::cerr << "write failed" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pMemory, 0, NULL);
    if (!hRemoteThread)
    {
        std::cerr << "create remote thread failed" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    DWORD ret = WaitForSingleObject(hRemoteThread, INFINITE);
    if (ret == WAIT_OBJECT_0)
    {
        std::cout << "DLL inject success" << std::endl;
    }
    else
    {
        std::cerr << "DLL inject failed" << std::endl;
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
        std::cerr << "wrong arguments" << std::endl;
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
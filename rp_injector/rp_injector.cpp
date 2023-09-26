#define WIN32_LEAN_AND_MEAN 
#include <iostream>
#include <Windows.h>
#include <optional>

bool injectDll(DWORD pid, LPCSTR dllPath)
{   

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
    {
        std::cerr << "打开进程失败" << std::endl;
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"KERNEL32.DLL");
    if (!hKernel32)
    {
        std::cerr << "未找到kernal32.dll" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA)
    {
        std::cerr << "获取LoadLibraryA地址失败" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    const auto size = (lstrlenA(dllPath) + 1) * sizeof(char);

    LPVOID pMemory = VirtualAllocEx(hProc, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!pMemory)
    {
        std::cerr << "创建虚拟内存失败" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    if (!WriteProcessMemory(hProc, pMemory, dllPath, size, NULL)) {
        std::cerr << "写入虚拟内存失败" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pMemory, 0, NULL);
    if (!hRemoteThread)
    {
        std::cerr << "创建远程线程失败" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    DWORD ret = WaitForSingleObject(hRemoteThread, INFINITE);
    if (ret == WAIT_OBJECT_0)
    {
        std::cout << "DLL注入成功" << std::endl;
    }
    else
    {
        std::cerr << "DLL注入失败" << std::endl;
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

// 必须按照 dllAbsolutePath gameNumber pids 的顺序传参.
// 其中pids的个数与gameNumber相同.
int main(int argc, char* argv[])
{
    if (argc <= 2)
    {
        std::cerr << "传参错误!" << std::endl;
        return 1;
    }
    char* dllAbsolutePath = argv[1];
    int gameNumber = atoi(argv[2]);
    if (argc != 3 + gameNumber)
    {
        std::cerr << "传入pid的个数与gameNumber不符!" << std::endl;
        return 1;
    }
    for (int i = 0; i < gameNumber; i++)
    {
        DWORD pid = atoi(argv[3 + i]);
        injectDll(pid, dllAbsolutePath);
    }
	return 0;
}
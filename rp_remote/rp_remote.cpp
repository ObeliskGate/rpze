#include "stdafx.h"
#include "rp_remote.h"

std::optional<HANDLE> getProcessHandleOfWindow(LPCWSTR windowName)
{
    HWND hWnd = FindWindowW(NULL, windowName);
    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid == 0) {
        std::cerr << "δ�ҵ�����" << std::endl;
        return {};
    }

    auto ret = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (ret) return ret;
    return {};
}

bool injectDll(HANDLE hProc, LPCWSTR dllPath)
{

    HMODULE hKernel32 = GetModuleHandleW(L"KERNEL32.DLL");
    if (!hKernel32) {
        std::cerr << "δ�ҵ�kernal32.dll" << std::endl;
        return false;
    }

    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        std::cerr << "��ȡLoadLibraryW��ַʧ��" << std::endl;
        return false;
    }

    const auto size = (lstrlenW(dllPath) + 1) * sizeof(wchar_t);

    LPVOID pMemory = VirtualAllocEx(hProc, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!pMemory) {
        std::cerr << "���������ڴ�ʧ��" << std::endl;
        return false;
    }

    if (!WriteProcessMemory(hProc, pMemory, dllPath, size, NULL)) {
        std::cerr << "д�������ڴ�ʧ��" << std::endl;
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pMemory, 0, NULL);
    if (!hRemoteThread) {
        std::cerr << "����Զ���߳�" << std::endl;
        return false;
    }

    DWORD ret = WaitForSingleObject(hRemoteThread, INFINITE);
    if (ret == WAIT_OBJECT_0) {
        std::cout << "DLLע��ɹ�" << std::endl;
    }
    else {
        std::cerr << "DLLעע��ʧ��" << std::endl;
    }

    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProc, pMemory, 0, MEM_RELEASE);

    return true;
}

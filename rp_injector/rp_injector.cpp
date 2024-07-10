#include <iostream>
#include <print>
#include <span>
#include <winerror.h>

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>

#ifdef _WIN64
#error please build in x86 mode
#endif

#include "dllexport.h"

class HandleWrapper
{
    HANDLE h;
public:
    HandleWrapper(HANDLE h) : h(h) {}
    HandleWrapper(const HandleWrapper&) = delete;
    HandleWrapper(HandleWrapper&& other) : HandleWrapper(other.h) { other.h = nullptr; }
    ~HandleWrapper() { if (bool(*this)) CloseHandle(h); }
    operator HANDLE() const { return h; }
    operator bool() const { return h != 0 && h != INVALID_HANDLE_VALUE; }
    bool operator!() const { return !bool(*this); }
};

class VMemoryWrapper
{
    LPVOID p;
    HANDLE hProc;
public:
    VMemoryWrapper(HANDLE hProc, LPVOID p) : p(p), hProc(hProc) {}
    VMemoryWrapper(const VMemoryWrapper&) = delete;
    VMemoryWrapper(VMemoryWrapper&& other) : VMemoryWrapper(other.hProc, other.p) { other.p = nullptr; }

    ~VMemoryWrapper() { if (bool(*this)) VirtualFreeEx(hProc, p, 0, MEM_RELEASE); }
    operator LPVOID() const { return p; }
    operator bool() const { return p != nullptr; }
    bool operator!() const { return !bool(*this); }

    template <typename T, size_t Extent>
    requires std::is_standard_layout_v<T>
    static VMemoryWrapper newArr(HANDLE hProc, std::span<T, Extent> arr)
    {
        auto p = VirtualAllocEx(hProc, nullptr, arr.size_bytes(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!p) throw std::runtime_error("alloc v-memory failed");
        if (!WriteProcessMemory(hProc, p, arr.data(), arr.size_bytes(), nullptr)) 
            throw std::runtime_error("write v-memory failed");
        return { hProc, p };
    }

    static VMemoryWrapper newStr(HANDLE hProc, std::string_view str) 
        { return newArr(hProc, std::span<const char> {str.data(), str.size() + 1}); }


    // NOLINTBEGIN(bugprone-sizeof-expression): sizeof(ptr) is the expected behavior
    template <typename... Args>
    requires (std::is_standard_layout_v<std::decay_t<Args>> && ...)
    static VMemoryWrapper newMemory(HANDLE hProc, Args&&... args)
    {
        constexpr auto size = (sizeof(std::decay_t<Args>) + ...);
        auto p = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!p) throw std::runtime_error("alloc v-memory failed");
        auto tmp = static_cast<BYTE*>(p);
        (
            [&]
            {
                using T = std::decay_t<Args>;
                if (!WriteProcessMemory(hProc, tmp, &args, sizeof(T), nullptr))
                    throw std::runtime_error("write v-memory failed");
                tmp += sizeof(T);
            }(), ...
        );
        // NOLINTEND(bugprone-sizeof-expression)
        return { hProc, p };
    }
};

DWORD waitRemoteThread(HANDLE hProc, FARPROC func, LPVOID vMemory)
{
    HandleWrapper hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)func, vMemory, 0, NULL);
    if (!hRemoteThread)
    {
        std::println(std::cerr, "create remote thread failed, err {}", GetLastError());
        return 0;
    }
    switch (WaitForSingleObject(hRemoteThread, 5000))
    {
    case WAIT_OBJECT_0: [[likely]]
        break;
    case WAIT_TIMEOUT:
        std::println(std::cerr, "remote thread: wait timeout");
        return 0;
    case WAIT_FAILED:
        std::println(std::cerr, "remote thread: wait failed, err {}", GetLastError());
        return 0;
    default:
        std::println(std::cerr, "remot thread: unexpected behavior");
        return 0;
    }   
    DWORD r;
    GetExitCodeThread(hRemoteThread, &r);
    return r;
}

FARPROC getModuleProcAddress(LPCSTR moduleName, LPCSTR procName)
{
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule)
    {
        std::println(std::cerr, "get module handle failed, err {}", GetLastError());
        return nullptr;
    }
    FARPROC p = GetProcAddress(hModule, procName);
    if (!p)
    {
        std::println(std::cerr, "get proc address failed, err {}", GetLastError());
        return nullptr;
    }
    return p;
}

HMODULE injectDll(DWORD pid, LPCSTR dllPath)
{   

    HandleWrapper hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
    {
        std::println(std::cerr, "open process failed, err {}", GetLastError());
        return nullptr;
    }

    FARPROC pLoadLibraryA = getModuleProcAddress("KERNEL32.DLL", "LoadLibraryA");
    if (!pLoadLibraryA) return nullptr;

    auto pMemory = VMemoryWrapper::newStr(hProc, dllPath);

    auto ret = waitRemoteThread(hProc, pLoadLibraryA, pMemory);
    if (!ret)
    {
        std::println(std::cerr, "LoadLibraryA inject failed");
        return nullptr;
    }
    std::println("inject success, module handle 0x{:x}", ret);
    return reinterpret_cast<HMODULE>(ret);

}

//     __declspec(naked) DWORD WINAPI callGetProcAddressAsThread(LPVOID params)
//     {
//         __asm
//         {
//             mov ecx, [esp + 4]
//             push [ecx + 4]
//             push [ecx]
//             call [ecx + 8]
//             ret 4
//         }
//     }

//     static_assert(std::is_same_v<decltype(&callGetProcAddressAsThread), LPTHREAD_START_ROUTINE>);

constexpr static unsigned char callGetProcAddressAsThread[] = 
    "\x8bL$\x04\xffq\x04\xff""1\xffQ\x08\xc2\x04\x00"; // same as above

bool setOptions(DWORD pid, InitArgs options, HMODULE hMod)
{
    HandleWrapper hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::println(std::cerr, "open process failed, err {}", GetLastError());
        return false;
    }
    auto vSetOptionStr = VMemoryWrapper::newStr(hProcess, "setEnv");
    FARPROC pGetProcAddress = getModuleProcAddress("KERNEL32.DLL", "GetProcAddress");
    if (!pGetProcAddress) return false;
#ifndef NDEBUG
    std::println("GetProcAddress: {}", (LPVOID)pGetProcAddress);
#endif

    auto vGetProcAddrWrapper = VMemoryWrapper::newArr(hProcess, 
        std::span{reinterpret_cast<const BYTE*>(&callGetProcAddressAsThread), 512});

    auto vGetProcAddressArgs = VMemoryWrapper::newMemory(hProcess, hMod, (LPVOID)vSetOptionStr, (LPVOID)pGetProcAddress);
   
    auto ret = waitRemoteThread(hProcess, reinterpret_cast<FARPROC>((LPVOID)vGetProcAddrWrapper), vGetProcAddressArgs);
    if (!ret)
    {
        std::println(std::cerr, "GetProcAddress failed, err {}", GetLastError());
        return false;
    }
    auto pSetOptions = reinterpret_cast<FARPROC>(ret);
#ifndef NDEBUG
    std::println("get GetProcAddress success , addr {}", (LPVOID)pSetOptions);
#endif
    auto vOptions = VMemoryWrapper::newMemory(hProcess, options);
    auto ret2 = waitRemoteThread(hProcess, pSetOptions, vOptions);
    if (ret2) // return 0 for success
    {
        std::println(std::cerr, "setOptions failed, err {}", GetLastError());
        return false;
    }
    return true;

}

// 必须按照 options dllAbsolutePath pids 的顺序传参.
int main(int argc, char* argv[])
{
    if (argc <= 3)
    {
        std::println(std::cerr, "expected at least 3 arguments, got {}", argc - 1);
        return 1;
    }
    uint32_t options = atoi(argv[1]);
    char* dllAbsolutePath = argv[2];
    for (int i = 3; i < argc; i++)
    {
        DWORD pid = atoi(argv[i]);
        auto hMod = injectDll(pid, dllAbsolutePath);
        if (setOptions(pid, options, hMod))
            std::println("setOptions {} success", options);
        
    }
	return 0;
}
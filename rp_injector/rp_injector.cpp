#include <iostream>
#include <print>

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>

#ifdef _WIN64
#error please build in x86 mode
#endif

class HandleWrapper
{
    HANDLE h;
public:
    HandleWrapper(HANDLE h) : h(h) {}
    HandleWrapper(const HandleWrapper&) = delete;
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
    ~VMemoryWrapper() { if (bool(*this)) VirtualFreeEx(hProc, p, 0, MEM_RELEASE); }
    operator LPVOID() const { return p; }
    operator bool() const { return p != nullptr; }
    bool operator!() const { return !bool(*this); }

    static VMemoryWrapper newStr(HANDLE hProc, std::string_view str)
    {
        auto size = str.size() + 1;
        auto p = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT, PAGE_READWRITE);
        if (!p) throw std::runtime_error("alloc v-memory failed");
        if (!WriteProcessMemory(hProc, p, str.data(), size, nullptr)) 
            throw std::runtime_error("write v-memory failed");
        // auto test = std::string(size, '\0');
        // if (!ReadProcessMemory(hProc, p, test.data(), size, nullptr))
        //     throw std::runtime_error("read v-memory failed");
        // std::println("test: {}", test);
        return { hProc, p };
    }

    template <typename... Args>
    requires (std::is_standard_layout_v<std::decay_t<Args>> && ...)
    static VMemoryWrapper newMemory(HANDLE hProc, Args&&... args)
    {
        constexpr auto size = (sizeof(std::decay_t<Args>) + ...);
        auto p = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT, PAGE_READWRITE);
        if (!p) throw std::runtime_error("alloc v-memory failed");
        auto tmp = static_cast<BYTE*>(p);
        (
            [&]() {
                auto t = std::forward<Args>(args);
                if (!WriteProcessMemory(hProc, tmp, &t, sizeof(t), nullptr))
                    throw std::runtime_error("write v-memory failed");
                tmp += sizeof(t);
            }(), ...
        );
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
    DWORD ret = WaitForSingleObject(hRemoteThread, INFINITE);
    if (ret != WAIT_OBJECT_0)
    {
        std::println(std::cerr, "wait failed, err {}", GetLastError());
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

struct GetProcAddrParams
{
    HMODULE hModule;
    LPCSTR procName;
    decltype(&GetProcAddress) pGetProcAddress;
};

FARPROC WINAPI callGetProcAddressAsThread(GetProcAddrParams* params)
{
    return params->pGetProcAddress(params->hModule, params->procName);
}

bool setOptions(DWORD pid, uint32_t options, HMODULE hMod)
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
    auto vGetProcAddressArgs = VMemoryWrapper::newMemory(hProcess, hMod, (LPVOID)vSetOptionStr, pGetProcAddress);

    VMemoryWrapper vGetProcAddrWrapper = { hProcess, 
       VirtualAllocEx(hProcess, nullptr, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE) };

    if (!vGetProcAddrWrapper)
    {
        std::println(std::cerr, "alloc v-memory for callGetProcAddressAsThread failed, err {}", GetLastError());
        return false;
    }

    if (!WriteProcessMemory(hProcess, vGetProcAddrWrapper, reinterpret_cast<void*>(&callGetProcAddressAsThread), 1024, nullptr))
    {
        std::println(std::cerr, "write v-memory for callGetProcAddressAsThread failed, err {}", GetLastError());
        return false;
    }
    
    auto ret = waitRemoteThread(hProcess, (FARPROC)(LPVOID)vGetProcAddrWrapper, vGetProcAddressArgs);
    if (!ret)
    {
        std::println(std::cerr, "GetProcAddress failed, err {}", GetLastError());
        return false;
    }
    std::println("get GetProcAddress success {:x}", ret);
    auto pSetOptions = reinterpret_cast<FARPROC>(ret);
    auto vOptions = VMemoryWrapper::newMemory(hProcess, options);
    auto ret2 = waitRemoteThread(hProcess, pSetOptions, vOptions);
    if (!ret2)
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
            std::println("setOptions success");
        
    }
	return 0;
}
#pragma once
#include "stdafx.h"

// 获得名字为windowName的窗口的HANDLE
std::optional<HANDLE> getProcessHandleOfWindow(LPCWSTR windowName);

// 向hProc进程为注入绝对路径为dllPath的dll, 成功返回true
bool injectDll(HANDLE hProc, LPCWSTR dllPath);
#pragma once

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
// Windows 头文件
#include <windows.h>
#include <iostream>
#include <string>
#include <assert.h>
#include <conio.h>
#include <optional>
#include <array>
#include <locale>

constexpr wchar_t SHARED_MEMORY_NAME_AFFIX[] = L"rp_dll_shared_memory_";


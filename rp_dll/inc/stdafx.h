#pragma once

#ifdef _WIN64
#error please compile as x86
#endif

// 添加要在此处预编译的标头
#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#define NOMINMAX
// Windows 头文件
#include <Windows.h> // IWYU pragma: export
#include <iostream>  // IWYU pragma: export

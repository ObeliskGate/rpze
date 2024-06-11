#pragma once

// 添加要在此处预编译的标头
#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#define NOMINMAX
// Windows 头文件
#include <Windows.h>
#include <iostream>
#include <initializer_list>
#include <assert.h>
#include <string>
#include <vector>
#include <optional>
#include <array>
#include <functional>
#include <limits>

constexpr wchar_t UU_NAME_AFFIX[] = L"__rp_dll_shared_affix_";

constexpr size_t SHARED_MEMORY_SIZE = 1024 * 8;

// 读取内存
template <typename T>
std::optional<T> readMemory(DWORD basePtr, const std::initializer_list<DWORD>& offsets = {})
{
	for (auto it : offsets)
	{
		basePtr = *reinterpret_cast<DWORD*>(basePtr);
		if (!basePtr) return {};
		basePtr += it;
	}
	if (!basePtr) return {};
	return *reinterpret_cast<T*>(basePtr);
}

// 写入内存, 成功返回true不成功返回false
template <typename T>
bool writeMemory(T&& data, DWORD basePtr, const std::initializer_list<DWORD>& offsets = {})
{
	for (auto it : offsets)
	{
		basePtr = *reinterpret_cast<DWORD*>(basePtr);
		if (!basePtr) return false;
		basePtr += it;
	}
	if (!basePtr) return false;
	*reinterpret_cast<T*>(basePtr) = data;
	return true;
}

#ifdef _WIN64
#error please compile as x86
#endif
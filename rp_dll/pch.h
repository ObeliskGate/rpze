// pch.h: 这是预编译标头文件。
// 下方列出的文件仅编译一次，提高了将来生成的生成性能。
// 这还将影响 IntelliSense 性能，包括代码完成和许多代码浏览功能。
// 但是，如果此处列出的文件中的任何一个在生成之间有更新，它们全部都将被重新编译。
// 请勿在此处添加要频繁更新的文件，这将使得性能优势无效。
#pragma once

// 添加要在此处预编译的标头
#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
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

constexpr wchar_t SHARED_MEMORY_NAME_AFFIX[] = L"rp_dll_shared_memory_";

constexpr size_t SHARED_MEMORY_SIZE = 8192;

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

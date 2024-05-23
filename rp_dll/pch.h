// pch.h: ����Ԥ�����ͷ�ļ���
// �·��г����ļ�������һ�Σ�����˽������ɵ��������ܡ�
// �⻹��Ӱ�� IntelliSense ���ܣ�����������ɺ�������������ܡ�
// ���ǣ�����˴��г����ļ��е��κ�һ��������֮���и��£�����ȫ�����������±��롣
// �����ڴ˴����ҪƵ�����µ��ļ����⽫ʹ������������Ч��
#pragma once

// ���Ҫ�ڴ˴�Ԥ����ı�ͷ
#define WIN32_LEAN_AND_MEAN             // �� Windows ͷ�ļ����ų�����ʹ�õ�����
#define NOMINMAX
// Windows ͷ�ļ�
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

// ��ȡ�ڴ�
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

// д���ڴ�, �ɹ�����true���ɹ�����false
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

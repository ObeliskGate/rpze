// pch.h: ����Ԥ�����ͷ�ļ���
// �·��г����ļ�������һ�Σ�����˽������ɵ��������ܡ�
// �⻹��Ӱ�� IntelliSense ���ܣ�����������ɺ�������������ܡ�
// ���ǣ�����˴��г����ļ��е��κ�һ��������֮���и��£�����ȫ�����������±��롣
// �����ڴ˴����ҪƵ�����µ��ļ����⽫ʹ������������Ч��
#pragma once

// ���Ҫ�ڴ˴�Ԥ����ı�ͷ
#define WIN32_LEAN_AND_MEAN             // �� Windows ͷ�ļ����ų�����ʹ�õ�����
// Windows ͷ�ļ�
#include <Windows.h>
#include <iostream>
#include <initializer_list>
#include <assert.h>
#include <string>
#include <vector>
#include <optional>
#include <array>

constexpr wchar_t SHARED_MEMORY_NAME_AFFIX[] = L"rp_dll_shared_memory_";

// ��ȡ�ڴ�
template <typename T>
std::optional<T> readMemory(DWORD basePtr, const std::initializer_list<DWORD>& offsets = {})
{
	for (auto it : offsets)
	{
		if (!basePtr) return {};
		basePtr = *reinterpret_cast<DWORD*>(basePtr);
		if (!basePtr) return {};
		basePtr += it;
	}
	if (!basePtr) return {};
	return *reinterpret_cast<T*>(basePtr);
}

// д���ڴ�, �ɹ�����true���ɹ�����false
template <typename T>
bool writeMemory(const T& data, DWORD basePtr, const std::initializer_list<DWORD>& offsets = {})
{
	for (auto it : offsets)
	{
		if (!basePtr) return false;
		basePtr = *reinterpret_cast<DWORD*>(basePtr);
		if (!basePtr) return false;
		basePtr += it;
	}
	if (!basePtr) return false;
	*reinterpret_cast<T*>(basePtr) = data;
	return true;
}

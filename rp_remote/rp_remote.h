#pragma once
#include "stdafx.h"

// �������ΪwindowName�Ĵ��ڵ�HANDLE
std::optional<HANDLE> getProcessHandleOfWindow(LPCWSTR windowName);

// ��hProc����Ϊע�����·��ΪdllPath��dll, �ɹ�����true
bool injectDll(HANDLE hProc, LPCWSTR dllPath);
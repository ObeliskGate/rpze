#pragma once

#define WIN32_LEAN_AND_MEAN             // �� Windows ͷ�ļ����ų�����ʹ�õ�����
// Windows ͷ�ļ�
#include <Windows.h>
#include <iostream>
#include <string>
#include <assert.h>
#include <conio.h>
#include <optional>
#include <array>
#include <locale>
#include <vector>
#include <limits>
#include <pybind11/pybind11.h>

constexpr wchar_t SHARED_MEMORY_NAME_AFFIX[] = L"rp_dll_shared_memory_";

namespace py = pybind11;


#pragma once

#define WIN32_LEAN_AND_MEAN             // �� Windows ͷ�ļ����ų�����ʹ�õ�����
#define NOMINMAX
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
#include <variant>

constexpr wchar_t UU_NAME_AFFIX[] = L"__rp_dll_shared_affix_";

constexpr size_t SHARED_MEMORY_SIZE = 1024 * 8;

namespace py = pybind11;


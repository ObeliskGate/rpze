#pragma once

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#define NOMINMAX
// Windows 头文件
#include <Windows.h>  // IWYU pragma: export
#include <pybind11/pybind11.h>  // IWYU pragma: export
#include <pybind11/stl.h>  // IWYU pragma: export
#include <iostream>  // IWYU pragma: export

namespace py = pybind11;  // NOLINT


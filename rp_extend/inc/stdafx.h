#pragma once

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#define NOMINMAX
// Windows 头文件
#include <Windows.h> 

#include <stddef.h>
#include <stdint.h>
#include <assert.h>

#include <string>
#include <string_view>
#include <print>
#include <concepts>
#include <iterator>
#include <type_traits>
#include <ranges>
#include <vector>
#include <functional>
#include <unordered_map>
#include <optional>
#include <iostream>


#include <pybind11/pybind11.h> 
#include <pybind11/stl.h>  
namespace py = pybind11;  // NOLINT




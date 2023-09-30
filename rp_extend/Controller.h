#pragma once
#include "Memory.h"
#include "stdafx.h"
#include <pybind11/stl.h>
// 给Python侧暴露的类型

class Controller
{
	Memory mem;
public:
	Controller(DWORD pid) : mem(pid) {}

	inline void next() { mem.next(); }

	inline bool is_blocked() { return mem.isBlocked(); }

	inline bool start_jump_frame() { return mem.startJumpFrame(); }

	inline bool end_jump_frame() { return mem.endJumpFrame(); }

	template <typename T>
	inline std::optional<T> read_memory(const std::vector<int32_t>& offsets) 
	{ return mem.readMemory<T>(offsets); }

	template <typename T>
	inline bool write_memory(T&& val, const std::vector<int32_t>& offsets) 
	{ return mem.writeMemory(val, offsets); }
};

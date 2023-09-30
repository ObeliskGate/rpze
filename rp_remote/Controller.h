#pragma once
#include "Memory.h"
// 给Python侧暴露的类型, 函数变量命名换snake_case

class Controller
{
	Memory mem;
public:
	void next();

	bool is_inserted();

	bool start_jump_frame();

	bool end_jump_frame();

	template <typename T>
	std::optional<T> read_memory();
};


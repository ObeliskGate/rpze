#pragma once
#include "Memory.h"
// ��Python�౩¶������, ��������������snake_case

class Controller
{
	std::unique_ptr<Memory> mem;
public:
	void next();

	bool is_inserted();

	bool start_jump_frame();

	bool end_jump_frame();

	template <typename T>
	std::optional<T> read_memory();
};


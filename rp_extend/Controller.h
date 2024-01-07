#pragma once
#include "Memory.h"
#include "stdafx.h"
#include <pybind11/stl.h>
// 给Python侧暴露的类型

class Controller
{
	Memory mem;
	uint32_t offset_buffer[1024] = {};

	uint32_t set_offset_arr_of_py_list(const py::list& offsets);
public:
	explicit Controller(DWORD pid) : mem(pid) {}

	DWORD pid() const { return mem.getPid(); }

	std::tuple<bool, uint32_t> get_p_board() const // 第一位返回true表示无须换新
	{
		return mem.getPBoard();
	}

	bool hook_connected(HookPosition pos = HookPosition::MAIN_LOOP) const { return mem.hookConnected(pos); }

	void next_frame() const { mem.next(); }

	void before() const { while (mem.isBlocked()) {} }

	bool start_jump_frame() { return mem.startJumpFrame(); }

	bool end_jump_frame() { return mem.endJumpFrame(); }

	template <typename T>
	std::optional<T> read_memory(const py::list& offsets);

	template <typename T>
	bool write_memory(T&& val, const py::list& offsets);
	
	inline bool run_code(const py::bytes& codes) const;

	void end() { mem.endControl(); }

	void start() { mem.startControl(); }

	uint32_t result_address() const { return mem.getWrittenAddress(); }

	uint32_t asm_address() const { return mem.getAsmAddress(); }

	template<typename T>
	T get_result()
	{
		static_assert(sizeof(T) <= 8);
		return *static_cast<volatile T*>(mem.getReturnResult());
	}

	bool operator==(const Controller& other) const { return mem.getPid() == other.mem.getPid(); }

	bool operator!=(const Controller& other) const { return mem.getPid() != other.mem.getPid(); }

	void open_hook(HookPosition hook) { mem.openHook(hook); }

	void close_hook(HookPosition hook) { mem.closeHook(hook); }

	template<typename T>
	void set_result(T val)
	{
		static_assert(sizeof(T) <= 8);
		*static_cast<volatile T*>(mem.getReturnResult()) = val;
	}

	py::object read_bytes(uint32_t size, const py::list& offsets);

	bool write_bytes(const py::bytes& in, const py::list& offsets);
};

template <typename T>
std::optional<T> Controller::read_memory(const py::list& offsets)
{
	auto len_ = set_offset_arr_of_py_list(offsets);
	return mem.readMemory<T>(offset_buffer, len_);
}

template <typename T>
bool Controller::write_memory(T&& val, const py::list& offsets)
{
	auto len_ = set_offset_arr_of_py_list(offsets);
	return mem.writeMemory<T>(std::forward<T>(val), offset_buffer, len_);
}

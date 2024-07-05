#pragma once
#include "Memory.h"
#include "stdafx.h"
#include <concepts>

// 给Python侧暴露的类型

class Controller
{
	Memory mem;
	uint32_t offset_buffer[128] = {};

	template <typename T>
	requires requires(T sequence, size_t i)
	{
		{ sequence[i] } -> std::convertible_to<py::object>;
		{ sequence.size() } -> std::integral;
	}
	size_t set_offset_arr_of_py_sequence(const T& offsets)
	{
		auto len_ = offsets.size();
		for (size_t i = 0; i < len_; i++)
		{
			offset_buffer[i] = py::cast<uint32_t>(offsets[i]);
		}
		return len_;
	}

public:
	py::memoryview result_mem;

	explicit Controller(DWORD pid);

	DWORD pid() const { return mem.getPid(); }

	std::pair<bool, uint32_t> get_p_board() const { return mem.getPBoard(); }

	bool hook_connected(HookPosition pos = HookPosition::MAIN_LOOP) const { return mem.hookConnected(pos); }

	bool global_connected() const { return mem.globalConnected(); }

	void next_frame() const { mem.next(); }

	void before() const { mem.before(); }

	void skip_frames(size_t num = 1) const { mem.skipFrames(num); }

	bool is_jumping_frame() const { return mem.isJumpingFrame(); }

	bool start_jump_frame() { return mem.startJumpFrame(); }

	bool end_jump_frame() { return mem.endJumpFrame(); }

	template <typename T>
	std::optional<T> read_memory(const py::args& offsets, bool force_remote = false);

	template <typename T>
	bool write_memory(T&& val, const py::args& offsets, bool force_remote = false);
	
	inline bool run_code(const py::bytes& codes) const { return mem.runCode(codes); }

	void end() { mem.endControl(); }

	void start() { mem.startControl(); }

	uint32_t result_address() const { return mem.getBufferAddress(); }

	uint32_t asm_address() const { return mem.getAsmAddress(); }

	bool operator==(const Controller& other) const { return mem.getPid() == other.mem.getPid(); }

	bool operator!=(const Controller& other) const { return mem.getPid() != other.mem.getPid(); }

	void open_hook(HookPosition hook) { mem.openHook(hook); }

	void close_hook(HookPosition hook) { mem.closeHook(hook); }

	SyncMethod sync_method() const { return mem.getSyncMethod(); }

	SyncMethod jumping_sync_method() const { return mem.getJumpingSyncMethod(); }

	void set_sync_method(SyncMethod val) { mem.setSyncMethod(val); }

	void set_jumping_sync_method(SyncMethod val) { mem.setJumpingSyncMethod(val); }

	template<typename T>
	requires std::is_standard_layout_v<T> && (sizeof(T) <= Shm::BUFFER_SIZE)
	T get_result() { return *static_cast<volatile T*>(mem.getReturnResult());}

	template<typename T>
	requires std::is_standard_layout_v<std::decay_t<T>> && (sizeof(std::decay_t<T>) <= Shm::BUFFER_SIZE)
	void set_result(T&& val) { *static_cast<volatile T*>(mem.getReturnResult()) = std::forward<T>(val);}

	py::object read_bytes(uint32_t size, const py::args& offsets, bool force_remote = false);

	bool write_bytes(const py::bytes& in, const py::args& offsets, bool force_remote = false);
};

template <typename T>
std::optional<T> Controller::read_memory(const py::args& offsets, bool force_remote)
{
	return mem.readMemory<T>({offset_buffer, set_offset_arr_of_py_sequence(offsets)}, force_remote);
}

template <typename T>
bool Controller::write_memory(T&& val, const py::args& offsets, bool force_remote)
{
	return mem.writeMemory(std::forward<T>(val), {offset_buffer, set_offset_arr_of_py_sequence(offsets)}, force_remote);
}


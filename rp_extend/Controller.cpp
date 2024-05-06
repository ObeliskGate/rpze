#include "stdafx.h"
#include "Controller.h"

PYBIND11_MODULE(rp_extend, m)
{
	py::enum_<HookPosition>(m, "HookPosition")
		.value("MAIN_LOOP", HookPosition::MAIN_LOOP)
		.value("ZOMBIE_PICK_RANDOM_SPEED", HookPosition::ZOMBIE_PICK_RANDOM_SPEED)
		.value("CHALLENGE_I_ZOMBIE_SCORE_BRAIN", HookPosition::CHALLENGE_I_ZOMBIE_SCORE_BRAIN);

	PYBIND11_CONSTINIT static py::gil_safe_call_once_and_store<py::object> base_exc_storage;
	base_exc_storage.call_once_and_store_result(
		[&m] { return py::exception<void>(m, "RpBaseException"); });

	py::register_exception<MemoryException>(m, "ControllerError", base_exc_storage.get_stored());

	py::class_<Controller>(m, "Controller")
		.def(py::init<DWORD>())
		.def("__eq__", &Controller::operator==)
		.def("__ne__", &Controller::operator!=)
		.def("__repr__", [](const Controller& ctler)
		{
			return "Controller(" + std::to_string(ctler.pid()) + ")";
		})
		.def_property_readonly("pid", &Controller::pid)
		.def_readonly("result_mem", &Controller::result_mem, py::return_value_policy::reference_internal)
		.def("next_frame", &Controller::next_frame)
		.def("before", &Controller::before)
		.def("skip_frames", &Controller::skip_frames, py::arg("num") = 1)
		.def("is_jumping_frame", &Controller::is_jumping_frame)
		.def("start_jump_frame", &Controller::start_jump_frame)
		.def("end_jump_frame", &Controller::end_jump_frame)
		.def("get_p_board", &Controller::get_p_board)
		.def("run_code", &Controller::run_code)
		.def("start", &Controller::start)
		.def("end", &Controller::end)
		.def("open_hook", &Controller::open_hook)
		.def("close_hook", &Controller::close_hook)
		.def("hook_connected", &Controller::hook_connected, py::arg("hook") = HookPosition::MAIN_LOOP)
		.def("global_connected", &Controller::global_connected)

		.def("read_bytes", &Controller::read_bytes)
		.def("write_bytes", &Controller::write_bytes)

		// read
		.def("read_bool", &Controller::read_memory<bool>)
		.def("read_i8", &Controller::read_memory<int8_t>)
		.def("read_i16", &Controller::read_memory<int16_t>)
		.def("read_i32", &Controller::read_memory<int32_t>)
		.def("read_i64", &Controller::read_memory<int64_t>)
		.def("read_u8", &Controller::read_memory<uint8_t>)
		.def("read_u16", &Controller::read_memory<uint16_t>)
		.def("read_u32", &Controller::read_memory<uint32_t>)
		.def("read_u64", &Controller::read_memory<uint64_t>)
		.def("read_f32", &Controller::read_memory<float>)
		.def("read_f64", &Controller::read_memory<double>)

		// write
		.def("write_bool", &Controller::write_memory<bool>)
		.def("write_i8", &Controller::write_memory<int8_t>)
		.def("write_i16", &Controller::write_memory<int16_t>)
		.def("write_i32", &Controller::write_memory<int32_t>)
		.def("write_i64", &Controller::write_memory<int64_t>)
		.def("write_u8", &Controller::write_memory<uint8_t>)
		.def("write_u16", &Controller::write_memory<uint16_t>)
		.def("write_u32", &Controller::write_memory<uint32_t>)
		.def("write_u64", &Controller::write_memory<uint64_t>)
		.def("write_f32", &Controller::write_memory<float>)
		.def("write_f64", &Controller::write_memory<double>)

		.def_property_readonly("result_address", &Controller::result_address)
		.def_property_readonly("asm_address", &Controller::asm_address)
		.def_property("result_bool", &Controller::get_result<bool>, &Controller::set_result<bool>)
		.def_property("result_i8", &Controller::get_result<int8_t>, &Controller::set_result<int8_t>)
		.def_property("result_i16", &Controller::get_result<int16_t>, &Controller::set_result<int16_t>)
		.def_property("result_i32", &Controller::get_result<int32_t>, &Controller::set_result<int32_t>)
		.def_property("result_i64", &Controller::get_result<int64_t>, &Controller::set_result<int64_t>)
		.def_property("result_u8", &Controller::get_result<uint8_t>, &Controller::set_result<uint8_t>)
		.def_property("result_u16", &Controller::get_result<uint16_t>, &Controller::set_result<uint16_t>)
		.def_property("result_u32", &Controller::get_result<uint32_t>, &Controller::set_result<uint32_t>)
		.def_property("result_u64", &Controller::get_result<uint64_t>, &Controller::set_result<uint64_t>)
		.def_property("result_f32", &Controller::get_result<float>, &Controller::set_result<float>)
		.def_property("result_f64", &Controller::get_result<double>, &Controller::set_result<double>);

}

uint32_t Controller::set_offset_arr_of_py_iterable(const py::tuple& offsets)
{
	auto len_ = static_cast<uint32_t>(offsets.size());
	for (auto&& it : offsets)
	{
		offset_buffer[len_] = it.cast<uint32_t>();
	}
	return len_;
}

Controller::Controller(DWORD pid) : mem(pid),
	result_mem(py::memoryview::from_memory(const_cast<void*>(mem.getReturnResult()), Memory::RESULT_SIZE, false))
{ }

bool Controller::run_code(const py::bytes& codes) const
{
	auto sw = std::string_view(codes);
	return mem.runCode(sw.data(), sw.size());
}

py::object Controller::read_bytes(uint32_t size, const py::args& offsets)
{
	auto len_ = set_offset_arr_of_py_iterable(offsets);
	auto ret = mem.readBytes(size, offset_buffer, len_);
	if (ret.has_value()) return py::bytes(ret->get(), size);
	return py::none();
}

bool Controller::write_bytes(const py::bytes& in, const py::args& offsets)
{
	auto sw = std::string_view(in);
	auto len_ = set_offset_arr_of_py_iterable(offsets);
	return mem.writeBytes(sw.data(), static_cast<uint32_t>(sw.size()), offset_buffer, len_);
}

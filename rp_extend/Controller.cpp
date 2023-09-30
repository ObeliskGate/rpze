#include "stdafx.h"
#include "Controller.h"

PYBIND11_MODULE(rp_extend, m)
{
	py::class_<Controller>(m, "Controller")
		.def(py::init<DWORD>())
		.def("next", &Controller::next)
		.def("is_blocked", &Controller::is_blocked)
		.def("start_jump_frame", &Controller::start_jump_frame)
		.def("end_jump_frame", &Controller::end_jump_frame)

		// read
		.def("read_i8", &Controller::read_memory<int8_t>)
		.def("read_i16", &Controller::read_memory<int16_t>)
		.def("read_i32", &Controller::read_memory<int32_t>)
		.def("read_i64", &Controller::read_memory<int64_t>)
		.def("read_f32", &Controller::read_memory<float>)
		.def("read_f64", &Controller::read_memory<double>)

		// write
		.def("write_i8", &Controller::write_memory<int8_t>)
		.def("write_i16", &Controller::write_memory<int16_t>)
		.def("write_i32", &Controller::write_memory<int32_t>)
		.def("write_i64", &Controller::write_memory<int64_t>)
		.def("write_f32", &Controller::write_memory<float>)
		.def("write_f64", &Controller::write_memory<double>)
		.def("write_memory", &Controller::write_memory<int32_t>);
}
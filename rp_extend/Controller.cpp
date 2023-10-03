#include "stdafx.h"
#include "Controller.h"

PYBIND11_MODULE(rp_extend, m)
{
	py::class_<Controller>(m, "Controller")
		.def(py::init<DWORD>())
		.def("next", &Controller::next)
		.def("before", &Controller::before)
		.def("start_jump_frame", &Controller::start_jump_frame)
		.def("end_jump_frame", &Controller::end_jump_frame)
		.def("get_time", &Controller::get_time)
		.def("run_code", &Controller::run_code)
		.def("start", &Controller::start)
		.def("end", &Controller::end)

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
		.def("write_memory", &Controller::write_memory<int32_t>)

		.def_property_readonly("result_address", &Controller::result_address)
		.def_property_readonly("result_i8", &Controller::get_result<int8_t>)
		.def_property_readonly("result_i16", &Controller::get_result<int16_t>)
		.def_property_readonly("result_i32", &Controller::get_result<int32_t>)
		.def_property_readonly("result_i64", &Controller::get_result<int64_t>)
		.def_property_readonly("result_f32", &Controller::get_result<float>)
		.def_property_readonly("result_f64", &Controller::get_result<double>);
}
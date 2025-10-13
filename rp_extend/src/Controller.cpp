#include "Controller.h"
#include "MemoryException.h"

#define RP_REPEAT_MACRO(macro) \
	macro(bool, bool) \
	macro(i8, int8_t) \
	macro(i16, int16_t) \
	macro(i32, int32_t) \
	macro(i64, int64_t) \
	macro(u8, uint8_t) \
	macro(u16, uint16_t) \
	macro(u32, uint32_t) \
	macro(u64, uint64_t) \
	macro(f32, float) \
	macro(f64, double)

PYBIND11_MODULE(rp_extend, m)
{
	py::native_enum<HookPosition>(m, "HookPosition", "enum.Enum")
		.value("MAIN_LOOP", HookPosition::MAIN_LOOP)
		.value("ZOMBIE_PICK_RANDOM_SPEED", HookPosition::ZOMBIE_PICK_RANDOM_SPEED)
		.value("CHALLENGE_I_ZOMBIE_SCORE_BRAIN", HookPosition::CHALLENGE_I_ZOMBIE_SCORE_BRAIN)
		.value("CHALLENGE_I_ZOMBIE_PLACE_PLANTS", HookPosition::CHALLENGE_I_ZOMBIE_PLACE_PLANTS)
		.finalize();

	py::native_enum<SyncMethod>(m, "SyncMethod", "enum.Enum")
		.value("SPIN", SyncMethod::SPIN)
		.value("MUTEX", SyncMethod::MUTEX)
		.finalize();

	PYBIND11_CONSTINIT static py::gil_safe_call_once_and_store<py::object> base_exc_storage;
	base_exc_storage.call_once_and_store_result(
		[&m] { return py::exception<void>(m, "RpBaseException"); });

	py::register_exception<MemoryException>(m, 
		"ControllerError",
		 base_exc_storage.get_stored());

	py::class_<Controller>(m, "Controller")
		.def(py::init<DWORD>())
		.def("__eq__", &Controller::operator==)
		.def("__ne__", &Controller::operator!=)
		.def("__repr__", [](const Controller& self)
			{ return std::format("Controller({})", self.pid()); })
		.def_property_readonly("pid", &Controller::pid)
		.def_readonly("result_mem", 
			&Controller::result_mem,
			 py::return_value_policy::reference_internal)
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
		.def_property("sync_method", &Controller::sync_method, &Controller::set_sync_method)
		.def_property("jumping_sync_method", &Controller::jumping_sync_method, &Controller::set_jumping_sync_method)

		// read
#define RP_READ_MODEL(t_name, t) \
		.def("read_"#t_name, &Controller::read_memory<t>, py::arg("force_remote") = false)

		RP_REPEAT_MACRO(RP_READ_MODEL)

        .def("read_bytes", &Controller::read_bytes, py::arg("size"), py::arg("force_remote") = false)

		// write
#define RP_WRITE_MODEL(t_name, t) \
		.def("write_"#t_name, &Controller::write_memory<t>, py::arg("value"), py::arg("force_remote") = false)
			
		RP_REPEAT_MACRO(RP_WRITE_MODEL)
		
		.def("write_bytes", &Controller::write_bytes, py::arg("value"), py::arg("force_remote") = false)

		.def_property_readonly("result_address", &Controller::result_address)
		.def_property_readonly("asm_address", &Controller::asm_address)

#define RP_RESULT_MODEL(t_name, t) \
		.def_property("result_"#t_name, &Controller::get_result<t>, &Controller::set_result<t>)

		RP_REPEAT_MACRO(RP_RESULT_MODEL);

}

Controller::Controller(DWORD pid) : mem(pid),
	result_mem(py::memoryview::from_memory(const_cast<void*>(mem.getReturnResult()), Shm::BUFFER_SIZE, false))
{ }

py::object Controller::read_bytes(uint32_t size, const py::args& offsets, bool force_remote)
{
	auto ret = mem.readBytes(size, 
		transform_to_offset(offsets), 
		force_remote);
	if (ret.has_value()) return py::bytes(ret->get(), size);
	return py::none();
}

bool Controller::write_bytes(const py::bytes& in, const py::args& offsets, bool force_remote)
{
	return mem.writeBytes(in, 
		transform_to_offset(offsets), 
		force_remote);
}

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
	auto objType = py::enum_<ObjType>(m, "ObjType");
	objType
		.value("PLANT", ObjType::Plant)
		.value("ZOMBIE", ObjType::Zombie)
		.value("PROJECTILE", ObjType::Projectile)
		.value("GRID_ITEM", ObjType::GridItem)
		.def_property_readonly("ITEM_SIZE", [](ObjType type) {
			return getObjTypeInfo(type).ITEM_SIZE;
		})
		.def_property_readonly("BOARD_ARRAY_OFFSET", [](ObjType type) {
			return getObjTypeInfo(type).BOARD_ARRAY_OFFSET;
		});

	py::class_<ObjTypeInfo>(m, "ObjTypeInfo")
		.def_property_readonly("ITEM_SIZE", [](const ObjTypeInfo& info) { return info.ITEM_SIZE; })
		.def_property_readonly("BOARD_ARRAY_OFFSET", [](const ObjTypeInfo& info) {
			return info.BOARD_ARRAY_OFFSET;
		});

	py::class_<ObjUuid>(m, "ObjUuid")
		.def(py::init<>())
		.def(py::init<uint32_t, uint16_t, ObjType>(),
			py::arg("uuid_cnt"), py::arg("index"), py::arg("type"))
		.def_property_readonly("uuid_cnt", [](const ObjUuid& uuid) { return uuid.fields.uuidCnt; })
		.def_property_readonly("index", [](const ObjUuid& uuid) { return uuid.fields.index; })
		.def_property_readonly("type", [](const ObjUuid& uuid) { return uuid.fields.type; })
		.def_property_readonly("value", &ObjUuid::asValue)
		.def("__bool__", [](const ObjUuid& uuid) { return static_cast<bool>(uuid); })
		.def("__int__", &ObjUuid::asValue)
		.def("__eq__", &ObjUuid::operator==)
		.def("__hash__", [](const ObjUuid& uuid) {
			return py::hash(py::int_(uuid.asValue()));
		})
		.def("__repr__", [](const ObjUuid& uuid) {
			return std::format("ObjUuid(uuid_cnt={}, index={}, type={})",
				uuid.fields.uuidCnt, uuid.fields.index, static_cast<uint16_t>(uuid.fields.type));
		});

	m.attr("OBJ_UUID_SLOT_COUNT") = py::int_(OBJ_UUID_SLOT_COUNT);
	m.attr("OBJ_TYPE_INFO") = py::make_tuple(
		OBJ_TYPE_INFO[0], OBJ_TYPE_INFO[1], OBJ_TYPE_INFO[2], OBJ_TYPE_INFO[3]);

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
		.def("get_obj_array_ptr", &Controller::get_obj_array_ptr)
		.def("get_obj_block_ptr", &Controller::get_obj_block_ptr)
		.def("get_obj_max_size", &Controller::get_obj_max_size)
		.def("get_obj_base_ptr",
			py::overload_cast<ObjType, int64_t>(&Controller::get_obj_base_ptr, py::const_),
			py::arg("type"), py::arg("index"))
		.def("get_obj_base_ptr",
			py::overload_cast<const ObjUuid&>(&Controller::get_obj_base_ptr, py::const_),
			py::arg("uuid"))
		.def("get_obj_uuid", &Controller::get_obj_uuid)
		.def("get_obj_uuid_by_ptr", &Controller::get_obj_uuid_by_ptr)
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

namespace
{
	const ObjArrayMeta& checkedMeta(const Memory& mem, ObjType type)
	{
		const auto* meta = mem.getObjArrayMeta(type);
		if (meta == nullptr)
			throw std::invalid_argument("invalid object type");
		return *meta;
	}

	uint32_t boundedMaxSize(const ObjArrayMeta& meta)
	{
		return std::min(meta.maxSize, static_cast<uint32_t>(OBJ_UUID_SLOT_COUNT));
	}
}

uint32_t Controller::get_obj_array_ptr(ObjType type) const
{
	return checkedMeta(mem, type).dataArrayPtr;
}

uint32_t Controller::get_obj_block_ptr(ObjType type) const
{
	return checkedMeta(mem, type).blockPtr;
}

uint32_t Controller::get_obj_max_size(ObjType type) const
{
	return checkedMeta(mem, type).maxSize;
}

uint32_t Controller::get_obj_base_ptr(ObjType type, int64_t index) const
{
	const auto& meta = checkedMeta(mem, type);
	if (meta.blockPtr == 0 || index < 0 || static_cast<uint64_t>(index) >= boundedMaxSize(meta))
		return 0;
	return meta.blockPtr + getObjStride(type) * static_cast<uint32_t>(index);
}

uint32_t Controller::get_obj_base_ptr(const ObjUuid& uuid) const
{
	if (!uuid || !isValidObjType(uuid.fields.type))
		return 0;
	const auto& meta = *mem.getObjArrayMeta(uuid.fields.type);
	if (meta.blockPtr == 0 || uuid.fields.index >= boundedMaxSize(meta) ||
		meta.uuidCnt[uuid.fields.index] != uuid.fields.uuidCnt)
		return 0;
	return meta.blockPtr + getObjStride(uuid.fields.type) * uuid.fields.index;
}

ObjUuid Controller::get_obj_uuid(ObjType type, int64_t index) const
{
	const auto& meta = checkedMeta(mem, type);
	if (index < 0 || static_cast<uint64_t>(index) >= boundedMaxSize(meta))
		return {};
	return {meta.uuidCnt[index], static_cast<uint16_t>(index), type};
}

ObjUuid Controller::get_obj_uuid_by_ptr(ObjType type, uint32_t ptr) const
{
	const auto& meta = checkedMeta(mem, type);
	if (meta.blockPtr == 0 || ptr < meta.blockPtr)
		return {};
	const auto delta = ptr - meta.blockPtr;
	const auto stride = getObjStride(type);
	if (delta % stride != 0)
		return {};
	const auto index = delta / stride;
	if (index >= boundedMaxSize(meta))
		return {};
	return {meta.uuidCnt[index], static_cast<uint16_t>(index), type};
}

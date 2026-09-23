#include "Controller.h"
#include "MemoryException.h"
#include <utility>
#include <bit>
#include <cmath>
#include <limits>
#include <stdexcept>

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
	py::tuple objTypeInfo(OBJ_TYPE_INFO.size());
	for (size_t index = 0; index < OBJ_TYPE_INFO.size(); ++index)
		objTypeInfo[index] = py::cast(OBJ_TYPE_INFO[index]);
	m.attr("OBJ_TYPE_INFO") = std::move(objTypeInfo);

	py::native_enum<HookPosition>(m, "HookPosition", "enum.Enum")
		.value("MAIN_LOOP", HookPosition::MAIN_LOOP)
		.value("ZOMBIE_PICK_RANDOM_SPEED", HookPosition::ZOMBIE_PICK_RANDOM_SPEED)
		.value("CHALLENGE_I_ZOMBIE_SCORE_BRAIN", HookPosition::CHALLENGE_I_ZOMBIE_SCORE_BRAIN)
		.value("CHALLENGE_I_ZOMBIE_PLACE_PLANTS", HookPosition::CHALLENGE_I_ZOMBIE_PLACE_PLANTS)
		.finalize();

	py::native_enum<RndHook>(m, "RndHook", "enum.Enum")
		.value("ZOMBIE_JACK_COUNTDOWN", RndHook::ZOMBIE_JACK_COUNTDOWN)
		.value("ZOMBIE_JACK_EARLY_EXPLOSION", RndHook::ZOMBIE_JACK_EARLY_EXPLOSION)
		.value("ZOMBIE_SPAWN_OTHER", RndHook::ZOMBIE_SPAWN_OTHER)
		.value("ZOMBIE_SPAWN_POLE", RndHook::ZOMBIE_SPAWN_POLE)
		.value("ZOMBIE_SPAWN_ZAMBONI", RndHook::ZOMBIE_SPAWN_ZAMBONI)
		.value("ZOMBIE_SPAWN_CATAPULT", RndHook::ZOMBIE_SPAWN_CATAPULT)
		.value("ZOMBIE_SPAWN_GARGANTUAR", RndHook::ZOMBIE_SPAWN_GARGANTUAR)
		.value("ZOMBIE_GARLIC_DIRECTION", RndHook::ZOMBIE_GARLIC_DIRECTION)
		.value("ZOMBIE_JALAPENO_COUNTDOWN", RndHook::ZOMBIE_JALAPENO_COUNTDOWN)
		.value("ZOMBIE_BUNGEE_HEIGHT", RndHook::ZOMBIE_BUNGEE_HEIGHT)
		.value("ZOMBIE_DANCER_SLIDE", RndHook::ZOMBIE_DANCER_SLIDE)
		.value("ZOMBIE_YETI_ESCAPE", RndHook::ZOMBIE_YETI_ESCAPE)
		.value("ZOMBIE_POGO_INITIAL", RndHook::ZOMBIE_POGO_INITIAL)
		.value("BOARD_LOOT", RndHook::BOARD_LOOT)
		.value("ZOMBIE_FREEZE_FIRST", RndHook::ZOMBIE_FREEZE_FIRST)
		.value("ZOMBIE_FREEZE_REPEAT", RndHook::ZOMBIE_FREEZE_REPEAT)
		.value("BOARD_WAVE_COUNTDOWN", RndHook::BOARD_WAVE_COUNTDOWN)
		.value("BOARD_SUN_INTERVAL", RndHook::BOARD_SUN_INTERVAL)
		.value("PLANT_KERNEL_BUTTER", RndHook::PLANT_KERNEL_BUTTER)
		.value("PLANT_BOWLING_DIRECTION", RndHook::PLANT_BOWLING_DIRECTION)
		.value("PLANT_PRODUCTION_INITIAL", RndHook::PLANT_PRODUCTION_INITIAL)
		.value("PLANT_PRODUCTION_INTERVAL", RndHook::PLANT_PRODUCTION_INTERVAL)
		.value("PLANT_ATTACK_INITIAL", RndHook::PLANT_ATTACK_INITIAL)
		.value("PLANT_ATTACK_INTERVAL", RndHook::PLANT_ATTACK_INTERVAL)
		.value("CHALLENGE_IZE_PLANT_REDUCTION", RndHook::CHALLENGE_IZE_PLANT_REDUCTION)
		.value("BOARD_ACTIVATION_RATIO", RndHook::BOARD_ACTIVATION_RATIO)
		.value("ZOMBIE_SPEED_JACK", RndHook::ZOMBIE_SPEED_JACK)
		.value("ZOMBIE_SPEED_LADDER", RndHook::ZOMBIE_SPEED_LADDER)
		.value("ZOMBIE_SPEED_DOLPHIN", RndHook::ZOMBIE_SPEED_DOLPHIN)
		.value("ZOMBIE_SPEED_NORMAL", RndHook::ZOMBIE_SPEED_NORMAL)
		.finalize();

	m.attr("RND_EXACT_CAPACITY") = py::int_(RND_EXACT_CAPACITY);

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
		.def("get_obj_next_uuid_cnt", &Controller::get_obj_next_uuid_cnt)
		.def("get_obj_base_ptr",
			py::overload_cast<ObjType, int64_t>(&Controller::get_obj_base_ptr, py::const_),
			py::arg("type"), py::arg("index"))
		.def("get_obj_base_ptr",
			py::overload_cast<const ObjUuid&>(&Controller::get_obj_base_ptr, py::const_),
			py::arg("uuid"))
		.def("get_obj_uuid", &Controller::get_obj_uuid)
		.def("get_obj_uuid_by_ptr", &Controller::get_obj_uuid_by_ptr)
		.def("rnd_set", &Controller::rnd_set,
			py::arg("hook"), py::arg("uuid"), py::arg("value"))
		.def("rnd_get", &Controller::rnd_get,
			py::arg("hook"), py::arg("uuid"))
		.def("rnd_remove", &Controller::rnd_remove,
			py::arg("hook"), py::arg("uuid"))
		.def("rnd_set_default", &Controller::rnd_set_default,
			py::arg("hook"), py::arg("value"))
		.def("rnd_get_default", &Controller::rnd_get_default, py::arg("hook"))
		.def("rnd_enabled", &Controller::rnd_enabled, py::arg("hook"))
		.def("rnd_clear", &Controller::rnd_clear, py::arg("hook") = std::nullopt)
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

	size_t checkedRndHookIndex(RndHook hook)
	{
		const auto index = static_cast<size_t>(hook);
		if (index >= RND_HOOK_COUNT)
			throw py::value_error("invalid RndHook");
		return index;
	}

	const RndHookInfo& checkedRndHookInfo(RndHook hook)
	{
		return RND_HOOK_INFO[checkedRndHookIndex(hook)];
	}

	void checkedRndUuid(RndHook hook, const ObjUuid& uuid)
	{
		const auto& info = checkedRndHookInfo(hook);
		if (info.target != RndTarget::Plant && info.target != RndTarget::Zombie)
			throw py::value_error("this RndHook does not accept an object UUID");
		if (!uuid || uuid.fields.index >= OBJ_UUID_SLOT_COUNT ||
			!isValidObjType(uuid.fields.type))
			throw py::value_error("invalid object UUID");
		const auto expectedType = info.target == RndTarget::Plant
			? ObjType::Plant
			: ObjType::Zombie;
		if (uuid.fields.type != expectedType)
			throw py::value_error("UUID type does not match RndHook target");
	}

	int32_t parseRndI32(const py::object& value)
	{
		PyObject* indexObject = PyNumber_Index(value.ptr());
		if (indexObject == nullptr)
		{
			throw py::error_already_set();
		}
		py::object index = py::reinterpret_steal<py::object>(indexObject);
		int overflow = 0;
		const auto parsed = PyLong_AsLongLongAndOverflow(index.ptr(), &overflow);
		if (overflow != 0 || PyErr_Occurred())
		{
			PyErr_Clear();
			throw std::overflow_error("integer RND value is outside the int32 range");
		}
		if (parsed < std::numeric_limits<int32_t>::min() ||
			parsed > std::numeric_limits<int32_t>::max())
			throw std::overflow_error("integer RND value is outside the int32 range");
		return static_cast<int32_t>(parsed);
	}

	float parseRndF32(const py::object& value)
	{
		double parsed;
		if (PyFloat_Check(value.ptr()))
		{
			parsed = PyFloat_AsDouble(value.ptr());
			if (PyErr_Occurred())
			{
				PyErr_Clear();
				throw py::value_error("invalid floating-point RND value");
			}
		}
		else if (PyLong_Check(value.ptr()))
		{
			parsed = PyLong_AsDouble(value.ptr());
			if (PyErr_Occurred())
			{
				PyErr_Clear();
				throw std::overflow_error("floating-point RND value is outside the Python float range");
			}
		}
		else
			throw py::type_error("floating-point RND values must be int or float");

		if (!std::isfinite(parsed))
			throw py::value_error("floating-point RND values must be finite");
		const auto narrowed = static_cast<float>(parsed);
		if (!std::isfinite(narrowed))
			throw std::overflow_error("floating-point RND value is outside the fp32 range");
		return narrowed;
	}

	uint32_t encodeRndValue(RndHook hook, const py::object& value)
	{
		const auto kind = checkedRndHookInfo(hook).valueKind;
		if (kind == RndValueKind::I32)
			return std::bit_cast<uint32_t>(parseRndI32(value));
		return std::bit_cast<uint32_t>(parseRndF32(value));
	}

	py::object decodeRndValue(RndHook hook, uint32_t bits)
	{
		const auto kind = checkedRndHookInfo(hook).valueKind;
		if (kind == RndValueKind::I32)
			return py::int_(std::bit_cast<int32_t>(bits));
		return py::float_(std::bit_cast<float>(bits));
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

uint32_t Controller::get_obj_next_uuid_cnt(ObjType type) const
{
	return checkedMeta(mem, type).nextUuidCnt;
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

void Controller::rnd_set(RndHook hook, const ObjUuid& uuid, py::object value)
{
	checkedRndUuid(hook, uuid);
	const auto bits = encodeRndValue(hook, value);
	mem.rndSet(hook, uuid, bits);
}

py::object Controller::rnd_get(RndHook hook, const ObjUuid& uuid) const
{
	checkedRndUuid(hook, uuid);
	const auto bits = mem.rndGet(hook, uuid);
	if (!bits.has_value())
		return py::none();
	return decodeRndValue(hook, *bits);
}

bool Controller::rnd_remove(RndHook hook, const ObjUuid& uuid)
{
	checkedRndUuid(hook, uuid);
	return mem.rndRemove(hook, uuid);
}

void Controller::rnd_set_default(RndHook hook, py::object value)
{
	checkedRndHookInfo(hook);
	if (value.is_none())
	{
		mem.rndSetDefault(hook, std::nullopt);
		return;
	}
	mem.rndSetDefault(hook, encodeRndValue(hook, value));
}

py::object Controller::rnd_get_default(RndHook hook) const
{
	checkedRndHookInfo(hook);
	const auto bits = mem.rndGetDefault(hook);
	if (!bits.has_value())
		return py::none();
	return decodeRndValue(hook, *bits);
}

bool Controller::rnd_enabled(RndHook hook) const
{
	checkedRndHookInfo(hook);
	return mem.rndEnabled(hook);
}

void Controller::rnd_clear(std::optional<RndHook> hook)
{
	if (hook.has_value())
		checkedRndHookInfo(*hook);
	mem.rndClear(hook);
}

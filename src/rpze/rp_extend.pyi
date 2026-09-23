# -*- coding: utf_8 -*-
# extend module of game controller
from enum import Enum
from typing import Self, overload


class HookPosition(Enum):
    MAIN_LOOP = 0
    # the main hook of the project
    # do not open / close it manually, use Controller.start()/.end() instead
    ZOMBIE_PICK_RANDOM_SPEED = 1  # useless
    CHALLENGE_I_ZOMBIE_SCORE_BRAIN = 2
    # open to disable 0x42B8B0 (disable := do nothing and return)
    CHALLENGE_I_ZOMBIE_PLACE_PLANTS = 3
    # open to disable 0x42A6C0

class RndHook(Enum):
    ZOMBIE_JACK_COUNTDOWN = 0
    ZOMBIE_JACK_EARLY_EXPLOSION = 1
    ZOMBIE_SPAWN_OTHER = 2
    ZOMBIE_SPAWN_POLE = 3
    ZOMBIE_SPAWN_ZAMBONI = 4
    ZOMBIE_SPAWN_CATAPULT = 5
    ZOMBIE_SPAWN_GARGANTUAR = 6
    ZOMBIE_GARLIC_DIRECTION = 7
    ZOMBIE_JALAPENO_COUNTDOWN = 8
    ZOMBIE_BUNGEE_HEIGHT = 9
    ZOMBIE_DANCER_SLIDE = 10
    ZOMBIE_YETI_ESCAPE = 11
    ZOMBIE_POGO_INITIAL = 12
    BOARD_LOOT = 13
    ZOMBIE_FREEZE_FIRST = 14
    ZOMBIE_FREEZE_REPEAT = 15
    BOARD_WAVE_COUNTDOWN = 16
    BOARD_SUN_INTERVAL = 17
    PLANT_KERNEL_BUTTER = 18
    PLANT_BOWLING_DIRECTION = 19
    PLANT_PRODUCTION_INITIAL = 20
    PLANT_PRODUCTION_INTERVAL = 21
    PLANT_ATTACK_INITIAL = 22
    PLANT_ATTACK_INTERVAL = 23
    CHALLENGE_IZE_PLANT_REDUCTION = 24
    BOARD_ACTIVATION_RATIO = 25
    ZOMBIE_SPEED_JACK = 26
    ZOMBIE_SPEED_LADDER = 27
    ZOMBIE_SPEED_DOLPHIN = 28
    ZOMBIE_SPEED_NORMAL = 29


class SyncMethod(Enum):
    SPIN = 1  # better performance for testing
    MUTEX = 2  # better performance for normal case like modifier


class ObjType(Enum):
    # object category used by the object and UUID APIs
    PLANT = 0
    ZOMBIE = 1
    PROJECTILE = 2
    GRID_ITEM = 3

    @property
    def ITEM_SIZE(self) -> int: ...  # object payload size in bytes; a slot is ITEM_SIZE + 4

    @property
    def BOARD_ARRAY_OFFSET(self) -> int: ...  # offset of this object's array from Board


class ObjTypeInfo:
    # layout metadata for one object category

    @property
    def ITEM_SIZE(self) -> int: ...  # object payload size in bytes; a slot is ITEM_SIZE + 4

    @property
    def BOARD_ARRAY_OFFSET(self) -> int: ...  # offset of this object's array from Board


class ObjUuid:
    # identifies an allocation by type, slot, and generation; zero uuid_cnt is invalid
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, uuid_cnt: int, index: int, type: ObjType) -> None: ...

    @property
    def uuid_cnt(self) -> int: ...  # per-type generation counter; changes when a slot is reused

    @property
    def index(self) -> int: ...  # slot index in the type's object block

    @property
    def type(self) -> ObjType: ...  # object category of this UUID

    @property
    def value(self) -> int: ...  # packed 64-bit UUID value

    def __bool__(self) -> bool: ...  # true when uuid_cnt is nonzero

    def __int__(self) -> int: ...  # return the packed 64-bit value

    def __eq__(self, other: Self, /) -> bool: ...  # compare packed UUID values

    def __hash__(self) -> int: ...  # hash the packed UUID value

    def __repr__(self) -> str: ...  # return a field-oriented representation


OBJ_UUID_SLOT_COUNT: int  # number of UUID slots tracked per object type
OBJ_TYPE_INFO: tuple[ObjTypeInfo, ...]  # layout metadata in ObjType order
RND_EXACT_CAPACITY: int  # maximum number of exact UUID entries


class RpBaseException(Exception): ...


class ControllerError(RpBaseException): ...


class Controller:
    # game controller

    # in the description of this class:
    #     connected := using start(), which means hook_connected(HookPosition.MAIN_LOOP) is True
    #     prepared := hook connected and before() used properly

    def __init__(self, pid: int, /) -> None: ...

    def __eq__(self, other: Self, /) -> bool: ...

    def __ne__(self, other: Self, /) -> bool: ...

    def __repr__(self) -> str: ...

    @property
    def result_mem(self) -> memoryview: ...  # a free piece of shared memory

    @property
    def result_address(self) -> int: ...  # the address of result_mem in game

    # value of result_mem, same as *(T*)result_address
    result_bool: bool
    result_f32: float
    result_f64: float
    result_i8: int
    result_i16: int
    result_i32: int
    result_i64: int
    result_u8: int
    result_u16: int
    result_u32: int
    result_u64: int

    sync_method: SyncMethod  # default: SyncMethod.MUTEX, cannot change when connected
    jumping_sync_method: SyncMethod  # default: SyncMethod.SPIN , cannot change when jumping frame

    @property
    def asm_address(self) -> int: ...  # start addr of where run_code would be executed

    @property
    def pid(self) -> int: ...  # game process id

    def skip_frames(self, num: int = 1) -> None: ...  # assert prepared; skip {num} frames and get prepared

    def before(self) -> None: ...  # required before every frame after start() control

    def next_frame(self) -> None: ...  # let the game continue to the next frame

    def start(self) -> None: ...  # start control and get prepared; do nothing when connected

    def end(self) -> None: ...
    # assert prepared; end control (end jumping frame if necessary); do nothing when not connected

    def start_jump_frame(self) -> bool: ...
    # assert prepared and has board
    # return False if already jumping

    def is_jumping_frame(self) -> bool: ...

    def end_jump_frame(self) -> bool: ...  # assert prepared; return False if not jumping, skip a frame

    def get_p_board(self) -> tuple[bool, int]: ...  # return (is_p_board_new, p_board)

    def get_obj_array_ptr(self, type: ObjType, /) -> int: ...  # address of the game's object array, or 0 when unavailable

    def get_obj_block_ptr(self, type: ObjType, /) -> int: ...  # address of its object block, or 0 when unavailable

    def get_obj_max_size(self, type: ObjType, /) -> int: ...  # maximum slot count reported by the game; UUID lookups cap at OBJ_UUID_SLOT_COUNT

    def get_obj_next_uuid_cnt(self, type: ObjType, /) -> int: ...  # authoritative next UUID counter for this type; preserved without a Board

    @overload
    def get_obj_base_ptr(self, type: ObjType, index: int, /) -> int: ...  # slot address, or 0 if unavailable or out of range

    @overload
    def get_obj_base_ptr(self, uuid: ObjUuid, /) -> int: ...  # current slot address, or 0 for an invalid or stale UUID

    def get_obj_uuid(self, type: ObjType, index: int, /) -> ObjUuid: ...  # UUID for a slot, or invalid if out of range or unused

    def get_obj_uuid_by_ptr(self, type: ObjType, ptr: int, /) -> ObjUuid: ...  # UUID for an exact slot address, or invalid if unmatched or unused

    def rnd_set(self, hook: RndHook, uuid: ObjUuid, value: int | float) -> None: ...

    def rnd_get(self, hook: RndHook, uuid: ObjUuid) -> int | float | None: ...

    def rnd_remove(self, hook: RndHook, uuid: ObjUuid) -> bool: ...

    def rnd_set_default(self, hook: RndHook, value: int | float | None) -> None: ...

    def rnd_get_default(self, hook: RndHook) -> int | float | None: ...

    def rnd_enabled(self, hook: RndHook) -> bool: ...

    def rnd_clear(self, hook: RndHook | None = None) -> None: ...

    def run_code(self, asm_bytes: bytes, /) -> bool: ...  # assert prepared; return False if failed

    def open_hook(self, hook: HookPosition, /) -> None: ...

    def close_hook(self, hook: HookPosition, /) -> None: ...

    def hook_connected(self, hook: HookPosition = HookPosition.MAIN_LOOP) -> bool: ...

    def global_connected(self) -> bool: ...  # return False if game is closed

    # fall back to use ReadProcessMemory & WriteProcessMemory when force_remote or not_prepared
    # *args for offsets
    # return None(read_... funcs) or False(write_... funcs) when reading nullptr
    # the game will crash when reading wild pointers
    def read_bool(self, *args: int, force_remote: bool = False) -> bool | None: ...

    def read_f32(self, *args: int, force_remote: bool = False) -> float | None: ...

    def read_f64(self, *args: int, force_remote: bool = False) -> float | None: ...

    def read_i8(self, *args: int, force_remote: bool = False) -> int | None: ...

    def read_i16(self, *args: int, force_remote: bool = False) -> int | None: ...

    def read_i32(self, *args: int, force_remote: bool = False) -> int | None: ...

    def read_i64(self, *args: int, force_remote: bool = False) -> int | None: ...

    def read_u8(self, *args: int, force_remote: bool = False) -> int | None: ...

    def read_u16(self, *args: int, force_remote: bool = False) -> int | None: ...

    def read_u32(self, *args: int, force_remote: bool = False) -> int | None: ...

    def read_u64(self, *args: int, force_remote: bool = False) -> int | None: ...

    def read_bytes(self, size: int, *args: int, force_remote: bool = False) -> bytes | None: ...


    def write_bool(self, value: bool, *args: int, force_remote: bool = False) -> bool: ...

    def write_f32(self, value: float, *args: int, force_remote: bool = False) -> bool: ...

    def write_f64(self, value: float, *args: int, force_remote: bool = False) -> bool: ...

    def write_i8(self, value: int, *args: int, force_remote: bool = False) -> bool: ...

    def write_i16(self, value: int, *args: int, force_remote: bool = False) -> bool: ...

    def write_i32(self, value: int, *args: int, force_remote: bool = False) -> bool: ...

    def write_i64(self, value: int, *args: int, force_remote: bool = False) -> bool: ...

    def write_u8(self, value: int, *args: int, force_remote: bool = False) -> bool: ...

    def write_u16(self, value: int, *args: int, force_remote: bool = False) -> bool: ...

    def write_u32(self, value: int, *args: int, force_remote: bool = False) -> bool: ...

    def write_u64(self, value: int, *args: int, force_remote: bool = False) -> bool: ...

    def write_bytes(self, value: bytes, *args: int, force_remote: bool = False) -> bool: ...

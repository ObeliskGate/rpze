# -*- coding: utf_8 -*-
# extend module of game controller
from enum import Enum
from typing import Self


class HookPosition(Enum):
    MAIN_LOOP = 0
    ZOMBIE_PICK_RANDOM_SPEED = 1  # useless
    CHALLENGE_I_ZOMBIE_SCORE_BRAIN = 2
    CHALLENGE_I_ZOMBIE_PLACE_PLANTS = 3


class SyncMethod(Enum):
    SPIN = 1  # better performance for testing
    MUTEX = 2  # better performance for normal use


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
    # skip a frame and get prepared
    def is_jumping_frame(self) -> bool: ...

    def end_jump_frame(self) -> bool: ...  # assert prepared; return False if not jumping

    def get_p_board(self) -> tuple[bool, int]: ...  # return (is_p_board_new, p_board)

    def run_code(self, asm_bytes: bytes, /) -> bool: ...  # assert prepared; return False if failed

    def open_hook(self, hook: HookPosition, /) -> None: ...

    def close_hook(self, hook: HookPosition, /) -> None: ...

    def hook_connected(self, hook: HookPosition = HookPosition.MAIN_LOOP) -> bool: ...

    def global_connected(self) -> bool: ...  # return False if game is closed

    # fall back to use ReadProcessMemory & WriteProcessMemory when not prepared
    # *args for offsets
    def read_bool(self, *args: int) -> bool | None: ...

    def read_f32(self, *args: int) -> float | None: ...

    def read_f64(self, *args: int) -> float | None: ...

    def read_i8(self, *args: int) -> int | None: ...

    def read_i16(self, *args: int) -> int | None: ...

    def read_i32(self, *args: int) -> int | None: ...

    def read_i64(self, *args: int) -> int | None: ...

    def read_u8(self, *args: int) -> int | None: ...

    def read_u16(self, *args: int) -> int | None: ...

    def read_u32(self, *args: int) -> int | None: ...

    def read_u64(self, *args: int) -> int | None: ...

    def read_bytes(self, size: int, *args: int) -> bytes | None: ...

    def write_bool(self, value: bool, *args: int) -> bool: ...

    def write_f32(self, value: float, *args: int) -> bool: ...

    def write_f64(self, value: float, *args: int) -> bool: ...

    def write_i8(self, value: int, *args: int) -> bool: ...

    def write_i16(self, value: int, *args: int) -> bool: ...

    def write_i32(self, value: int, *args: int) -> bool: ...

    def write_i64(self, value: int, *args: int) -> bool: ...

    def write_u8(self, value: int, *args: int) -> bool: ...

    def write_u16(self, value: int, *args: int) -> bool: ...

    def write_u32(self, value: int, *args: int) -> bool: ...

    def write_u64(self, value: int, *args: int) -> bool: ...

    def write_bytes(self, value: bytes, *args: int) -> bool: ...

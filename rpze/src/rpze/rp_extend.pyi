# -*- coding: utf_8 -*- 
from __future__ import annotations

__all__ = ['HookPosition', 'Controller']

from enum import Enum
from typing import Self


class HookPosition(Enum):
    MAIN_LOOP = 0,
    ZOMBIE_PICK_RANDOM_SPEED = 1,
    CHALLENGE_I_ZOMBIE_SCORE_BRAIN = 2
    

class Controller:
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

    @property
    def result_address(self) -> int: ...
    @property
    def asm_address(self) -> int: ...
    @property
    def pid(self) -> int: ...

    def __init__(self, pid: int) -> None: ...
    def __eq__(self, other: Self) -> bool: ...
    def __ne__(self, other: Self) -> bool: ...

    def before(self) -> None: ...
    def next_frame(self) -> None: ...
    def start(self) -> None: ...
    def end(self) -> None: ...
    def start_jump_frame(self) -> bool: ...
    def end_jump_frame(self) -> bool: ...
    def get_p_board(self) -> tuple[bool, int]: ...
    def run_code(self, asm_bytes: bytes) -> bool: ...
    def open_hook(self, hook: HookPosition) -> None: ...
    def close_hook(self, hook: HookPosition) -> None: ...
    def hook_connected(self, hook: HookPosition = HookPosition.MAIN_LOOP) -> bool: ...
    
    def read_bool(self, offsets: list[int]) -> bool | None: ...
    def read_f32(self, offsets: list[int]) -> float | None: ...
    def read_f64(self, offsets: list[int]) -> float | None: ...
    def read_i8(self, offsets: list[int]) -> int | None: ...
    def read_i16(self, offsets: list[int]) -> int | None: ...
    def read_i32(self, offsets: list[int]) -> int | None: ...
    def read_i64(self, offsets: list[int]) -> int | None: ...
    def read_u8(self, offsets: list[int]) -> int | None: ...
    def read_u16(self, offsets: list[int]) -> int | None: ...
    def read_u32(self, offsets: list[int]) -> int | None: ...
    def read_u64(self, offsets: list[int]) -> int | None: ...
    def read_bytes(self, size: int, offsets: list[int]) -> bytes | None: ...
    
    def write_bool(self, value: bool, offsets: list[int]) -> bool: ...
    def write_f32(self, value: float, offsets: list[int]) -> bool: ...
    def write_f64(self, value: float, offsets: list[int]) -> bool: ...
    def write_i8(self, value: int, offsets: list[int]) -> bool: ...
    def write_i16(self, value: int, offsets: list[int]) -> bool: ...
    def write_i32(self, value: int, offsets: list[int]) -> bool: ...
    def write_i64(self, value: int, offsets: list[int]) -> bool: ...
    def write_u8(self, value: int, offsets: list[int]) -> bool: ...
    def write_u16(self, value: int, offsets: list[int]) -> bool: ...
    def write_u32(self, value: int, offsets: list[int]) -> bool: ...
    def write_u64(self, value: int, offsets: list[int]) -> bool: ...
    def write_bytes(self, value: bytes, offsets: list[int]) -> bool: ...
from __future__ import annotations
import typing
__all__ = ['Controller']
class Controller:
    def __init__(self, pid: int) -> None:
        ...
    def before(self) -> None:
        ...
    def next_frame(self) -> None:
        ...
    def start(self) -> None:
        ...
    def end(self) -> None:
        ...
    def start_jump_frame(self) -> bool:
        ...
    def end_jump_frame(self) -> bool:
        ...
    def get_time(self) -> int:
        ...
    def run_code(self, asm_code: bytes, code_length: int) -> bool:
        ...
    
    def read_bool(self, offsets: list[int]) -> bool | None:
        ...
    def read_f32(self, offsets: list[int]) -> float | None:
        ...
    def read_f64(self, offsets: list[int]) -> float | None:
        ...
    def read_i8(self, offsets: list[int]) -> int | None:
        ...
    def read_i16(self, offsets: list[int]) -> int | None:
        ...
    def read_i32(self, offsets: list[int]) -> int | None:
        ...
    def read_i64(self, offsets: list[int]) -> int | None:
        ...
    def read_u8(self, offsets: list[int]) -> int | None:
        ...
    def read_u16(self, offsets: list[int]) -> int | None:
        ...
    def read_u32(self, offsets: list[int]) -> int | None:
        ...
    def read_u64(self, offsets: list[int]) -> int | None:
        ...
    
    def write_bool(self, value: bool, offsets: list[int]) -> bool:
        ...
    def write_f32(self, value: float, offsets: list[int]) -> bool:
        ...
    def write_f64(self, value: float, offsets: list[int]) -> bool:
        ...
    def write_i8(self, value: int, offsets: list[int]) -> bool:
        ...
    def write_i16(self, value: int, offsets: list[int]) -> bool:
        ...
    def write_i32(self, value: int, offsets: list[int]) -> bool:
        ...
    def write_i64(self, value: int, offsets: list[int]) -> bool:
        ...
    def write_u8(self, value: int, offsests: list[int]) -> bool:
        ...
    def write_u16(self, value: int, offsests: list[int]) -> bool:
        ...
    def write_u32(self, value: int, offsests: list[int]) -> bool:
        ...
    def write_u64(self, value: int, offsests: list[int]) -> bool:
        ...
    @property
    def result_address(self) -> int:
        ...
    @property
    def result_bool(self) -> bool:
        ...
    @property
    def result_f32(self) -> float:
        ...
    @property
    def result_f64(self) -> float:
        ...
    @property
    def result_i8(self) -> int:
        ...
    @property
    def result_i16(self) -> int:
        ...
    @property
    def result_i32(self) -> int:
        ...
    @property
    def result_i64(self) -> int:
        ...
    @property
    def result_u8(self) -> int:
        ...
    @property
    def result_u16(self) -> int:
        ...
    @property
    def result_u32(self) -> int:
        ...
    @property
    def result_u64(self) -> int:
        ...
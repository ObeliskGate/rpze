# -*- coding: utf_8 -*-
"""
场地物品相关的枚举和类
"""
from enum import IntEnum
from typing import Self

from .obj_base import ObjNode, property_int_enum, property_i32, property_bool, property_f32, obj_list
from ..basic import asm


class GriditemType(IntEnum):
    """
    场地物品类型
    """
    none = 0
    grave = 0x1
    crater = 0x2
    ladder = 0x3
    brain_aq = 0x6
    vase = 0x7
    rake = 0xb
    brain = 0xc


class Griditem(ObjNode):
    """
    场地物品. 包括脑子, 梯子等
    """
    OBJ_SIZE = 0xEC

    ITERATOR_FUNC_ADDRESS = 0x41CAD0

    type_ = property_int_enum(0x8, GriditemType, "场地物品类型")

    row = property_i32(0x14, "所在行")

    col = property_i32(0x10, "所在列")

    brain_hp = property_i32(0x18, """
        脑子血量, 墓碑冒出的量, 弹坑消失倒计时, 钉钯消失倒计时
        
        对于 ize 中脑子, 初始为70, 每次被啃时-= 1(区别于植物血量 -= 4)
        """)

    layer = property_i32(0x1c, "图层")

    is_dead = property_bool(0x20, "是否死亡")

    x = property_f32(0x24, "x 坐标")

    y = property_f32(0x28, "y 坐标")

    def __str__(self) -> str:
        if not self.is_dead:
            return f"#{self.id.index} {self.type_.name} at {self.row + 1}-{self.col + 1}"
        return "dead griditem"

    def die(self) -> None:
        """
        令自己死亡
        """
        code = f"""
            push esi
            mov esi, {self.base_ptr}
            call {0x44D000}  // Griditem::GriditemDie
            ret"""
        asm.run(code, self.controller)


class GriditemList(obj_list(Griditem)):
    """
    场地物品 DataArray
    """
    def alloc_item(self) -> Griditem:
        """
        从内存数组中申请新的 griditem 对象

        Returns:
            申请出的 Griditem 对象
        """
        code = f"""
            push esi
            mov esi, {self.base_ptr}
            call {0x41E1C0}  // DataArray<GridItem>::DataArrayAlloc
            mov [{self.controller.result_address}], eax
            pop esi
            ret"""
        asm.run(code, self.controller)
        return Griditem(self.controller.result_u32, self.controller)

    def free_all(self) -> Self:
        code = f"""
                push edi
                push esi
                mov eax, [0x6a9ec0]
                mov edi, [eax + 0x768]
                mov esi, {self.controller.result_address}
                xor edx, edx
                mov [esi], edx
                LIterate:
                    mov {Griditem.ITERATOR_P_BOARD_REG}, edi
                    call {Griditem.ITERATOR_FUNC_ADDRESS}  // Board::IterateGriditem
                    test al, al
                    jz LFreeAll
                    mov esi, [esi]
                    call {0x44D000}  // Griditem::GriditemDie
                    mov esi, {self.controller.result_address}
                    jmp LIterate
                    
                LFreeAll:
                    mov eax, {self.base_ptr}
                    call {0x41E7D0}  // DataArray<Griditem>::DataArrayFreeAll
                    pop esi
                    pop edi
                    ret"""
        asm.run(code, self.controller)
        return self

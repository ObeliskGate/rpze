# -*- coding: utf_8 -*-
"""
场地物品相关的枚举和类
"""
from enum import IntEnum
from typing import Self

from . import obj_base as ob
from ..basic import asm


class GriditemType(IntEnum):
    none = 0,
    grave = 0x1,
    crater = 0x2,
    ladder = 0x3,
    brain_aq = 0x6,
    vase = 0x7,
    rake = 0xb,
    brain = 0xc


class Griditem(ob.ObjNode):
    """
    场地物品, 包括脑子, 梯子等
    """
    OBJ_SIZE = 0xEC

    ITERATOR_FUNC_ADDRESS = 0x41CAD0

    type_ = ob.property_int_enum(0x8, GriditemType, "场地物品类型")

    row = ob.property_i32(0x14, "所在行")

    col = ob.property_i32(0x10, "所在列")

    brain_hp = ob.property_i32(0x18, """
        脑子血量, 墓碑冒出的量, 弹坑消失倒计时, 钉钯消失倒计时
        
        对于ize中脑子, 初始为70, 每次被啃时-= 1(区别于植物血量 -= 4)
        """)

    layer = ob.property_i32(0x1c, "图层")

    x = ob.property_f32(0x24, "x坐标")

    y = ob.property_f32(0x28, "y坐标")

    def __str__(self):
        return f"#{self.id.index} {self.type_.name} at {self.row + 1}-{self.col + 1}"

    def die(self):
        """
        令自己死亡
        """
        code = f"""
            push esi;
            mov esi, {self.base_ptr};
            call {0x44D000}  // Griditem::GriditemDie
            ret;"""
        asm.run(code, self._controller)


class GriditemList(ob.obj_list(Griditem)):
    def alloc_item(self) -> Griditem:
        """
        从内存数组中申请新的griditem对象

        Returns:
            申请出的Griditem对象
        """
        code = f"""
            push esi;
            mov esi, {self.base_ptr};
            call {0x41E1C0};  // DataArray<GridItem>::DataArrayAlloc
            mov [{self._controller.result_address}], eax;
            pop esi;
            ret;"""
        asm.run(code, self._controller)
        return Griditem(self._controller.result_u32, self._controller)

    def free_all(self) -> Self:
        p_board = self._controller.get_p_board()[1]
        code = f"""
                push ebx;
                push edi;
                push esi;
                mov edi, {p_board};
                mov ebx, {self._controller.result_address}
                mov esi, ebx;
                xor edx, edx;
                mov [esi], edx;
                LIterate:
                    mov {Griditem.ITERATOR_P_BOARD_REG}, edi;
                    call {Griditem.ITERATOR_FUNC_ADDRESS};  // Board::IterateGriditem
                    test al, al;
                    jz LFreeAll;
                    mov esi, [esi];
                    call {0x44D000};  // Griditem::GriditemDie
                    mov esi, ebx;
                    jmp LIterate;
                    
                LFreeAll:
                    mov eax, {self.base_ptr}
                    call {0x41E7D0};  // DataArray<Griditem>::DataArrayFreeAll
                    pop esi;
                    pop edi;
                    pop ebx;
                    ret;"""
        asm.run(code, self._controller)
        return self

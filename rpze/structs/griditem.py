# -*- coding: utf_8 -*-
"""
场地物品相关的枚举和类
"""
from enum import IntEnum

import structs.obj_base as ob
from basic import asm


class GriditemType(IntEnum):
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

    type_: GriditemType = ob.property_int_enum(0x8, GriditemType, "场地物品类型")

    row: int = ob.property_i32(0x14, "所在行")

    col: int = ob.property_i32(0x10, "所在列")

    brain_hp: int = ob.property_i32(0x18, """
        脑子血量, 墓碑冒出的量, 弹坑消失倒计时, 钉钯消失倒计时
        
        对于ize中脑子, 初始为70, 每次被啃时-= 1(区别于植物血量 -= 4)
        """)

    layer: int = ob.property_i32(0x1c, "图层")

    x: float = ob.property_f32(0x24, "x坐标")

    y: float = ob.property_f32(0x28, "y坐标")

    def __str__(self):
        return f"#{self.id.index} {self.type_.name} at {self.row + 1}-{self.col + 1}"


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
            mov edx, {0x41E1C0};  // DataArray<GridItem>::DataArrayAlloc
            call edx;
            mov [{self._controller.result_address}], eax;
            pop esi;
            ret;"""
        asm.run(code, self._controller)
        return Griditem(self._controller.result_u32, self._controller)

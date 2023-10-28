# -*- coding: utf_8 -*-
"""
场地物品相关的枚举和类
"""
from enum import IntEnum

import structs.obj_base as ob
from rp_extend import Controller


class GriditemType(IntEnum):
    grave = 0x1,
    crater = 0x2,
    ladder = 0x3,
    brain = 0x6,
    vase = 0x7,
    rake = 0xB


class Griditem(ob.ObjNode):
    """
    场地物品, 包括脑子, 弹坑, 梯子等
    """
    OBJ_SIZE = 0xEC

    ITERATOR_FUNC_ADDRESS = 0x41CAD0

    type_: GriditemType = ob.property_int_enum(0x8, GriditemType, "场地物品类型")

    row: int = ob.property_i32(0x14, "所在行")

    col: int = ob.property_i32(0x10, "所在列")

    brain_hp: int = ob.property_i32(0x18, "脑子血量")


class GriditemList(ob.obj_list(Griditem)):
    pass


def get_griditem_list(ctler: Controller) -> GriditemList:
    if (t := ctler.read_i32([0x6a9ec0, 0x768])) is None:
        raise RuntimeError("game base ptr not found")
    else:
        return GriditemList(t + 0x11c, ctler)
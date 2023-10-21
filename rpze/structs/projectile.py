# -*- coding: utf_8 -*- 
from enum import IntEnum

import basic.asm as asm
import structs.obj_base as ob
from rp_extend import Controller
from structs.obj_base import ObjNode, ObjId

class ProjectileType(IntEnum):
    none = -1,
    pea = 0x0,
    snow_pea = 0x1,
    cabbage = 0x2,
    melon = 0x3,
    puff = 0x4,
    wintermelon = 0x5,
    fire_pea = 0x6,
    star = 0x7,
    cactus = 0x8,
    basketball = 0x9,
    kernel = 0xA,
    cob_cannon = 0xB,
    butter = 0xC
    
class ProjectileMotionType(IntEnum):
    straight = 0,
    parabola = 1,
    switch_way = 2,
    puff = 5,
    left_straight = 6,
    starfruit = 7,
    cattail = 9
    
class ProjecTile(ObjNode):
    iterator_function_address = 0x41C9B0
    
    obj_size = 0x94
    
    int_x: int = ob.property_i32(0x8, "图像整数x坐标")
    
    int_y: int = ob.property_i32(0xc, "图像整数y坐标")
    
    x: float = ob.property_f32(0x30, "浮点x坐标")
    
    y: float = ob.property_f32(0x34, "浮点y坐标")
    
    dx: float = ob.property_f32(0x3c, "x速度")
    
    dy: float = ob.property_f32(0x40, "y速度")
    
    type_: ProjectileType = ob.property_int_enum(0x5c, ProjectileType, "子弹类型")
    
    motion_type: ProjectileMotionType = ob.property_int_enum(0x58, ProjectileMotionType, "子弹运动类型")
    
    target_zombie_id: ObjId = ob.property_obj(0x88, ObjId, "香蒲子弹目标僵尸")
    

class ProjectileList(ob.obj_list(ProjecTile)):
    pass


def get_projectile_list(ctler: Controller) -> ProjectileList | None:
    if (t := ctler.read_i32([0x6a9ec0, 0x768])) is None:
        raise RuntimeError("game base ptr not found")
    else:
        return ProjectileList(t + 0xc8, ctler)
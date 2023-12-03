# -*- coding: utf_8 -*-
"""
子弹相关的枚举和类
"""
from enum import IntEnum
from typing import Self

from . import obj_base as ob
from ..basic import asm


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


class Projectile(ob.ObjNode):
    ITERATOR_FUNC_ADDRESS = 0x41C9B0
    
    OBJ_SIZE = 0x94
    
    int_x: int = ob.property_i32(0x8, "图像整数x坐标")
    
    int_y: int = ob.property_i32(0xc, "图像整数y坐标")
    
    x: float = ob.property_f32(0x30, "浮点x坐标")
    
    y: float = ob.property_f32(0x34, "浮点y坐标")
    
    dx: float = ob.property_f32(0x3c, "x速度")
    
    dy: float = ob.property_f32(0x40, "y速度")
    
    type_: ProjectileType = ob.property_int_enum(0x5c, ProjectileType, "子弹类型")
    
    motion_type: ProjectileMotionType = ob.property_int_enum(
        0x58, ProjectileMotionType, "子弹运动类型")
    
    @property
    def target_zombie_id(self) -> ob.ObjId:
        """香蒲子弹目标僵尸"""
        return ob.ObjId(self.base_ptr + 0x88, self._controller)

    def die(self):
        """
        令自己死亡
        """
        code = f"""
            mov eax, {self.base_ptr};
            mov edx, {0x46EB20};  // Projectile::Die
            call edx;
            ret;"""
        asm.run(code, self._controller)
    

class ProjectileList(ob.obj_list(Projectile)):
    def free_all(self) -> Self:
        p_board = self._controller.get_p_board()[1]
        code = f"""
                push edi;   
                push esi;
                push ebx;
                mov ebx, {Projectile.ITERATOR_FUNC_ADDRESS};
                mov edi, {0x46EB20};
                mov esi, {self._controller.result_address};
                xor edx, edx;
                xor edx, edx;
                mov [esi], edx;
                LIterate:
                    mov edx, {p_board};
                    call ebx;  // Board::IterateProjectile
                    test al, al;
                    jz LFreeAll;
                    mov eax, [esi]
                    call edi;  // Projectile::Die
                    jmp LIterate;
                    
                LFreeAll:
                    mov edi, {self.base_ptr}
                    mov edx, {0x41e600};  // DataArray<Zombie>::DataArrayFreeAll
                    call edx;
                    pop ebx;
                    pop esi;
                    pop edi;
                    ret;"""
        asm.run(code, self._controller)
        return self

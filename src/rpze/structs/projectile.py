# -*- coding: utf_8 -*-
"""
子弹相关的枚举和类
"""
from enum import IntEnum
from typing import Self

from .obj_base import property_i32, property_f32, property_bool, property_int_enum, ObjId, obj_list, GameObject
from ..basic import asm


class ProjectileType(IntEnum):
    """
    子弹类型
    """
    PEA = pea = 0
    SNOWPEA = snow_pea = 1
    CABBAGE = cabbage = 2
    MELON = melon = 3
    PUFF = puff = 4
    WINTERMELON = wintermelon = 5
    FIREBALL = fire_pea = 6
    STAR = star = 7
    SPIKE = cactus = 8
    BASKETBALL = basketball = 9
    KERNEL = kernel = 10
    COBBIG = cob_cannon = 11
    BUTTER = butter = 12
    ZOMBIE_PEA = 13
    NUM_PROJECTILES = 14


class ProjectileMotionType(IntEnum):
    """
    子弹运动类型
    """
    STRAIGHT = straight = 0
    LOBBED = parabola = 1
    THREEPEATER = switch_way = 2
    BEE = 3
    BEE_BACKWARDS = 4
    PUFF = puff = 5
    BACKWARDS = left_straight = 6
    STAR = starfruit = 7
    FLOAT_OVER = 8
    HOMING = cattail = 9


class Projectile(GameObject):
    """
    子弹对象
    """
    ITERATOR_FUNC_ADDRESS = 0x41C9B0

    OBJ_SIZE = 0x94

    int_x = property_i32(0x8, "图像整数 x 坐标")

    int_y = property_i32(0xc, "图像整数 y 坐标")

    col = property_i32(0x1c, "所在行数")

    m_pos_x = x = property_f32(0x30, "浮点 x 坐标")

    m_pos_y = y = property_f32(0x34, "浮点 y 坐标")

    m_vel_x = dx = property_f32(0x3c, "x 速度")

    m_vel_y = dy = property_f32(0x40, "y 速度")

    m_dead = is_dead = property_bool(0x50, "是否死亡")

    m_projectile_type = type_ = property_int_enum(
        0x5c, ProjectileType, "子弹类型")

    m_motion_type = motion_type = property_int_enum(
        0x58, ProjectileMotionType, "子弹运动类型")

    @property
    def target_zombie_id(self) -> ObjId:  # mTargetZombieID
        """香蒲子弹目标僵尸"""
        return ObjId(self.base_ptr + 0x88, self.controller)

    def die(self) -> None:
        """
        令自己死亡
        """
        code = f"""
            mov eax, {self.base_ptr}
            call {0x46EB20}  // Projectile::Die
            ret"""
        asm.run(code, self.controller)


class ProjectileList(obj_list(Projectile)):
    """
    子弹 DataArray
    """
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
                    mov {Projectile.ITERATOR_P_BOARD_REG}, edi
                    call {Projectile.ITERATOR_FUNC_ADDRESS}  // Board::IterateProjectile
                    test al, al
                    jz LFreeAll
                    mov eax, [esi]
                    call {0x46EB20}  // Projectile::Die
                    jmp LIterate
                    
                LFreeAll:
                    mov edi, {self.base_ptr}
                    call {0x41e600}  // DataArray<Zombie>::DataArrayFreeAll
                    pop esi
                    pop edi
                    ret"""
        asm.run(code, self.controller)
        return self

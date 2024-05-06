# -*- coding: utf_8 -*-
"""
僵尸相关的枚举和类
"""
from enum import IntEnum
from typing import Self

from . import obj_base as ob
from ..basic import asm


class ZombieType(IntEnum):
    """
    僵尸类型
    """
    none = -1
    zombie = 0x0
    flag = 0x1
    conehead = 0x2
    pole_vaulting = 0x3
    buckethead = 0x4
    newspaper = 0x5
    screendoor = 0x6
    football = 0x7
    dancing = 0x8
    backup_dancer = 0x9
    ducky_tube = 0xa
    snorkel = 0xb
    zomboni = 0xc
    dolphin_rider = 0xe
    jack_in_the_box = 0xf
    balloon = 0x10
    digger = 0x11
    pogo = 0x12
    yeti = 0x13
    bungee = 0x14
    ladder = 0x15
    catapult = 0x16
    gargantuar = 0x17
    imp = 0x18
    giga_gargantuar = 0x20


class ZombieStatus(IntEnum):
    """
    僵尸状态
    """
    walking = 0x0
    dying = 0x1
    dying_from_instant_kill = 0x2
    dying_from_lawnmower = 0x3
    bungee_target_drop = 0x4
    bungee_body_drop = 0x5
    bungee_idle_after_drop = 0x6
    bungee_grab = 0x7
    bungee_raise = 0x8
    bungee_idle = 0xa
    pole_vaulting_running = 0xb
    pole_vaulting_jumping = 0xc
    pole_vaulting_walking = 0xd
    rising_from_ground = 0xe
    jackbox_walking = 0xf
    jackbox_pop = 0x10
    pogo_with_stick = 0x14
    pogo_idle_before_target = 0x15
    pogo_jump_across = 0x1b
    newspaper_walking = 0x1d
    newspaper_destroyed = 0x1e
    newspaper_running = 0x1f
    digger_dig = 0x20
    digger_drill = 0x21
    digger_lost_dig = 0x22
    digger_landing = 0x23
    digger_dizzy = 0x24
    digger_walk_right = 0x25
    digger_walk_left = 0x26
    digger_idle = 0x27
    dancing_moonwalk = 0x28
    dancing_point = 0x29
    dancing_wait_summoning = 0x2a
    dancing_summoning = 0x2b
    dancing_walking = 0x2c
    dancing_armrise1 = 0x2d
    dancing_armrise2 = 0x2e
    dancing_armrise3 = 0x2f
    dancing_armrise4 = 0x30
    dancing_armrise5 = 0x31
    backup_spawning = 0x32
    dolphin_walk_with_dolphin = 0x33
    dolphin_jump_in_pool = 0x34
    dolphin_ride = 0x35
    dolphin_jump = 0x36
    dolphin_walk_in_pool = 0x37
    dolphin_walk_without_dolphin = 0x38
    snorkel_walking = 0x39
    snorkel_jump_in_the_pool = 0x3a
    snorkel_swim = 0x3b
    snorkel_up_to_eat = 0x3c
    snorkel_eat = 0x3d
    snorkel_finished_eat = 0x3e
    catapult_shoot = 0x43
    catapult_idle = 0x44
    balloon_flying = 0x49
    balloon_falling = 0x4a
    balloon_walking = 0x4b
    imp_flying = 0x47
    imp_landing = 0x48
    gargantuar_throw = 0x45
    gargantuar_smash = 0x46
    ladder_walking = 0x4c
    ladder_placing = 0x4d
    yeti_escape = 0x5b


class ZombieAction(IntEnum):
    """
    僵尸动作类型
    """
    none = 0x0
    entering_pool = 0x1
    leaving_pool = 0x2
    caught_by_kelp = 0x3
    climbing_ladder = 0x6
    falling = 0x7
    fall_from_sky = 0x9


class ZombieAccessoriesType1(IntEnum):
    """
    一类防具类型
    """
    none = 0x0
    roadcone = 0x1
    bucket = 0x2
    football_cap = 0x3
    miner_hat = 0x4


class ZombieAccessoriesType2(IntEnum):
    """
    二类防具类型
    """
    none = 0x0
    screen_door = 0x1
    newspaper = 0x2
    ladder = 0x3


class Zombie(ob.ObjNode):
    """
    僵尸对象
    """
    ITERATOR_FUNC_ADDRESS = 0x41C8F0

    OBJ_SIZE = 0x15c

    int_x = ob.property_i32(0x8, "整数x坐标")

    int_y = ob.property_i32(0xc, "整数y坐标")

    row = ob.property_i32(0x1c, "所在行数")

    type_ = ob.property_int_enum(0x24, ZombieType, "僵尸种类")

    status = ob.property_int_enum(0x28, ZombieStatus, "僵尸状态")

    x = ob.property_f32(0x2c, "浮点x坐标")

    y = ob.property_f32(0x30, "浮点y坐标")

    dx = ob.property_f32(0x34, "x方向速度")

    is_eating = ob.property_bool(0x51, "在啃食时为True")

    flash_cd = ob.property_i32(0x54, """
    发亮倒计时
                                    
    - 刚生成僵尸时为0, 受击变为25
    - 在flash_cd < -500时, 僵尸开始速度重置 + 啃食加速
    """)

    time_since_spawn = ob.property_i32(0x60, "出生时间")

    action = ob.property_int_enum(0x64, ZombieAction, "僵尸行为")

    hp = ob.property_i32(0xc8, "本体血量")

    max_hp = ob.property_u32(0xcc, "本体血量上限")

    accessories_type_1 = ob.property_int_enum(0xc4, ZombieAccessoriesType1, "一类饰品类型")

    accessories_hp_1 = ob.property_i32(0xd0, "一类饰品血量")

    accessories_max_hp_1 = ob.property_i32(0xd4, "一类饰品血量上限")

    accessories_type_2 = ob.property_int_enum(0xd8, ZombieAccessoriesType2, "二类饰品")

    accessories_hp_2 = ob.property_i32(0xdc, "二类饰品血量")

    accessories_max_hp_2 = ob.property_i32(0xe0, "二类饰品血量上限")

    bungee_col = ob.property_i32(0x80, "蹦级目标所在列")

    hit_box_x = ob.property_i32(0x8c, "中弹判定横坐标")

    hit_box_y = ob.property_i32(0x90, "中弹判定纵坐标")

    hit_width = ob.property_i32(0x94, "中弹判定宽度")

    hit_height = ob.property_i32(0x98, "中弹判定高度")

    attack_box_x = ob.property_i32(0x9c, "攻击判定横坐标")

    attack_box_y = ob.property_i32(0xa0, "攻击判定纵坐标")

    attack_width = ob.property_i32(0xa4, "攻击判定宽度")

    attack_height = ob.property_i32(0xa8, "攻击判定高度")

    slow_cd = ob.property_i32(0xac, "减速倒计时")

    butter_cd = ob.property_i32(0xb0, "黄油固定倒计时")

    freeze_cd = ob.property_i32(0xb4, "冻结倒计时")

    is_dead = ob.property_bool(0xec, '是否"彻底"死亡, 即濒死时此条为False')

    is_not_dying = ob.property_bool(0xba, "不在濒死状态时为True")

    @property
    def master_id(self) -> ob.ObjId:  # 似乎所有ObjNode subclass都用Property而不是Attribute更好看
        """舞王id"""
        return ob.ObjId(self.base_ptr + 0xf0, self.controller)

    @property
    def partner_ids(self) -> tuple[ob.ObjId, ob.ObjId, ob.ObjId, ob.ObjId]:
        """伴舞id"""
        return tuple(ob.ObjId(self.base_ptr + 0xf4 + i * 4, self.controller) for i in range(4))

    def __str__(self) -> str:
        if not self.is_dead:
            return f"#{self.id.index} {self.type_.name} at row {self.row + 1}"
        return "dead zombie"

    def die_no_loot(self) -> None:
        """
        令僵尸消失，移除僵尸附件和动画，同时处理除掉落外的僵尸消失相关事件（会触发过关奖品掉落的判定）。
        """
        code = f"""
            mov ecx, {self.base_ptr}
            call {0x530510} // Zombie::DieNoLoot
            ret"""
        asm.run(code, self.controller)


class ZombieList(ob.obj_list(Zombie)):
    """
    僵尸DataArray
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
                mov {Zombie.ITERATOR_P_BOARD_REG}, edi
                call {Zombie.ITERATOR_FUNC_ADDRESS}  // Board::IterateZombie
                test al, al
                jz LFreeAll
                mov ecx, [esi]
                call {0x530510}  // Zombie::DieNoLoot
                jmp LIterate
                
            LFreeAll:
                mov edi, {self.base_ptr}
                call {0x41e4d0}  // DataArray<Zombie>::DataArrayFreeAll
                pop esi
                pop edi
                ret"""
        asm.run(code, self.controller)
        return self

from enum import IntEnum

import structs.obj_base as ob
from basic import asm
from rp_extend import Controller


# 数据结构和pvz_emulator命名保持一致

class ZombieType(IntEnum):
    none = -1,
    zombie = 0x0,
    flag = 0x1,
    conehead = 0x2,
    pole_vaulting = 0x3,
    buckethead = 0x4,
    newspaper = 0x5,
    screendoor = 0x6,
    football = 0x7,
    dancing = 0x8,
    backup_dancer = 0x9,
    ducky_tube = 0xa,
    snorkel = 0xb,
    zomboni = 0xc,
    dolphin_rider = 0xe,
    jack_in_the_box = 0xf,
    balloon = 0x10,
    digger = 0x11,
    pogo = 0x12,
    yeti = 0x13,
    bungee = 0x14,
    ladder = 0x15,
    catapult = 0x16,
    gargantuar = 0x17,
    imp = 0x18,
    giga_gargantuar = 0x20


class ZombieStatus(IntEnum):
    walking = 0x0,
    dying = 0x1,
    dying_from_instant_kill = 0x2,
    dying_from_lawnmower = 0x3,
    bungee_target_drop = 0x4,
    bungee_body_drop = 0x5,
    bungee_idle_after_drop = 0x6,
    bungee_grab = 0x7,
    bungee_raise = 0x8,
    bungee_idle = 0xa,
    pole_valuting_running = 0xb,
    pole_valuting_jumpping = 0xc,
    pole_vaulting_walking = 0xd,
    rising_from_ground = 0xe,
    jackbox_walking = 0xf,
    jackbox_pop = 0x10,
    pogo_with_stick = 0x14,
    pogo_idle_before_target = 0x15,
    pogo_jump_across = 0x1b,
    newspaper_walking = 0x1d,
    newspaper_destoryed = 0x1e,
    newspaper_running = 0x1f,
    digger_dig = 0x20,
    digger_drill = 0x21,
    digger_lost_dig = 0x22,
    digger_landing = 0x23,
    digger_dizzy = 0x24,
    digger_walk_right = 0x25,
    digger_walk_left = 0x26,
    digger_idle = 0x27,
    dancing_moonwalk = 0x28,
    dancing_point = 0x29,
    dancing_wait_summoning = 0x2a,
    dancing_summoning = 0x2b,
    dancing_walking = 0x2c,
    dancing_armrise1 = 0x2d,
    dancing_armrise2 = 0x2e,
    dancing_armrise3 = 0x2f,
    dancing_armrise4 = 0x30,
    dancing_armrise5 = 0x31,
    backup_spawning = 0x32,
    dophin_walk_with_dophin = 0x33,
    dophin_jump_in_pool = 0x34,
    dophin_ride = 0x35,
    dophin_jump = 0x36,
    dophin_walk_in_pool = 0x37,
    dophin_walk_without_dophin = 0x38,
    snorkel_walking = 0x39,
    snorkel_jump_in_the_pool = 0x3a,
    snorkel_swim = 0x3b,
    snorkel_up_to_eat = 0x3c,
    snorkel_eat = 0x3d,
    snorkel_finied_eat = 0x3e,
    catapult_shoot = 0x43,
    catapult_idle = 0x44,
    balloon_flying = 0x49,
    balloon_falling = 0x4a,
    balloon_walking = 0x4b,
    imp_flying = 0x47,
    imp_landing = 0x48,
    gargantuar_throw = 0x45,
    gargantuar_smash = 0x46,
    ladder_walking = 0x4c,
    ladder_placing = 0x4d,
    yeti_escape = 0x5b


class ZombieAction(IntEnum):
    none = 0x0,
    entering_pool = 0x1,
    leaving_pool = 0x2,
    caught_by_kelp = 0x3,
    climbing_ladder = 0x6,
    falling = 0x7,
    fall_from_sky = 0x9


class ZombieAccessoriesType1(IntEnum):
    none = 0x0,
    roadcone = 0x1,
    bucket = 0x2,
    football_cap = 0x3,
    miner_hat = 0x4


class ZombieAccessoriesType2(IntEnum):
    none = 0x0,
    screen_door = 0x1,
    newspaper = 0x2,
    ladder = 0x3


class Zombie(ob.ObjNode):
    iterator_function_address = 0x41C8F0

    obj_size = 0x15c

    int_x: int = ob.property_i32(0x8, "int_x")
    # 整数y坐标
    int_y: int = ob.property_i32(0xc, "int_y")

    width: int = ob.property_i32(0x10, "width")
        
    height: int = ob.property_i32(0x14, "height")
        
    row: int = ob.property_i32(0x1c, "row")
        
    type_: ZombieType = ob.property_int_enum(0x24, ZombieType, "zombie_type")

    status: ZombieStatus = ob.property_int_enum(0x28, ZombieStatus, "zombie_status")

    x: float = ob.property_f32(0x2c, "float_x")
        
    y: float = ob.property_f32(0x30, "float_y")
    # x的变化率, 横向速度
    dx: float = ob.property_f32(0x34, "dx")
        
    is_eating: bool = ob.property_bool(0x51, "is_eating")
    # 闪光倒计时
    flash_countdown: int = ob.property_i32(0x54, "flash_countdown")
    # 出生时间
    time_since_spawn: int = ob.property_i32(0x60, "time_countdown")
        
    action: ZombieAction = ob.property_int_enum(0x64, ZombieAction, "zombie_action")
    # 本体血量
    hp: int = ob.property_i32(0xc8, "hp")
    # 本体血量上限
    max_hp: int = ob.property_u32(0xcc, "max_hp")

    accessories_type_1: ZombieAccessoriesType1 = ob.property_int_enum(0xc4, ZombieAccessoriesType1, "accessories_type_1")

    accessories_hp_1: int = ob.property_i32(0xd0, "accessories_hp_1")

    accessories_max_hp_1: int = ob.property_i32(0xd4, "accessories_max_hp_1")

    accessories_type_2: ZombieAccessoriesType2 = ob.property_int_enum(0xd8, ZombieAccessoriesType2, "accessories_type_2")

    accessories_hp_2: int = ob.property_i32(0xdc, "accessories_hp_2")

    accessories_max_hp_2: int = ob.property_i32(0xe0, "accessories_max_hp_2")
    # 是否"彻底"死亡, 即濒死时此条为false
    is_dead: bool = ob.property_bool(0xec, "is_dead")
    # 不在濒死状态时为true
    is_not_dying: bool = ob.property_bool(0xba, "is_not_dying")

    def __str__(self) -> str:
        return f"#{self.id.index} {self.type_.name} at row {self.row + 1}"


class ZombieList(ob.obj_list(Zombie)):
    def izombie_place_zombie(self, row: int, col: int, type_: ZombieType):
        ret_idx = self.next_index
        p_challenge = self.controller.read_i32([0x6a9ec0, 0x768, 0x160])
        code = f'''
            push edx;
            mov eax, {row};
            push {col};
            push {int(type_)};
            mov ecx, {p_challenge};
            mov edx, 0x42a0f0;
            call edx;
            pop edx;
            ret;'''
        asm.run(code, self.controller)
        return self.at(ret_idx)


def get_zombie_list(ctler: Controller) -> ZombieList | None:
    if (t := ctler.read_i32([0x6a9ec0, 0x768])) is None:
        raise RuntimeError("game base ptr not found")
    else:
        return ZombieList(t + 0x90, ctler)

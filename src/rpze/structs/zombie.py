# -*- coding: utf_8 -*-
"""
僵尸相关的枚举和类
"""
from enum import IntEnum
from typing import Self

from .obj_base import ObjNode, property_i32, property_int_enum, property_f32, property_bool, property_u32, ObjId, \
    obj_list
from ..basic import asm


class ZombieType(IntEnum):
    """
    僵尸类型
    """
    INVALID = none = -1
    NORMAL = zombie = 0
    FLAG = flag = 1
    TRAFFIC_CONE = conehead = 2
    POLEVAULTER = pole_vaulting = 3
    PAIL = buckethead = 4
    NEWSPAPER = newspaper = 5
    DOOR = screendoor = 6
    FOOTBALL = football = 7
    DANCER = dancing = 8
    BACKUP_DANCER = backup_dancer = 9
    DUCKY_TUBE = ducky_tube = 10
    SNORKEL = snorkel = 11
    ZAMBONI = zomboni = 12  # maybe a typo in pdb
    BOBSLED = 13
    DOLPHIN_RIDER = dolphin_rider = 14
    JACK_IN_THE_BOX = jack_in_the_box = 15
    BALLOON = balloon = 16
    DIGGER = digger = 17
    POGO = pogo = 18
    YETI = yeti = 19
    BUNGEE = bungee = 20
    LADDER = ladder = 21
    CATAPULT = catapult = 22
    GARGANTUAR = gargantuar = 23
    IMP = imp = 24
    BOSS = 25
    PEA_HEAD = 26
    WALLNUT_HEAD = 27
    JALAPENO_HEAD = 28
    GATLING_HEAD = 29
    SQUASH_HEAD = 30
    TALLNUT_HEAD = 31
    REDEYE_GARGANTUAR = giga_gargantuar = 32
    NUM_ZOMBIE_TYPES = 33


class ZombieStatus(IntEnum):
    """
    僵尸状态
    """
    ZOMBIE_NORMAL = walking = 0
    ZOMBIE_DYING = dying = 1
    ZOMBIE_BURNED = dying_from_instant_kill = 2
    ZOMBIE_MOWERED = dying_from_lawnmower = 3
    BUNGEE_DIVING = bungee_target_drop = 4
    BUNGEE_DIVING_SCREAMING = bungee_body_drop = 5
    BUNGEE_AT_BOTTOM = bungee_idle_after_drop = 6
    BUNGEE_GRABBING = bungee_grab = 7
    BUNGEE_RISING = bungee_raise = 8
    BUNGEE_HIT_OUCHY = 9
    BUNGEE_CUTSCENE = bungee_idle = 10
    POLEVAULTER_PRE_VAULT = pole_vaulting_running = 11
    POLEVAULTER_IN_VAULT = pole_vaulting_jumping = 12
    POLEVAULTER_POST_VAULT = pole_vaulting_walking = 13
    RISING_FROM_GRAVE = rising_from_ground = 14
    JACK_IN_THE_BOX_RUNNING = jackbox_walking = 15
    JACK_IN_THE_BOX_POPPING = jackbox_pop = 16
    BOBSLED_SLIDING = 17
    BOBSLED_BOARDING = 18
    BOBSLED_CRASHING = 19
    POGO_BOUNCING = pogo_with_stick = 20
    POGO_HIGH_BOUNCE_1 = pogo_idle_before_target = 21
    POGO_HIGH_BOUNCE_2 = 22
    POGO_HIGH_BOUNCE_3 = 23
    POGO_HIGH_BOUNCE_4 = 24
    POGO_HIGH_BOUNCE_5 = 25
    POGO_HIGH_BOUNCE_6 = 26
    POGO_FORWARD_BOUNCE_2 = pogo_jump_across = 27
    POGO_FORWARD_BOUNCE_7 = 28
    NEWSPAPER_READING = newspaper_walking = 29
    NEWSPAPER_MADDENING = newspaper_destroyed = 30
    NEWSPAPER_MAD = newspaper_running = 31
    DIGGER_TUNNELING = digger_dig = 32
    DIGGER_RISING = digger_drill = 33
    DIGGER_TUNNELING_PAUSE_WITHOUT_AXE = digger_lost_dig = 34
    DIGGER_RISE_WITHOUT_AXE = digger_landing = 35
    DIGGER_STUNNED = digger_dizzy = 36
    DIGGER_WALKING = digger_walk_right = 37
    DIGGER_WALKING_WITHOUT_AXE = digger_walk_left = 38
    DIGGER_CUTSCENE = digger_idle = 39
    DANCER_DANCING_IN = dancing_moonwalk = 40
    DANCER_SNAPPING_FINGERS = dancing_point = 41
    DANCER_SNAPPING_FINGERS_WITH_LIGHT = dancing_wait_summoning = 42
    DANCER_SNAPPING_FINGERS_HOLD = dancing_summoning = 43
    DANCER_DANCING_LEFT = dancing_walking = 44
    DANCER_WALK_TO_RAISE = dancing_armrise1 = 45
    DANCER_RAISE_LEFT_1 = dancing_armrise2 = 46
    DANCER_RAISE_RIGHT_1 = dancing_armrise3 = 47
    DANCER_RAISE_LEFT_2 = dancing_armrise4 = 48
    DANCER_RAISE_RIGHT_2 = dancing_armrise5 = 49
    DANCER_RISING = backup_spawning = 50
    DOLPHIN_WALKING = dolphin_walk_with_dolphin = 51
    DOLPHIN_INTO_POOL = dolphin_jump_in_pool = 52
    DOLPHIN_RIDING = dolphin_ride = 53
    DOLPHIN_IN_JUMP = dolphin_jump = 54
    DOLPHIN_WALKING_IN_POOL = dolphin_walk_in_pool = 55
    DOLPHIN_WALKING_WITHOUT_DOLPHIN = dolphin_walk_without_dolphin = 56
    SNORKEL_WALKING = snorkel_walking = 57
    SNORKEL_INTO_POOL = snorkel_jump_in_the_pool = 58
    SNORKEL_WALKING_IN_POOL = snorkel_swim = 59
    SNORKEL_UP_TO_EAT = snorkel_up_to_eat = 60
    SNORKEL_EATING_IN_POOL = snorkel_eat = 61
    SNORKEL_DOWN_FROM_EAT = snorkel_finished_eat = 62
    ZOMBIQUARIUM_ACCEL = 63
    ZOMBIQUARIUM_DRIFT = 64
    ZOMBIQUARIUM_BACK_AND_FORTH = 65
    ZOMBIQUARIUM_BITE = 66
    CATAPULT_LAUNCHING = catapult_shoot = 67
    CATAPULT_RELOADING = catapult_idle = 68
    GARGANTUAR_THROWING = gargantuar_throw = 69
    GARGANTUAR_SMASHING = gargantuar_smash = 70
    IMP_GETTING_THROWN = imp_flying = 71
    IMP_LANDING = imp_landing = 72
    BALLOON_FLYING = balloon_flying = 73
    BALLOON_POPPING = balloon_falling = 74
    BALLOON_WALKING = balloon_walking = 75
    LADDER_CARRYING = ladder_walking = 76
    LADDER_PLACING = ladder_placing = 77
    BOSS_ENTER = 78
    BOSS_IDLE = 79
    BOSS_SPAWNING = 80
    BOSS_STOMPING = 81
    BOSS_BUNGEES_ENTER = 82
    BOSS_BUNGEES_DROP = 83
    BOSS_BUNGEES_LEAVE = 84
    BOSS_DROP_RV = 85
    BOSS_HEAD_ENTER = 86
    BOSS_HEAD_IDLE_BEFORE_SPIT = 87
    BOSS_HEAD_IDLE_AFTER_SPIT = 88
    BOSS_HEAD_SPIT = 89
    BOSS_HEAD_LEAVE = 90
    YETI_RUNNING = yeti_escape = 91
    SQUASH_PRE_LAUNCH = 92
    SQUASH_RISING = 93
    SQUASH_FALLING = 94
    SQUASH_DONE_FALLING = 95


class ZombieAction(IntEnum):
    """
    僵尸动作类型

    源码认为是描述僵尸所在的高度`ZombieHeight`
    """
    ZOMBIE_NORMAL = none = 0
    IN_TO_POOL = entering_pool = 1
    OUT_OF_POOL = leaving_pool = 2
    DRAGGED_UNDER = caught_by_kelp = 3
    UP_TO_HIGH_GROUND = 4
    DOWN_OFF_HIGH_GROUND = 5
    UP_LADDER = climbing_ladder = 6
    FALLING = falling = 7
    IN_TO_CHIMNEY = 8
    GETTING_BUNGEE_DROPPED = fall_from_sky = 9
    ZOMBIQUARIUM = 10


class ZombieAccessoriesType1(IntEnum):
    """
    一类防具类型

    源码认为是头盔类型`HelmType`
    """
    NONE = none = 0
    TRAFFIC_CONE = roadcone = 1
    PAIL = bucket = 2
    FOOTBALL = football_cap = 3
    DIGGER = miner_hat = 4
    REDEYES = 5
    HEADBAND = 6
    BOBSLED = 7
    WALLNUT = 8
    TALLNUT = 9


class ZombieAccessoriesType2(IntEnum):
    """
    二类防具类型

    源码认为是护盾类型`ShieldType`
    """
    NONE = none = 0
    DOOR = screen_door = 1
    NEWSPAPER = newspaper = 2
    LADDER = ladder = 3


class Zombie(ObjNode):
    """
    僵尸对象
    """
    ITERATOR_FUNC_ADDRESS = 0x41C8F0

    OBJ_SIZE = 0x15c

    int_x = property_i32(0x8, "整数 x 坐标")

    int_y = property_i32(0xc, "整数 y 坐标")

    row = property_i32(0x1c, "所在行数")

    m_zombie_type = type_ = property_int_enum(0x24, ZombieType, "僵尸种类")

    m_zombie_phase = status = property_int_enum(0x28, ZombieStatus, "僵尸状态")

    m_pos_x = x = property_f32(0x2c, "浮点 x 坐标")

    m_pos_y = y = property_f32(0x30, "浮点 y 坐标")

    m_vel_x = dx = property_f32(0x34, "x 方向速度")

    m_is_eating = is_eating = property_bool(0x51, "在啃食时为 True")

    m_just_go_shot_counter = flash_cd = property_i32(0x54, """
    发亮倒计时
                                    
    - 刚生成僵尸时为0, 受击变为25
    - 在 flash_cd < -500时, 僵尸开始速度重置 + 啃食加速
    """)

    m_zombie_age = time_since_spawn = property_i32(0x60, "出生时间")

    m_zombie_height = action = property_int_enum(0x64, ZombieAction, "僵尸行为")

    m_body_health = hp = property_i32(0xc8, "本体血量")

    m_body_max_health = max_hp = property_u32(0xcc, "本体血量上限")

    m_helm_type = accessories_type_1 = property_int_enum(
        0xc4, ZombieAccessoriesType1, "一类饰品类型")

    m_helm_health = accessories_hp_1 = property_i32(0xd0, "一类饰品血量")

    m_helm_max_health = accessories_max_hp_1 = property_i32(0xd4, "一类饰品血量上限")

    m_shield_type = accessories_type_2 = property_int_enum(
        0xd8, ZombieAccessoriesType2, "二类饰品")

    m_shield_health = accessories_hp_2 = property_i32(0xdc, "二类饰品血量")

    m_shield_max_health = accessories_max_hp_2 = property_i32(0xe0, "二类饰品血量上限")

    m_target_col = bungee_col = property_i32(0x80, "蹦级目标所在列")

    hit_box_x = property_i32(0x8c, "中弹判定横坐标")

    hit_box_y = property_i32(0x90, "中弹判定纵坐标")

    hit_width = property_i32(0x94, "中弹判定宽度")

    hit_height = property_i32(0x98, "中弹判定高度")

    attack_box_x = property_i32(0x9c, "攻击判定横坐标")

    attack_box_y = property_i32(0xa0, "攻击判定纵坐标")

    attack_width = property_i32(0xa4, "攻击判定宽度")

    attack_height = property_i32(0xa8, "攻击判定高度")

    m_chilled_counter = slow_cd = property_i32(0xac, "减速倒计时")

    m_buttered_counter = butter_cd = property_i32(0xb0, "黄油固定倒计时")

    m_ice_trap_counter = freeze_cd = property_i32(0xb4, "冻结倒计时")

    m_dead = is_dead = property_bool(0xec, '是否"彻底"死亡, 即濒死时此条为 False')

    m_has_head = is_not_dying = property_bool(0xba, "不在濒死状态时为 True")

    @property
    def master_id(self) -> ObjId:  # mRelatedZombieID
        """舞王id"""
        return ObjId(self.base_ptr + 0xf0, self.controller)

    @property
    def partner_ids(self) -> tuple[ObjId, ObjId, ObjId, ObjId]:  # mFollowerZombieID[4]
        """伴舞id"""
        return tuple(ObjId(self.base_ptr + 0xf4 + i * 4,    # type: ignore
                           self.controller) for i in range(4))

    @property
    def m_body_reanim_id(self) -> ObjId:
        """动画 id"""
        return ObjId(self.base_ptr + 0x118, self.controller)

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


class ZombieList(obj_list(Zombie)):
    """
    僵尸 DataArray
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

# -*- coding: utf_8 -*-
"""
植物相关的枚举和类
"""
import typing
from enum import IntEnum

from .obj_base import property_i32, property_bool, property_int_enum, ObjId, obj_list, GameObject
from ..basic import asm


class PlantType(IntEnum):
    """
    植物类型
    """
    PEASHOOTER = pea_shooter = 0
    SUNFLOWER = sunflower = 1
    CHERRYBOMB = cherry_bomb = 2
    WALLNUT = wallnut = 3
    POTATOMINE = potato_mine = 4
    SNOWPEA = snow_pea = 5
    CHOMPER = chomper = 6
    REPEATER = repeater = 7
    PUFFSHROOM = puffshroom = 8
    SUNSHROOM = sunshroom = 9
    FUMESHROOM = fumeshroom = 10
    GRAVEBUSTER = grave_buster = 11
    HYPNOSHROOM = hypnoshroom = 12
    SCAREDYSHROOM = scaredyshroom = 13
    ICESHROOM = iceshroom = 14
    DOOMSHROOM = doomshroom = 15
    LILYPAD = lily_pad = 16
    SQUASH = squash = 17
    THREEPEATER = threepeater = 18
    TANGLEKELP = tangle_kelp = 19
    JALAPENO = jalapeno = 20
    SPIKEWEED = spikeweed = 21
    TORCHWOOD = torchwood = 22
    TALLNUT = tallnut = 23
    SEASHROOM = seashroom = 24
    PLANTERN = plantern = 25
    CACTUS = cactus = 26
    BLOVER = blover = 27
    SPLITPEA = split_pea = 28
    STARFRUIT = starfruit = 29
    PUMPKINSHELL = pumpkin = 30
    MAGNETSHROOM = magnetshroom = 31
    CABBAGEPULT = cabbagepult = 32
    FLOWERPOT = flower_pot = 33
    KERNELPULT = kernelpult = 34
    INSTANT_COFFEE = coffee_bean = 35
    GARLIC = garlic = 36
    UMBRELLA = umbrella_leaf = 37
    MARIGOLD = marigold = 38
    MELONPULT = melonpult = 39
    GATLINGPEA = gatling_pea = 40
    TWINSUNFLOWER = twin_sunflower = 41
    GLOOMSHROOM = gloomshroom = 42
    CATTAIL = cattail = 43
    WINTERMELON = winter_melon = 44
    GOLD_MAGNET = gold_magnet = 45
    SPIKEROCK = spikerock = 46
    COBCANNON = cob_cannon = 47
    IMITATER = imitator = 48
    EXPLODE_O_NUT = NUM_SEEDS_IN_CHOOSER = 49
    GIANT_WALLNUT = 50
    SPROUT = 51
    LEFTPEATER = 52
    NUM_SEED_TYPES = 53
    BEGHOULED_BUTTON_SHUFFLE = 54
    BEGHOULED_BUTTON_CRATER = 55
    SLOT_MACHINE_SUN = 56
    SLOT_MACHINE_DIAMOND = 57
    ZOMBIQUARIUM_SNORKLE = 58
    ZOMBIQUARIUM_TROPHY = 59
    ZOMBIE_NORMAL = 60
    ZOMBIE_TRAFFIC_CONE = 61
    ZOMBIE_POLEVAULTER = 62
    ZOMBIE_PAIL = 63
    ZOMBIE_LADDER = 64
    ZOMBIE_DIGGER = 65
    ZOMBIE_BUNGEE = 66
    ZOMBIE_FOOTBALL = 67
    ZOMBIE_BALLOON = 68
    ZOMBIE_SCREEN_DOOR = 69
    ZOMBONI = 70
    ZOMBIE_POGO = 71
    ZOMBIE_DANCER = 72
    ZOMBIE_GARGANTUAR = 73
    ZOMBIE_IMP = 74
    NONE = -1


class PlantStatus(IntEnum):
    """
    植物状态
    """
    NOTREADY = idle = 0
    READY = wait = 1
    DOINGSPECIAL = work = 2
    SQUASH_LOOK = squash_look = 3
    SQUASH_PRE_LAUNCH = squash_jump_up = 4
    SQUASH_RISING = squash_stop_in_the_air = 5
    SQUASH_FALLING = squash_jump_down = 6
    SQUASH_DONE_FALLING = squash_crushed = 7
    GRAVEBUSTER_LANDING = grave_buster_land = 8
    GRAVEBUSTER_EATING = grave_buster_idle = 9
    CHOMPER_BITING = chomper_bite_begin = 10
    CHOMPER_BITING_GOT_ONE = chomper_bite_success = 11
    CHOMPER_BITING_MISSED = chomper_bite_fail = 12
    CHOMPER_DIGESTING = chomper_chew = 13
    CHOMPER_SWALLOWING = chomper_swallow = 14
    POTATO_RISING = potato_sprout_out = 15
    POTATO_ARMED = potato_armed = 16
    POTATO_MASHED = 17
    SPIKEWEED_ATTACKING = spike_attack = 18
    SPIKEWEED_ATTACKING_2 = 19
    SCAREDYSHROOM_LOWERING = scaredyshroom_scared = 20
    SCAREDYSHROOM_SCARED = scaredyshroom_scared_idle = 21
    SCAREDYSHROOM_RAISING = scaredyshroom_grow = 22
    SUNSHROOM_SMALL = sunshroom_small = 23
    SUNSHROOM_GROWING = sunshroom_grow = 24
    SUNSHROOM_BIG = sunshroom_big = 25
    MAGNETSHROOM_SUCKING = magnetshroom_working = 26
    MAGNETSHROOM_CHARGING = magnetshroom_inactive_idle = 27
    BOWLING_UP = 28
    BOWLING_DOWN = 29
    CACTUS_LOW = cactus_short_idle = 30
    CACTUS_RISING = cactus_grow_tall = 31
    CACTUS_HIGH = cactus_tall_idle = 32
    CACTUS_LOWERING = cactus_get_short = 33
    TANGLEKELP_GRABBING = tangle_kelp_grab = 34
    COBCANNON_ARMING = cob_cannon_unarmed_idle = 35
    COBCANNON_LOADING = cob_cannon_charge = 36
    COBCANNON_READY = cob_cannon_launch = 37
    COBCANNON_FIRING = cob_cannon_armed_idle = 38
    KERNELPULT_BUTTER = kernelpult_launch_butter = 39
    UMBRELLA_TRIGGERED = umbrella_leaf_block = 40
    UMBRELLA_REFLECTING = umbrella_leaf_shrink = 41
    IMITATER_MORPHING = imitator_explode = 42
    ZEN_GARDEN_WATERED = 43
    ZEN_GARDEN_NEEDY = 44
    ZEN_GARDEN_HAPPY = 45
    MARIGOLD_ENDING = 46
    FLOWERPOT_INVULNERABLE = flower_pot_placed = 47
    LILYPAD_INVULNERABLE = lily_pad_placed = 48


class Plant(GameObject):
    """
    植物对象
    """
    ITERATOR_FUNC_ADDRESS = 0x41c950

    OBJ_SIZE = 0x14c

    x = property_i32(0x8, "x")

    y = property_i32(0xc, "y")

    visible = property_bool(0x18, "可见时为 True")

    row = property_i32(0x1c, "所在行数, 起点为0")

    m_seed_type = type_ = property_int_enum(0x24, PlantType, "植物类型")

    m_plant_col = col = property_i32(0x28, "所在列数, 起点为0")

    m_state = status = property_int_enum(0x3c, PlantStatus, "植物状态")

    m_plant_health = hp = property_i32(0x40, "当前血量")

    m_plant_max_health = max_hp = property_i32(0x44, "最大血量")

    can_attack = property_bool(0x48, "能攻击时为 True")

    m_subclass = property_i32(0x48, """
        植物子类型: 0 为普通, 1 为发射类
        
        和`can_attack`道理相同但在源码中实际按`int`使用
    """)  # 笨蛋 tod


    m_state_countdown = status_cd = property_i32(0x54, """
        属性倒计时, 如磁铁 cd
                                     
        地刺攻击倒计时也在这儿:
            地刺的判断和 generate_cd 无关. 在范围内有僵尸时使status_cd = 100, == 75时打出攻击
        """)

    m_launch_counter = generate_cd = property_i32(0x58, """
        子弹生成 / 物品生产倒计时
                                       
        初值为 max_boot_delay - 14 到 max_boot_delay
        """)

    m_launch_rate = max_boot_delay = property_i32(0x5c, """
        generate_cd 的最大值
                                          
        对大多数植物为 150，对投手为 300，忧郁菇为 200
        """)

    m_shooting_counter = launch_cd = property_i32(0x90, """
        从准备发射到发射子弹的倒计时
                                     
        **这里有坑, 平常常见的大喷49等数据是两个数据做减法减出来的而不是存在这里的直接数据**
        对于 ize 常见单发植物, 均在 generate_cd == 0时修改 launch_cd, launch_cd == 1时候打出子弹.
        其他时候恒为0值.
        ize 植物与 launch_cd 初始数值的关系如下:
            - 豌豆/冰豆/裂荚右: 35
            - 双发/裂荚左 :26
            - 小喷: 29
            - 大喷: 50
            - 杨桃: 40
            - 玉米: 30
            - 胆小: 25
        简单认为攻击所需时间为(上述数值 - 1)即可.
        
        胆小的规律较为复杂:
            - 胆小在 launch_cd == 0的时候检测身边僵尸以决定自己是不是缩头
            - 胆小攻击基本规律同上, 同样在== 1时打出子弹
            - 在不是正常站立时, 胆小个人每帧更新 generate_cd = 150
        因而, 胆小在常态情况时每帧判断一次周围僵尸决定缩头, 但在攻击前兆时不判断.
        之前零度误认为胆小索敌成功到发射为25也可能源于此, 实际上还是取24更为合适.
        
        对于ize常见双发植物(双发/裂荚左):
            在 generate_cd == 25的时候改动一次 launch_cd = 26, 即25后打出子弹
            在 generate_cd == 0时再改改动一次 launch_cd = 26
        """)

    m_dead = is_dead = property_bool(0x141, "死亡时为 True")

    @property
    def target_zombie_id(self) -> ObjId:  # mTargetZombieID
        """倭瓜, 水草目标僵尸编号"""
        return ObjId(self.base_ptr + 0x12c, self.controller)

    def __str__(self) -> str:
        if not self.is_dead:
            return f"#{self.id.index} {self.type_.name} at {self.row + 1}-{self.col + 1}"
        return "dead plant"

    def die(self) -> None:
        """
        令自己死亡
        """
        code = f"""
            push {self.base_ptr}
            call {0x4679b0}  // Plant::Die
            ret"""
        asm.run(code, self.controller)


class PlantList(obj_list(Plant)):
    """
    植物 DataArray
    """
    def get_by_grid(self, row: int, col: int) -> Plant | None:
        """
        通过row, col找到对应植物
        
        获取编号最小的. 不支持南瓜花盆一类获取所有植物, 更不支持叠种.
        
        Args:
            row: 行数, 从0开始
            col: 列数, 从0开始
        Returns:
            对应位置编号最小的植物, 找不到返回None
        """
        code = f"""
            push esi
            push edi
            mov esi, {self.controller.result_address}
            xor eax, eax
            mov [esi], eax
            mov eax, [0x6a9ec0]
            mov edi, [eax + 0x768]

            LIterate:
                mov {Plant.ITERATOR_P_BOARD_REG}, edi
                call {Plant.ITERATOR_FUNC_ADDRESS}  // Board::IteratePlant
                test al, al
                jz LNoResult
                mov eax, [esi]  // eax = Plant*
                cmp dword ptr [eax + {Plant.row.offset}], {row}
                jne LIterate
                cmp dword ptr [eax + {Plant.col.offset}], {col}
                jne LIterate
                pop edi
                pop esi
                ret

            LNoResult:
                xor eax, eax
                mov [esi], eax
                pop edi
                pop esi
                ret"""
        asm.run(code, self.controller)
        if (result := self.controller.result_u32) != 0:
            return Plant(result, self.controller)
        return None

    def free_all(self) -> typing.Self:
        code = f"""
            push esi
            push edi
            mov eax, [0x6a9ec0]
            mov edi, [eax + 0x768]
            mov esi, {self.controller.result_address}
            xor edx, edx
            mov [esi], edx  // mov [esi], 0 is invalid
            LIterate:
                mov {Plant.ITERATOR_P_BOARD_REG}, edi
                call {Plant.ITERATOR_FUNC_ADDRESS}  // Board::IteratePlant
                test al, al
                jz LFreeAll
                push dword ptr [esi]
                call {0x4679b0}  // Plant::Die
                jmp LIterate
                
            LFreeAll:
                mov eax, {self.base_ptr}
                call {0x41E590} // DataArray<Plant>::DataArrayFreeAll
                pop edi
                pop esi
                ret"""
        asm.run(code, self.controller)
        return self

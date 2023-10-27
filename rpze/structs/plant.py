# -*- coding: utf_8 -*-
"""
植物相关的枚举和类
"""
from enum import IntEnum

import basic.asm as asm
import structs.obj_base as ob
from rp_extend import Controller
from structs.obj_base import ObjNode


class PlantType(IntEnum):
    none = -1,
    pea_shooter = 0x0,
    sunflower = 0x1,
    cherry_bomb = 0x2,
    wallnut = 0x3,
    potato_mine = 0x4,
    snow_pea = 0x5,
    chomper = 0x6,
    repeater = 0x7,
    puffshroom = 0x8,
    sunshroom = 0x9,
    fumeshroom = 0xA,
    grave_buster = 0xB,
    hypnoshroom = 0xC,
    scaredyshroom = 0xD,
    iceshroom = 0xE,
    doomshroom = 0xF,
    lily_pad = 0x10,
    squash = 0x11,
    threepeater = 0x12,
    tangle_kelp = 0x13,
    jalapeno = 0x14,
    spikeweed = 0x15,
    torchwood = 0x16,
    tallnut = 0x17,
    seashroom = 0x18,
    plantern = 0x19,
    cactus = 0x1a,
    blover = 0x1b,
    split_pea = 0x1c,
    starfruit = 0x1d,
    pumpkin = 0x1e,
    magnetshroom = 0x1f,
    cabbagepult = 0x20,
    flower_pot = 0x21,
    kernelpult = 0x22,
    coffee_bean = 0x23,
    garlic = 0x24,
    umbrella_leaf = 0x25,
    marigold = 0x26,
    melonpult = 0x27,
    gatling_pea = 0x28,
    twin_sunflower = 0x29,
    gloomshroom = 0x2A,
    cattail = 0x2B,
    winter_melon = 0x2C,
    gold_magnet = 0x2D,
    spikerock = 0x2E,
    cob_cannon = 0x2F,
    imitater = 0x30


class PlantStatus(IntEnum):
    idle = 0x0,
    wait = 0x1,
    work = 0x2,
    squash_look = 0x3,
    squash_jump_up = 0x4,
    squash_stop_in_the_air = 0x5,
    squash_jump_down = 0x6,
    squash_crushed = 0x7,
    grave_buster_land = 0x8,
    grave_buster_idle = 0x9,
    chomper_bite_begin = 0xA,
    chomper_bite_success = 0xB,
    chomper_bite_fail = 0xC,
    chomper_chew = 0xD,
    chomper_swallow = 0xE,
    potato_sprout_out = 0xF,
    potato_armed = 0x10,
    spike_attack = 0x12,
    scaredyshroom_scared = 0x14,
    scaredyshroom_scared_idle = 0x15,
    scaredyshroom_grow = 0x16,
    sunshroom_small = 0x17,
    sunshroom_grow = 0x18,
    sunshroom_big = 0x19,
    magnetshroom_working = 0x1A,
    magnetshroom_inactive_idle = 0x1B,
    cactus_short_idle = 0x1E,
    cactus_grow_tall = 0x1F,
    cactus_tall_idle = 0x20,
    cactus_get_short = 0x21,
    tangle_kelp_grab = 0x22,
    cob_cannon_unaramed_idle = 0x23,
    cob_cannon_charge = 0x24,
    cob_cannon_launch = 0x25,
    cob_cannon_armed_idle = 0x26,
    kernelpult_launch_butter = 0x27,
    umbrella_leaf_block = 0x28,
    umbrella_leaf_shrink = 0x29,
    imitater_explode = 0x2A,
    flower_pot_placed = 0x2F,
    lily_pad_placed = 0x30


class Plant(ObjNode):
    ITERATOR_FUNC_ADDRESS = 0x41c950

    OBJ_SIZE = 0x14c

    x: int = ob.property_i32(0x8, "x")

    y: int = ob.property_i32(0xc, "y")

    visible: bool = ob.property_bool(0x18, "可见时为True")

    row: int = ob.property_i32(0x1c, "所在行数, 起点为0")

    type_: PlantType = ob.property_int_enum(0x24, PlantType, "植物类型")

    col: int = ob.property_i32(0x28, "所在列数, 起点为0")

    status: PlantStatus = ob.property_int_enum(0x3c, PlantStatus, "植物状态")

    hp: int = ob.property_i32(0x40, "当前血量")

    status_cd: int = ob.property_i32(0x54, """
        属性倒计时, 如磁铁cd
                                     
        地刺攻击倒计时也在这儿:
            地刺的判断和generate_cd无关. 在范围内有僵尸时使status_cd = 100, == 75时打出攻击
        """)

    generate_cd: int = ob.property_i32(0x58, """
        子弹生成 / 物品生产倒计时
                                       
        初值为max_boot_delay - 14到max_boot_delay
        """)

    max_boot_delay: int = ob.property_i32(0x5c, """
        generate_cd的最大值
                                          
        对大多数植物为150，对投手为300，曾为200
        """)

    launch_cd: int = ob.property_i32(0x90, """
        从准备发射到发射子弹的倒计时
                                     
        **这里有坑, 平常常见的大喷49等数据是两个数据做减法减出来的而不是存在这里的直接数据**
        对于ize常见单发植物, 均在generate_cd == 0时修改launch_cd, launch_cd == 1时候打出子弹.
        其他时候恒为0值.
        ize植物与launch_cd初始数值的关系如下:
            - 豌豆/冰豆/裂荚右: 35
            - 双发/裂荚左 :26
            - 小喷: 29
            - 大喷: 50
            - 杨桃: 40
            - 玉米: 30
            - 胆小: 25
        简单认为攻击所需时间为(上述数值 - 1)即可.
        
        胆小的规律较为复杂:
            - 胆小在launch_cd == 0的时候检测身边僵尸以决定自己是不是缩头
            - 胆小攻击基本规律同上,   同样在== 1时打出子弹
            - 在不是正常站立时, 胆小个人每帧更新generate_cd = 150
        因而, 胆小在常态情况时每帧判断一次周围僵尸决定缩头, 但在攻击前兆时不判断.
        之前零度误认为胆小索敌成功到发射为25也可能源于此, 实际上还是取24更为合适.
        
        对于ize常见双发植物(双发/裂荚左):
            在generate_cd == 25的时候改动一次launch_cd = 26, 即25后打出子弹
            在generate_cd == 0时再改改动一次launch_cd = 26
        """)

    can_attack: bool = ob.property_bool(0x48, "能攻击时为True")

    is_dead: bool = ob.property_bool(0x141, "死亡时为True")
    
    @property
    def target_zombie_id(self) -> ob.ObjId:
        """倭瓜, 水草目标僵尸编号"""
        return ob.ObjId(self.base_ptr + 0x12c, self.controller)

    def __str__(self) -> str:
        return f"#{self.id.index} {self.type_.name} at {self.row + 1}-{self.col + 1}"


class PlantList(ob.obj_list(Plant)):
    def plain_new_plant(self, row: int, col: int, type_: PlantType) -> Plant:
        p_board = self.controller.read_i32([0x6a9ec0, 0x768])
        code = f'''
            push edx;
            push -1;
            push {int(type_)};
            push {row};
            push {col};
            mov eax, {p_board};
            mov edx, 0x40CE20;  // Board::NewPlant
            call edx;
            mov [{self.controller.result_address}], eax;
            pop edx;
            ret;'''
        asm.run(code, self.controller)
        return Plant(self.controller.result_u32, self.controller)


def get_plant_list(ctler: Controller) -> PlantList:
    if (t := ctler.read_i32([0x6a9ec0, 0x768])) is None:
        raise RuntimeError("game base ptr not found")
    else:
        return PlantList(t + 0xac, ctler)

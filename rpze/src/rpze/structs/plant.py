# -*- coding: utf_8 -*-
"""
植物相关的枚举和类
"""
import random
import typing
from enum import IntEnum

from . import obj_base as ob
from ..basic import asm
from .obj_base import ObjNode


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
        return ob.ObjId(self.base_ptr + 0x12c, self._controller)

    def __str__(self) -> str:
        return f"#{self.id.index} {self.type_.name} at {self.row + 1}-{self.col + 1}"

    def die(self):
        """
        令自己死亡
        """
        code = f"""
            push {self.base_ptr};
            mov edx, {0x4679b0};  // Plant::Die
            call edx;
            ret;"""
        asm.run(code, self._controller)

    def randomize_generate_cd(self) -> typing.Self:
        """
        令自己的generate_cd按照"放置充分长时间"后的结果随机化.
        **仅对can_attack == True植物有效**

        具体来说. 其generate_cd概率分布图像为一个梯形:
        上底为max_boot_delay - 14, 下底为max_boot_delay.

        Returns:
            返回自己
        """
        if not self.can_attack:
            return self
        # 拆成[0, max_boot_delay - 14)和[max_boot_delay - 14, max_boot_delay]两个区间
        # 注意可以取0...
        # h * (max_boot_delay - 14) + (h + 0) * 15 / 2 = 1解这个方程, h为梯形的高
        h = 1 / ((max_ := self.max_boot_delay) - 6.5)
        distribute = ([h] * (max_ - 14)).extend([h / 15 * i for i in range(14, -1, -1)])
        self.generate_cd = random.choices(population=range(max_ + 1), weights=distribute)[0]
        return self


class PlantList(ob.obj_list(Plant)):
    def get_by_pos(self, row: int, col: int) -> Plant | None:
        """
        通过row, col找到对应植物
        
        获取编号最小的. 不支持南瓜花盆一类获取所有植物, 更不支持叠种.
        
        Args:
            row: 行数, 从0开始
            col: 列数, 从0开始
        Returns:
            对应位置编号最小的植物, 找不到返回None
        """
        for plant in ~self:
            if plant.row == row and plant.col == col:
                return plant
        return None

    @typing.overload
    def __getitem__(self, grid_str: str) -> Plant:
        """
        通过grid_str坐标获取植物

        Args:
            grid_str: 格子字符串
        Returns:
            对应位置编号最小的植物, 找不到返回None
        """

    def __getitem__(self, item):
        if isinstance(item, str):
            row, col = ob.parse_grid_str(item)
            return self.get_by_pos(row, col)
        return super().__getitem__(item)

    def free_all(self) -> typing.Self:
        p_board = self._controller.get_p_board()[1]
        code = f"""
            push esi;
            push ebx;
            push edi;
            mov ebx, {Plant.ITERATOR_FUNC_ADDRESS};
            mov edi, {0x4679b0};
            mov esi, {self._controller.result_address};
            xor edx, edx;
            mov [esi], edx;  // mov [esi], 0 is invalid
            LIterate:
                mov edx, {p_board};
                call ebx;  // Board::IteratePlant
                test al, al;
                jz LFreeAll;
                push dword ptr [esi];
                call edi;  // Plant::Die
                jmp LIterate;
                
            LFreeAll:
                mov eax, {self.base_ptr};
                mov edx, {0x41E590}; // DataArray<Plant>::DataArrayFreeAll
                call edx;
                pop edi;
                pop ebx;
                pop esi;
                ret;"""
        asm.run(code, self._controller)
        return self

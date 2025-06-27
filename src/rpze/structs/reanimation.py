# -*- coding: utf_8 -*-
"""
描述 pvz 中动画文件 Reanimation 的相关结构
"""
from enum import IntEnum
from typing import Self

from .obj_base import ObjNode, property_bool, obj_list, property_i32, property_int_enum
from ..basic import asm


class ReanimationType(IntEnum):
    NONE = -1,
    LOADBAR_SPROUT = 0,
    LOADBAR_ZOMBIEHEAD = 1,
    SODROLL = 2,
    FINAL_WAVE = 3,
    PEASHOOTER = 4,
    WALLNUT = 5,
    LILYPAD = 6,
    SUNFLOWER = 7,
    LAWNMOWER = 8,
    READYSETPLANT = 9,
    CHERRYBOMB = 10,
    SQUASH = 11,
    DOOMSHROOM = 12,
    SNOWPEA = 13,
    REPEATER = 14,
    SUNSHROOM = 15,
    TALLNUT = 16,
    FUMESHROOM = 17,
    PUFFSHROOM = 18,
    HYPNOSHROOM = 19,
    CHOMPER = 20,
    ZOMBIE = 21,
    SUN = 22,
    POTATOMINE = 23,
    SPIKEWEED = 24,
    SPIKEROCK = 25,
    THREEPEATER = 26,
    MARIGOLD = 27,
    ICESHROOM = 28,
    ZOMBIE_FOOTBALL = 29,
    ZOMBIE_NEWSPAPER = 30,
    ZOMBIE_ZAMBONI = 31,
    SPLASH = 32,
    JALAPENO = 33,
    JALAPENO_FIRE = 34,
    COIN_SILVER = 35,
    ZOMBIE_CHARRED = 36,
    ZOMBIE_CHARRED_IMP = 37,
    ZOMBIE_CHARRED_DIGGER = 38,
    ZOMBIE_CHARRED_ZAMBONI = 39,
    ZOMBIE_CHARRED_CATAPULT = 40,
    ZOMBIE_CHARRED_GARGANTUAR = 41,
    SCRAREYSHROOM = 42,
    PUMPKIN = 43,
    PLANTERN = 44,
    TORCHWOOD = 45,
    SPLITPEA = 46,
    SEASHROOM = 47,
    BLOVER = 48,
    FLOWER_POT = 49,
    CACTUS = 50,
    DANCER = 51,
    TANGLEKELP = 52,
    STARFRUIT = 53,
    POLEVAULTER = 54,
    BALLOON = 55,
    GARGANTUAR = 56,
    IMP = 57,
    DIGGER = 58,
    DIGGER_DIRT = 59,
    ZOMBIE_DOLPHINRIDER = 60,
    POGO = 61,
    BACKUP_DANCER = 62,
    BOBSLED = 63,
    JACKINTHEBOX = 64,
    SNORKEL = 65,
    BUNGEE = 66,
    CATAPULT = 67,
    LADDER = 68,
    PUFF = 69,
    SLEEPING = 70,
    GRAVE_BUSTER = 71,
    ZOMBIES_WON = 72,
    MAGNETSHROOM = 73,
    BOSS = 74,
    CABBAGEPULT = 75,
    KERNELPULT = 76,
    MELONPULT = 77,
    COFFEEBEAN = 78,
    UMBRELLALEAF = 79,
    GATLINGPEA = 80,
    CATTAIL = 81,
    GLOOMSHROOM = 82,
    BOSS_ICEBALL = 83,
    BOSS_FIREBALL = 84,
    COBCANNON = 85,
    GARLIC = 86,
    GOLD_MAGNET = 87,
    WINTER_MELON = 88,
    TWIN_SUNFLOWER = 89,
    POOL_CLEANER = 90,
    ROOF_CLEANER = 91,
    FIRE_PEA = 92,
    IMITATER = 93,
    YETI = 94,
    BOSS_DRIVER = 95,
    LAWN_MOWERED_ZOMBIE = 96,
    CRAZY_DAVE = 97,
    TEXT_FADE_ON = 98,
    HAMMER = 99,
    SLOT_MACHINE_HANDLE = 100,
    CREDITS_FOOTBALL = 101,
    CREDITS_JACKBOX = 102,
    SELECTOR_SCREEN = 103,
    PORTAL_CIRCLE = 104,
    PORTAL_SQUARE = 105,
    ZENGARDEN_SPROUT = 106,
    ZENGARDEN_WATERINGCAN = 107,
    ZENGARDEN_FERTILIZER = 108,
    ZENGARDEN_BUGSPRAY = 109,
    ZENGARDEN_PHONOGRAPH = 110,
    DIAMOND = 111,
    ZOMBIE_HAND = 112,
    STINKY = 113,
    RAKE = 114,
    RAIN_CIRCLE = 115,
    RAIN_SPLASH = 116,
    ZOMBIE_SURPRISE = 117,
    COIN_GOLD = 118,
    TREE_OF_WISDOM = 119,
    TREE_OF_WISDOM_CLOUDS = 120,
    TREE_FOOD = 121,
    CREDITS_MAIN = 122,
    CREDITS_MAIN2 = 123,
    CREDITS_MAIN3 = 124,
    ZOMBIE_CREDITS_DANCE = 125,
    CREDITS_STAGE = 126,
    CREDITS_BIGBRAIN = 127,
    CREDITS_FLOWER_PETALS = 128,
    CREDITS_INFANTRY = 129,
    CREDITS_THROAT = 130,
    CREDITS_CRAZYDAVE = 131,
    CREDITS_BOSSDANCE = 132,
    ZOMBIE_CREDITS_SCREEN_DOOR = 133,
    ZOMBIE_CREDITS_CONEHEAD = 134,
    CREDITS_ZOMBIEARMY1 = 135,
    CREDITS_ZOMBIEARMY2 = 136,
    CREDITS_TOMBSTONES = 137,
    CREDITS_SOLARPOWER = 138,
    CREDITS_ANYHOUR = 139,
    CREDITS_WEARETHEUNDEAD = 140,
    CREDITS_DISCOLIGHTS = 141,


class Reanimation(ObjNode):
    """
    动画对象
    """
    OBJ_SIZE = 0xa0

    m_reanimation_type = property_int_enum(0x0, ReanimationType, "动画类型")

    m_dead = is_dead = property_bool(0x14, "is dead")

    m_frame_start = property_i32(0x18, "动画从第几帧开始")

    ITERATOR_FUNC_ADDRESS = 0x41CB90

    ITERATOR_P_BOARD_REG = "eax"

    def get_track_velocity(self) -> float:
        """
        取得动画 _ground 轨道的横向瞬时速度

        Returns:
            从当前帧至下一帧的横向位移 * 动画速率 * 0.01

            若动画不存在 _ground 轨道, 则在获取轨道序号时会返回第 0 个轨道, 取得的速度亦为该轨道的瞬时速度.
        """
        ctler = self.controller
        code = f"""
            mov eax, {self.base_ptr}
            mov edx, {0x4738D0} // Reanimation::GetTrackVelocity(eax = Reanimation* this)
            call edx
            fstp qword ptr[{ctler.result_address}]
            ret"""
        asm.run(code, ctler)
        return ctler.result_f64


class ReanimationList(obj_list(Reanimation)):
    """
    动画对象 DataArray
    """

    def free_all(self) -> Self:
        code = f"""
            push ebx
            push edi
            push esi
            mov eax, [0x6a9ec0]
            mov edi, [eax + 0x768]
            mov esi, {self.controller.result_address}
            xor edx, edx
            mov [esi], edx  // esi for ra, edi for board
            LIterate:
                mov {Reanimation.ITERATOR_P_BOARD_REG}, edi
                call {Reanimation.ITERATOR_FUNC_ADDRESS}  // Board::IterateReanim
                test al, al
                jz LFreeAll
                mov ecx, [esi]
                call {0x4733F0}  // Reanimation::ReanimationDie(ecx)
                jmp LIterate
                
            LFreeAll:
                mov ebx, {self.base_ptr}
                call {0x446a80}  // DataArray<Zombie>::DataArrayFreeAll(ebx)
                pop esi
                pop edi
                pop ebx
                ret"""

        asm.run(code, self.controller)
        return self

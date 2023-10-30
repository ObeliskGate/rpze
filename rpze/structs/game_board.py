# -*- coding: utf_8 -*-
"""
游戏主界面相关的函数和类
"""
import functools

import structs.obj_base as ob
from structs.griditem import GriditemList
from structs.plant import PlantList, Plant
from structs.projectile import ProjectileList
from rp_extend import Controller
from structs.zombie import ZombieList
import basic.asm as asm


class GameBoard(ob.ObjBase):
    """
    函数表中Board对象

    增加了一些不属于Board类的方法和属性(大部分为LawnApp和Challenge的), 故命名为GameBoard以示区分.

    Attributes:
        zombie_list: 僵尸列表
        plant_list: 植物列表
        projectile_list: 子弹列表
        griditem_list: 场地物品列表
    """
    OBJ_SIZE = 0x57b0

    def __init__(self, base_ptr: int, controller: Controller):
        super().__init__(base_ptr, controller)
        self.zombie_list: ZombieList = ZombieList(base_ptr + 0x90, controller)
        self.plant_list: PlantList = PlantList(base_ptr + 0xac, controller)
        self.projectile_list: ProjectileList = ProjectileList(base_ptr + 0xc8, controller)
        self.griditem_list: GriditemList = GriditemList(base_ptr + 0x11c, controller)

    _p_challenge: int = ob.property_i32(0x160, "Challenge对象指针")

    is_dance_mode: bool = ob.property_bool(0x5765, "在dance秘籍时中为True")

    sun_num: int = ob.property_i32(0x5560, "阳光数量")

    @property
    def game_time(self):
        """游戏时间(包括选卡停留的时间)"""
        return self.controller.get_time()

    @property
    def mj_clock(self) -> int:
        """mj时钟"""
        return self.controller.read_i32([0x6a9ec0, 0x838])  # 我真看不懂为什么mj时钟在LawnApp底下啊

    @mj_clock.setter
    def mj_clock(self, value: int):
        self.controller.write_i32(value, [0x6a9ec0, 0x838])

    def set_izombie(self, plant: Plant):
        """
        对植物进行IZ模式调整, 如纸板化, 土豆出土

        Args:
            plant: 要调整的植物
        """
        code = f"""
            mov eax, {self._p_challenge};
            push {plant.base_ptr};
            mov ecx, 0x42A530; // Challenge::IZombieSetupPlant
            call ecx;
            ret;"""
        asm.run(code, self.controller)


@functools.lru_cache(maxsize=None)
def get(controller: Controller) -> GameBoard:
    """
    获取当前游戏主界面对象

    Args:
        controller: pvz控制器对象
    Returns:
        当前游戏主界面对象
    """
    return GameBoard(controller.read_u32([0x6a9ec0, 0x768]), controller)

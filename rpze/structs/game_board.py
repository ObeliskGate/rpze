# -*- coding: utf_8 -*-
"""
游戏主界面相关的函数和类
"""

import structs.obj_base as ob
from structs.griditem import GriditemList, Griditem, GriditemType
from structs.plant import PlantList, Plant, PlantType
from structs.projectile import ProjectileList
from rp_extend import Controller
from structs.zombie import ZombieList, ZombieType
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

    _p_challenge: int = ob.property_u32(0x160, "Challenge对象指针")

    is_dance_mode: bool = ob.property_bool(0x5765, "在dance秘籍时中为True")

    sun_num: int = ob.property_i32(0x5560, "阳光数量")

    @property
    def game_time(self):
        """游戏时间(包括选卡停留的时间)"""
        return self._controller.get_time()

    @property
    def mj_clock(self) -> int:
        """mj时钟"""
        return self._controller.read_i32([0x6a9ec0, 0x838])  # 我真看不懂为什么mj时钟在LawnApp底下啊

    @mj_clock.setter
    def mj_clock(self, value: int):
        self._controller.write_i32(value, [0x6a9ec0, 0x838])

    def iz_setup_plant(self, plant: Plant):
        """
        对植物进行IZ模式调整, 如纸板化, 土豆出土

        Args:
            plant: 要调整的植物
        Raises:
            ValueError: Challenge对象不存在时抛出
        """
        if not (p_c := self._p_challenge):
            raise ValueError("Challenge object doesn't exist!")
        code = f"""
            mov eax, {p_c};
            push {plant.base_ptr};
            mov ecx, 0x42A530; // Challenge::IZombieSetupPlant
            call ecx;
            ret;"""
        asm.run(code, self._controller)

    def plain_new_plant(self, row: int, col: int, type_: PlantType) -> Plant:
        """
        关卡内种植植物
        
        此函数不会创建种植的音、特效且不会触发限制种植类关卡种植特定植物的特殊效果.
        
        Args:
            row: 行, 从0开始
            col: 列, 从0开始
            type_: 植物类型
        Returns:
            种植成功的植物对象
        """
        code = f'''
            push -1;
            push {int(type_)};
            push {row};
            push {col};
            mov eax, {self.base_ptr};
            mov edx, 0x40CE20;  // Board::NewPlant
            call edx;
            mov [{self._controller.result_address}], eax;
            ret;'''
        asm.run(code, self._controller)
        return Plant(self._controller.result_u32, self._controller)
    
    def iz_new_plant(self, row: int, col: int, type_: PlantType) -> Plant | None:
        """
        判断植物能否种植在指定格子内, 若能则种植植物并对植物进行我是僵尸关卡的特殊调整.

        Args:
            row: 行数, 0为起点
            col: 列数, 0为起点
            type_: 植物类型
        Returns:
            成功则返回植物对象, 否则返回None
        Raises:
            ValueError: Challenge对象不存在时抛出
        """
        if not (p_c := self._p_challenge):
            raise ValueError("Challenge object doesn't exist!")
        next_idx = self.plant_list.next_index
        code = f"""
            push ebx;
            push edi;
            mov ebx, {row};
            push {col};
            push {int(type_)};
            mov edi, {p_c};
            mov ecx, 0x42a660; // Challenge::IZombiePlacePlantInSquare
            call ecx;  
            pop edi;
            pop ebx;
            ret;"""
        asm.run(code, self._controller)
        return self.plant_list.find(next_idx)
    
    def iz_place_zombie(self, row: int, col: int, type_: ZombieType):
        """
        向指定位置放置僵尸.

        Args:
            row: 行数, 0为起点
            col: 列数, 0为起点
            type_: 僵尸
        Returns:
            放置的僵尸对象
        Raises:
            ValueError: Challenge对象不存在时抛出
        """
        if not (p_c := self._p_challenge):
            raise ValueError("Challenge object doesn't exist!")
        ret_idx = self.zombie_list.next_index
        if p_c != (t := self._controller.read_u32([self.base_ptr + 0x160])):
            print(p_c, t)
        code = f'''
            mov eax, {row};
            push {col};
            push {int(type_)};
            mov ecx, {p_c};
            mov edx, 0x42a0f0;
            call edx;
            ret;'''
        asm.run(code, self._controller)
        return self.zombie_list.at(ret_idx)

    def pixel_to_col(self, x: int, y: int = 0) -> int:
        """
        将坐标转换为列数

        Args:
            x: x坐标
            y: y坐标, 仅在禅境花园有用
        Returns:
            对应的列数, 0开始
        """
        code = f"""
            push edi;
            mov edi, {y};
            mov eax, {x};
            mov ecx, {self.base_ptr};
            mov edx, {0x41c4c0};  // Board::PixelToGridX 
            call edx;
            mov [{self._controller.result_address}], eax;
            pop edi;
            ret;"""
        asm.run(code, self._controller)
        return self._controller.result_i32

    def pixel_to_row(self, x: int, y: int) -> int:
        """
        将坐标转换为行数

        Args:
            x: x坐标
            y: y坐标
        Returns:
            对应的行数, 0开始, 对地图外的点, 返回-1
        """
        code = f"""
            push ebx;
            mov ecx, {y};
            mov eax, {x};
            mov edx, {self.base_ptr};
            mov ebx, {0x41c550};  // Board::PixelToGridY
            call ebx;
            mov [{self._controller.result_address}], eax;
            pop ebx;
            ret;"""
        asm.run(code, self._controller)
        return self._controller.result_i32

    def pixel_to_grid(self, x: int, y: int) -> tuple[int, int]:
        """
        将坐标转换为行列

        Args:
            x: x坐标
            y: y坐标
        Returns:
            (row, col)元组， 均从0开始
        """
        return self.pixel_to_row(x, y), self.pixel_to_col(x, y)

    def grid_to_pixel_x(self, col: int, row: int = 0):
        """
        将行列转换为x坐标

        **请注意参数顺序!!!**

        Args:
            col: 列数, 0开始
            row: 行数, 0开始, 仅在禅境花园有用
        Returns:
            对应的x坐标
        """
        code = f"""
            push esi;
            mov esi, {row};
            mov eax, {col};
            mov ecx, {self.base_ptr};
            mov edx, {0x41C680};  // Board::GridToPixelX
            call edx;
            mov [{self._controller.result_address}], eax;
            pop esi;
            ret;"""
        asm.run(code, self._controller)
        return self._controller.result_i32

    def grid_to_pixel_y(self, row: int, col: int) -> int:
        """
        将行列转换为y坐标

        Args:
            row: 行数, 0开始
            col: 列数, 0开始
        Returns:
            对应的y坐标
        """
        code = f"""
            push ebx;
            mov ebx, {self.base_ptr};
            mov eax, {row};
            mov ecx, {col};
            mov edx, {0x41c740};  // Board::GridToPixelY
            call edx;
            mov [{self._controller.result_address}], eax;
            pop ebx;
            ret;"""
        asm.run(code, self._controller)
        return self._controller.result_i32

    def grid_to_pixel(self, row: int, col: int) -> tuple[int, int]:
        """
        将行列转换为像素坐标

        Args:
            row: 行数, 0开始
            col: 列数, 0开始
        Returns:
            (x, y)元组
        """
        return self.grid_to_pixel_x(col, row), self.grid_to_pixel_y(row, col)

    def new_iz_brain(self, row: int) -> Griditem:  # 我非常无语为什么这个函数原版没有
        """
        构造一个新的IZ脑子, 用于我是僵尸关卡

        Args:
            row: 构造所在行, 0开始
        Returns:
            构造的IZ脑子
        """
        ret = self.griditem_list.alloc_item()
        ret.type_ = GriditemType.brain
        ret.row = row
        ret.col = 0
        ret.layer = 302000 + 10000 * row  # from cvp
        ret.brain_hp = 70
        ret.x = float(self.grid_to_pixel_x(0, 0) - 40)
        ret.y = float(self.grid_to_pixel_y(row, 0) + 40)
        return ret


__game_board_cache = None  # 重复构造对象会导致多次decode字节码, 故缓存.


def get_board(controller: Controller | None = None) -> GameBoard:
    """
    获取当前游戏主界面对象

    Args:
        controller: pvz控制器对象. 当为None时, 取得上一个缓存的GameBoard对象.
    Returns:
        当前游戏主界面对象
    Raises:
        RuntimeError: Board对象不存在时抛出
    """
    global __game_board_cache
    if controller is None:
        if __game_board_cache is None:
            raise RuntimeError("Board object doesn't exist!")
        return __game_board_cache
    valid, p_board = controller.get_p_board()
    if not p_board:  # 期待Board对象存在, 用异常不用Optional
        raise RuntimeError("Board object doesn't exist!")
    if (not valid) or (__game_board_cache is None):
        __game_board_cache = GameBoard(p_board, controller)
    return __game_board_cache

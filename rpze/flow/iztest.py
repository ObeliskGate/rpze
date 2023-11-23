# -*- coding: utf_8 -*-
"""
iztools 全场测试功能模拟
"""
from collections.abc import Callable
from random import randint
from typing import TypeAlias, Self, Any

from flow.flow import FlowFactory, TickRunnerResult, FlowManager
from flow.utils import until
from rp_extend import Controller
from structs.game_board import GameBoard, get_board
from structs.griditem import Griditem
from structs.plant import PlantType, Plant
from structs.zombie import ZombieType
from collections import namedtuple

plant_abbr_to_type: dict[str, PlantType] = {
    ".": PlantType.none,
    "1": PlantType.pea_shooter,
    "h": PlantType.sunflower,
    "o": PlantType.wallnut,
    "t": PlantType.potato_mine,
    "b": PlantType.snow_pea,
    "z": PlantType.chomper,
    "2": PlantType.repeater,
    "p": PlantType.puffshroom,
    "d": PlantType.doomshroom,
    "x": PlantType.scaredyshroom,
    "w": PlantType.squash,
    "3": PlantType.threepeater,
    "_": PlantType.spikeweed,
    "j": PlantType.torchwood,
    "l": PlantType.split_pea,
    "5": PlantType.starfruit,
    "c": PlantType.magnetshroom,
    "y": PlantType.kernelpult,
    "s": PlantType.umbrella_leaf
}
zombie_abbr_to_type: dict[str, ZombieType] = {
    "xg": ZombieType.imp,
    "lz": ZombieType.conehead,
    "cg": ZombieType.pole_vaulting,
    "tt": ZombieType.buckethead,
    "bj": ZombieType.bungee, "xt": ZombieType.bungee,
    "kg": ZombieType.digger,
    "tz": ZombieType.ladder, "ft": ZombieType.ladder,
    "gl": ZombieType.football,
    "ww": ZombieType.dancing, "mj": ZombieType.dancing
}
PlaceZombieOp = namedtuple("PlaceZombieOp", ["type_", "time", "row", "col"])
"""
描述僵尸放置操作的对象

Attributes:
    type_ (ZombieType) : 要放置的僵尸类型
    time (int) : 放置的时间
    row (int) : 放置的行, 从0开始
    col (int) : 放置的列, 从0开始
"""  # Pycharm这里不显示docstring的Attributes
PlantTypeList: TypeAlias = list[list[PlantType | None]]


def parse_grid_str(grid_str: str, minus_one: bool = True) -> tuple[int, int]:
    """
    根据f'{row}-{col}'字符串返回(row, col)对象

    Args:
        grid_str: 形如'1-2'的字符串
        minus_one: 为True时会自动为row, col减1，使其从0开始
    Returns:
        (row, col)元组
    """
    return (int(grid_str.split('-')[0]) - 1, int(grid_str.split('-')[1]) - 1) if minus_one else \
        (int(grid_str.split('-')[0]), int(grid_str.split('-')[1]))


def parse_plant_type_list(plant_type_str: str) -> tuple[PlantTypeList, PlantTypeList]:
    """
    根据iztools植物字符串生成植物列表

    使用+号表示延迟一轮种植, 即"调控栈位".

    Args:
        plant_type_str: 与izt要求相同的植物列表字符串.
    Returns:
        两个5 * 5列表, 分别表示第一轮, 第二轮种植的植物. 空白值由None(而非PlantType.none)填充
    Raises:
        ValueError: plant_type_string格式错误时抛出
    """
    first_list: list[list[PlantType | None]] = [[None for _ in range(5)] for _ in range(5)]
    second_list: list[list[PlantType | None]] = [[None for _ in range(5)] for _ in range(5)]
    lines = plant_type_str.strip().splitlines(False)
    if (t := len(lines)) != 5:
        raise ValueError(f"plant_type_string must have 5 lines, instead of {t} lines")
    for row, line in enumerate(lines):
        line = line.strip()
        plus_plant_indices = [i - 1 for i, char in enumerate(line) if char == '+']
        if not plus_plant_indices:
            if (t := len(line)) != 5:
                raise ValueError(f"line {row} must have 5 plants, instead of {t} plants")
            first_list[row] = [(plant_abbr_to_type[abbr] if abbr != '.' else None) for abbr in line]
        else:
            if plus_plant_indices[0] == -1:
                raise ValueError(f"line {row} can't start with +")
            col = 0
            for (i, char) in enumerate(line):
                if char == "+":
                    continue
                if i in plus_plant_indices:
                    second_list[row][col] = plant_abbr_to_type[char] if char != '.' else None
                else:
                    first_list[row][col] = plant_abbr_to_type[char] if char != '.' else None
                col += 1
            if col != 5:
                raise ValueError(f"line {row} must have 5 plants, instead of {t} plants")
    return first_list, second_list


def parse_target_list(target_str: str) -> tuple[list[tuple[int, int]], list[int]]:
    """
    根据iztools目标字符串生成目标列表

    Args:
        target_str: 与izt要求相同的目标字符串
    Returns:
        两个列表, 分别表示目标植物和目标脑子的位置
    """
    poses = [parse_grid_str(pos) for pos in target_str.strip().split()]
    return [pos for pos in poses if pos[1] != -1], [pos[0] for pos in poses if pos[1] == -1]


def parse_zombie_place_list(place_zombie_str: str) -> list[PlaceZombieOp]:
    """
    根据iztools僵尸放置字符串生成僵尸放置列表

    Args:
        place_zombie_str: 与izt要求相同的僵尸放置字符串.
    Returns:
        一个列表, 返回所有僵尸操作, 用PlaceZombieOp表示
    Raises:
        ValueError: place_zombie_string格式错误时抛出
    """
    lines = place_zombie_str.strip().splitlines(False)
    if (t := len(lines)) != 3:
        raise ValueError(f"place_zombie_string must have 3 lines, instead of {t} lines")
    types = [zombie_abbr_to_type[abbr] for abbr in lines[0].strip().split()]
    times = [int(time) for time in lines[1].strip().split()]
    rows, cols = zip(*[parse_grid_str(pos) for pos in lines[2].strip().split()])  # zip(*list)转置
    if not (len(types) == len(times) == len(rows) == len(cols)):
        raise ValueError("length of types, times, rows and cols must be equal")
    return [PlaceZombieOp(*tpl) for tpl in zip(types, times, rows, cols)]


class IzTest:
    def __init__(self, controller: Controller):
        # 用init
        self.plant_type_lists: tuple[PlantTypeList, PlantTypeList] = ([], [])
        self.place_zombie_list: list[PlaceZombieOp] = []
        self.repeat_time: int = 1000
        self.mj_init_phase: int = randint(0, 459)
        self.target_plants_pos: list[tuple[int, int]] = []
        self.target_brains_pos: list[int] = []
        self.game_board: GameBoard = get_board(controller)
        self.controller: Controller = controller
        self.flow_factory: FlowFactory = FlowFactory()

        # 运行时候会时刻改变的量. protected, 不建议修改
        self._end_callback: Callable[[bool], None] = lambda _: None
        self._enable_default_check_end: bool = True
        self._target_plants: list[Plant] = []
        self._target_brains: list[Griditem] = []
        self._last_test_succeeded: bool = False
        self._success_count: int = 0
        self._test_time: int = 0
        self._flow_manager: FlowManager | None = None

    def init_by_str(self, iztools_str: str) -> Self:
        """
        通过iztools字符串初始化iztest对象

        与iztools的输入格式不完全相同:
            - 允许首尾空行以及每行首尾空格.
            - 支持第二行空行表示无目标: 若此行为空, 则不启用内置的判断输赢功能.
            - 支持不输入8 9 10行表示不放置僵尸: 若此行为空, 则不启用内置的判断输赢功能.
            - (暂且)不支持通过书写顺序调整僵尸编号.

        Args:
            iztools_str: iztools输入字符串
        Returns:
            self
        Raises:
            ValueError: 输入字符串格式错误时抛出
        Examples:
            >>> ctler: Controller = ...
            >>> iz_test = IzTest(ctler).init_by_str('''
            ...     1000 -1
            ...     3-0 4-0 5-0 3-3
            ...     .....
            ...     .....
            ...     bs3_c
            ...     b2ljh
            ...     blyl_
            ...     cg   cg   xg   ww
            ...     0    1    300  700
            ...     4-6  4-6  4-6  4-6''')
            如上为iztools默认例子的输入方式.
        """
        lines = iztools_str.strip().splitlines(False)
        try:
            self.repeat_time, mj_init_phase = map(int, lines[0].strip().split())
            if mj_init_phase < -1 or mj_init_phase >= 460:
                raise ValueError(f"mj_init_phase must be in [-1, 459], not {mj_init_phase}")
            self.mj_init_phase = mj_init_phase if mj_init_phase != -1 else randint(0, 459)
            self.target_plants_pos, self.target_brains_pos = parse_target_list(lines[1])
            if self.target_plants_pos == [] and self.target_brains_pos == []:
                self._enable_default_check_end = False
            self.plant_type_lists = parse_plant_type_list('\n'.join(lines[2:7]))
            for target_pos in self.target_plants_pos:
                if (self.plant_type_lists[0][target_pos[0]][target_pos[1]] is None
                        and self.plant_type_lists[1][target_pos[0]][target_pos[1]] is None):
                    raise ValueError(f"target plant at {target_pos} is None")
            if len(lines) == 7:
                self.place_zombie_list = []
                self._enable_default_check_end = False
                return self
            self.place_zombie_list = parse_zombie_place_list('\n'.join(lines[7:10]))
        except IndexError:
            raise ValueError(f"iztools_str must have 7 or 10 lines, not {len(lines)} lines")
        return self

    def set_end_callback(self) -> Callable[[Callable[[bool], None]], Callable[[bool], None]]:
        """
        装饰器, 设置结束时的回调函数

        回调的bool参数为本次测试是否成功

        Returns:
            添加用装饰器
        """

        def _decorator(func: Callable[[bool], None]) -> Callable[[bool], None]:
            self._end_callback = func
            return func
        return _decorator

    def end(self, succeeded: bool) -> TickRunnerResult:
        """
        返回本函数, 表示本次测试结束

        Args:
            succeeded: 成功则传入True, 失败传入False
        Returns:
            TickRunnerResult.BREAK_RUN
        """
        self._last_test_succeeded = succeeded
        self._end_callback(succeeded)
        if succeeded:
            self._success_count += 1
        self._test_time += 1
        return TickRunnerResult.BREAK_RUN

    def _set_flow_factory(self) -> Self:
        """
        设置flow_factory
        """
        @self.flow_factory.connect(until(0), only_once=True)
        def _init(_):
            # 清掉所有_ObjList的栈
            (board := self.game_board).plant_list.free_all().reset_stack()
            board.zombie_list.free_all().reset_stack()
            board.projectile_list.free_all().reset_stack()
            board.griditem_list.free_all().reset_stack()

            for plant_list in self.plant_type_lists:
                for row, line in enumerate(plant_list):
                    for col, type_ in enumerate(line):
                        if type_ is None:
                            continue
                        plant = board.iz_new_plant(row, col, type_)
                        assert plant is not None
                        if (row, col) in self.target_plants_pos:
                            self._target_plants.append(plant)

            board.mj_clock = self.mj_init_phase

            for i in range(5):
                brain = self.game_board.new_iz_brain(i)
                if i in self.target_brains_pos:
                    self._target_brains.append(brain)

        for op in self.place_zombie_list:
            @self.flow_factory.connect(until(op.time), only_once=True)
            def _place_zombie(_):
                self.game_board.iz_place_zombie(op.row, op.col, op.type_)

        if self._enable_default_check_end:
            @self.flow_factory.add_tick_runner()
            def _check_end(_):
                if all(plant.is_dead for plant in self._target_plants) \
                        and all(brain.id.rank == 0 for brain in self._target_brains):
                    return self.end(True)  # all iterable对象所有元素为True时候True
                if self.game_board.zombie_list.obj_num == 0:
                    return self.end(False)
                return TickRunnerResult.NEXT

        return self

# -*- coding: utf_8 -*-
"""
iztools 全场测试功能模拟
"""
from random import randint
from typing import TypeAlias, Self

from flow.flow import FlowFactory, TickRunnerResult
from flow.utils import until
from structs.game_board import GameBoard
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
        一个列表, 返回(row: int, col: int, type_: ZombieType, time: int)的namedtuple; row, col从0开始
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
    def __init__(self, game_board_: GameBoard):
        self.plantTypeList: tuple[PlantTypeList, PlantTypeList] = ([], [])
        self.placeZombieList: list[PlaceZombieOp] = []
        self.repeat_time: int = 1000
        self.mj_init_phase: int = randint(0, 459)
        self.target_plants_pos: list[tuple[int, int]] = []
        self.target_brains_pos: list[int] = []
        self.game_board: GameBoard = game_board_
        self.flow_factory: FlowFactory = FlowFactory()

        self._target_plants: list[Plant] = []
        self._target_brains: list[Griditem] = []

    def init(self, iztools_str: str) -> Self:
        """
        通过iztools字符串初始化iztest对象

        Args:
            iztools_str: iztools标准输入字符串
        Returns:
            返回自己
        Raises:
            ValueError: 输入字符串格式错误时抛出
        Examples:
            >>> game_board: GameBoard = ...
            >>> iz_test = IzTest(game_board).init('''
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
        self.repeat_time, mj_init_phase = map(int, lines[0].strip().split())
        if mj_init_phase < -1 or mj_init_phase >= 460:
            raise ValueError(f"mj_init_phase must be in [-1, 459], not {mj_init_phase}")
        self.mj_init_phase = mj_init_phase if mj_init_phase != -1 else randint(0, 459)
        self.target_plants_pos, self.target_brains_pos = parse_target_list(lines[1])
        self.plantTypeList = parse_plant_type_list('\n'.join(lines[2:7]))
        self.placeZombieList = parse_zombie_place_list('\n'.join(lines[7:10]))
        return self

    def _set_flow_factory(self):
        """
        设置flow_factory
        """
        @self.flow_factory.connect(until(0), only_once=True)
        def _init(_):
            # todo 清掉所有对象的栈
            for row, line in enumerate(self.plantTypeList[0]):
                for col, type_ in enumerate(line):
                    if type_ is not None:
                        plant = self.game_board.iz_new_plant(row, col, type_)
                        if (row, col) in self.target_plants_pos:
                            self._target_plants.append(plant)
            for row, line in enumerate(self.plantTypeList[1]):
                for col, type_ in enumerate(line):
                    if type_ is not None:
                        plant = self.game_board.iz_new_plant(row, col, type_)
                        if (row, col) in self.target_plants_pos:
                            self._target_plants.append(plant)
            self.game_board.mj_clock = self.mj_init_phase

            for i in range(5):
                brain = self.game_board.new_iz_brain(i)
                if i in self.target_brains_pos:
                    self._target_brains.append(brain)

        for op in self.placeZombieList:
            @self.flow_factory.connect(until(op.time), only_once=True)
            def _place_zombie(_):
                self.game_board.iz_place_zombie(op.row, op.col, op.type_)

        @self.flow_factory.add_tick_runner()
        def _check_end(_):
            if (False not in [plant.is_dead for plant in self._target_plants]) and \
                    (False not in [brain.id.rank == 0 for brain in self._target_brains]):
                # todo, 返回内容设计. 可能思路是给iz_test对象(或者FlowFactory)传"数据收集"回调
                return TickRunnerResult.END_FLOW
            if self.game_board.zombie_list.__len__() == 0:
                # todo, 返回内容设计
                return TickRunnerResult.END_FLOW
            return TickRunnerResult.NEXT

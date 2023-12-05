# -*- coding: utf_8 -*-
"""
简化flow编写的工具函数
"""
from typing import overload

from .flow import FlowManager, AwaitableCondFunc, CondFunc
from ..structs.game_board import GameBoard, get_board
from ..structs.obj_base import parse_grid_str
from ..structs.plant import Plant, PlantType
from ..structs.zombie import ZombieType, Zombie


# flow utils
# 除去delay以外 所有的CondFunc factory以until + 情况命名
@overload
def until(time: int) -> AwaitableCondFunc:
    """
    生成一个 判断时间是否到达 的函数

    Args:
        time: 到time时返回True
    Examples:
        >>> async def flow(_):
        ...     await until(100)
        ...     ...  # do something
        为一个 在time >= 100时执行do something的flow
    """


@overload
def until(cond_func: CondFunc) -> AwaitableCondFunc:
    """
    把cond_func函数包装为AwaitableCondFunc对象.

    Args:
        cond_func: 判断条件的函数
    Returns:
        一个包装的AwaitableCondFunc函数.
    """


def until(arg):
    if isinstance(arg, int):
        return AwaitableCondFunc(lambda fr: fr.time >= arg)
    return AwaitableCondFunc(arg)


def delay(time: int) -> AwaitableCondFunc:
    """
    生成一个 延迟time帧后返回True 的函数

    Args:
        time: 延迟用时间
    Raises:
        ValueError: time <= 0时候抛出.
    Examples:
        >>> async def flow(fm: FlowManager):
        ...     ...  # do something
        ...     place("cg 1-6")
        ...     await delay(50, fm)
        ...     place("cg 2-6")
        ...     ...  # do other thing
        为相隔50cs连放双撑杆
    """
    if time <= 0:
        raise ValueError(f"time must be positive, not {time}")

    def _cond_func(fm: FlowManager, start_time: list[int | None] = [None]) -> bool:
        if start_time[0] is None:
            start_time[0] = fm.time
        if fm.time >= start_time[0] + time - 1:
            return True
        return False
    return AwaitableCondFunc(_cond_func)


def until_precise_digger(magnetshroom: Plant) -> AwaitableCondFunc:
    """
    生成一个等到磁铁到达精确矿时间的函数

    Args:
        magnetshroom: 要判断cd的磁铁
    Examples:
        >>> magnet: Plant = ...
        >>> async def flow(_):
        ...     ...  # do something
        ...     place("kg 1-6")
        ...     await until_precise_digger(magnetshroom)
        ...     place("kg 2-6")
        ...     ...  # do other thing
        为2-1精确矿
    """
    return AwaitableCondFunc(lambda _: magnetshroom.status_cd == 1500 - 913)


def until_plant_die(plant: Plant) -> AwaitableCondFunc:
    """
    生成一个等到植物死亡的函数

    Args:
        plant: 要判断的植物
    """
    return AwaitableCondFunc(lambda _: plant.is_dead)


def until_plant_last_shoot(plant: Plant) -> AwaitableCondFunc:
    """
    生成一个 等到植物"本段最后一次连续攻击" 的函数.

    Args:
        plant: 要判断的植物
    """
    def _cond_func(fm: FlowManager, is_shooting_flag=[False], try_to_shoot_time=[None]):
        if plant.generate_cd == 1:  # 下一帧开打
            try_to_shoot_time[0] = fm.time + 1
        if try_to_shoot_time[0] == fm.time and plant.launch_cd != 0:  # 在攻击时
            is_shooting_flag[0] = True
            return False
        if try_to_shoot_time[0] == fm.time and plant.launch_cd == 0:  # 不在攻击时
            t = is_shooting_flag[0]
            is_shooting_flag[0] = False
            return t  # 上一轮是攻击的 且 这一轮不攻击 返回True
        return False
    return AwaitableCondFunc(_cond_func)


# ize utils
ize_plant_types: set[PlantType] = {
    PlantType.pea_shooter,
    PlantType.sunflower,
    PlantType.wallnut,
    PlantType.potato_mine,
    PlantType.snow_pea,
    PlantType.chomper,
    PlantType.repeater,
    PlantType.puffshroom,
    PlantType.doomshroom,
    PlantType.scaredyshroom,
    PlantType.squash,
    PlantType.threepeater,
    PlantType.spikeweed,
    PlantType.torchwood,
    PlantType.split_pea,
    PlantType.starfruit,
    PlantType.magnetshroom,
    PlantType.kernelpult,
    PlantType.umbrella_leaf
}
"""所有ize中出现的植物"""

ize_zombie_types: set[ZombieType] = {
    ZombieType.imp,
    ZombieType.conehead,
    ZombieType.pole_vaulting,
    ZombieType.buckethead,
    ZombieType.bungee,
    ZombieType.digger,
    ZombieType.ladder,
    ZombieType.football,
    ZombieType.dancing
}
"""所有ize中出现的僵尸"""

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
    "d": PlantType.fumeshroom,
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
"""植物缩写到植物类型的字典"""

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
"""僵尸缩写到僵尸类型的字典"""


def place(place_str: str, board: GameBoard | None = None) -> Zombie | Plant | None:
    """
    用字符串放置植物

    Args:
        place_str: 放置植物/僵尸的字符串
        board: 要放置的board. 为None时使用get_board()
    Returns:
        放置的植物或者僵尸
    Raises:
        ValueError: 无法识别的植物或僵尸缩写
    Examples:
        >>> gb: GameBoard = ...
        >>> place("1 1-2", gb)
        放置一颗豌豆在1-2
        >>> place("cg 1-6")
        放置一个撑杆在1-6
    """
    if board is None:
        board = get_board()
    type_str, pos_str = place_str.split(" ")
    row, col = parse_grid_str(pos_str)
    if (type_ := plant_abbr_to_type.get(type_str)) is not None:
        return board.iz_new_plant(row, col, type_)
    if (type_ := zombie_abbr_to_type.get(type_str)) is not None:
        return board.iz_place_zombie(row, col, type_)
    raise ValueError(f"invalid type_str: {type_str}")


# flow generator utils
async def repeat(place_str: str,
                 time: int = 2, interval: int = 20, board: GameBoard | None = None):
    """
    生成一个连续放东西的flow

    Args:
        place_str: 放置植物/僵尸的字符串
        time: 放僵尸个数
        interval: 放僵尸间隔时间
        board: 要放置的board. 为None时使用get_board()
    Examples:
        >>> gb: GameBoard = ...
        >>> async def flow(_):
        ...    ...  # do something
        ...    await repeat("cg 1-6")
        为在1-6连放双撑杆
    """
    place(place_str, board)
    for _ in range(time - 1):
        await delay(interval)
        place(place_str, board)
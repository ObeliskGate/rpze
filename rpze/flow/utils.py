# -*- coding: utf_8 -*-
"""
简化flow编写的工具函数
"""
from flow.flow import FlowManager, CondFunc, FlowGenerator, Flow
from structs.plant import Plant, PlantType
from structs.zombie import ZombieType
from structs.game_board import GameBoard


# flow utils
# 除去delay以外 所有的CondFunc factory以until + 情况命名
def until(time: int) -> CondFunc:
    """
    生成一个 判断时间是否到达 的函数

    Args:
        time: 到time时返回True
    Examples:
        >>> def flow(_):
        ...     yield until(100)
        ...     ...  # do something
        为一个 在time >= 100时执行do something的flow
    """
    return lambda fr: fr.time >= time


def delay(time: int) -> CondFunc:
    """
    生成一个 延迟time帧后返回True 的函数

    Args:
        time: 延迟用时间
    Raises:
        ValueError: time <= 0时候抛出.
    Examples:
        >>> gb: GameBoard = ...
        >>> def flow(fm: FlowManager):
        ...     ...  # do something
        ...     gb.iz_place_zombie(0, 5, ZombieType.pole_vaulting)
        ...     yield delay(50, fm)
        ...     gb.iz_place_zombie(0, 5, ZombieType.pole_vaulting)
        ...     ...  # do other thing
        为连放双撑杆
    """
    if time <= 0:
        raise ValueError(f"time must be positive, not {time}")

    def _cond_func(fm: FlowManager, args: list[int | None] = [None]) -> bool:
        if args[0] is None:  # args[0]为start_time
            args[0] = fm.time
        if args[0] <= fm.time - time + 1:
            return True
        return False
    return _cond_func


def until_precise_digger(magnetshroom: Plant) -> CondFunc:
    """
    生成一个等到磁铁到达精确矿时间的函数

    Args:
        magnetshroom: 要判断cd的磁铁
    Examples:
        >>> gb: GameBoard = ...
        >>> magnet: Plant = ...
        >>> def flow(_):
        ...     ...  # do something
        ...     gb.iz_place_zombie(0, 5, ZombieType.digger)
        ...     yield until_precise_digger(magnetshroom)
        ...     gb.iz_place_zombie(1, 5, ZombieType.digger)
        ...     ...  # do other thing
        为2-6精确矿
    """
    return lambda _: magnetshroom.status_cd == 1500 - 913


def until_plant_die(plant: Plant) -> CondFunc:
    """
    生成一个等到植物死亡的函数

    Args:
        plant: 要判断的植物
    """
    return lambda _: plant.is_dead


def until_plant_last_shoot(plant: Plant) -> CondFunc:
    """
    生成一个 等到植物"本段最后一次连续攻击" 的函数.

    Args:
        plant: 要判断的植物
    """
    def _cond_func(fm: FlowManager, is_shooting_flag=[False], try_to_shoot_time=[None]):  # 表示"上一轮是否是攻击的"
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
    return _cond_func


# flow generator utils
def continuous_place_zombie(board: GameBoard, row: int, col: int, zombie_type: ZombieType,
                            time: int = 2, interval: int = 20) -> FlowGenerator:
    """
    生成一个连续放僵尸的flow

    Args:
        board: 要放僵尸的board
        row: 行数
        col: 列数
        zombie_type: 僵尸类型
        time: 放僵尸个数
        interval: 放僵尸间隔时间
    Returns:
        生成的flow
    Examples:
        >>> gb: GameBoard = ...
        >>> def flow(flow_manager):
        ...    ...  # do something
        ...    yield from continuous_place_zombie(gb, 0, 5, ZombieType.pole_vaulting)
        为在1-6连放双撑杆
    """
    board.iz_place_zombie(row, col, zombie_type)
    for _ in range(time - 1):
        yield delay(interval)
        board.iz_place_zombie(row, col, zombie_type)
    return None  # satisfy pycharm type check


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

# -*- coding: utf_8 -*-
"""
简化flow编写的工具函数
"""
from flow.flow import FlowRunner, CondFunc
from structs.plant import Plant


# flow utils
def until(time: int) -> CondFunc:
    """
    生成一个判断时间是否到达的函数

    Args:
        time: 到time时返回True
    Examples:
        >>> def flow(_):
        ...     ...  # do something
        ...     yield until(100)
        ...     ...  # do other thing
        为一个 在time == 100时执行do otherthing的flow
    """
    return lambda fr: fr.time == time


def delay(time: int, flow_runner: FlowRunner) -> CondFunc:
    """
    生成一个 延迟time帧后返回True 的函数

    Args:
        time: 延迟用时间
        flow_runner: 当前FlowRunner对象
    Examples:
        >>> from structs.game_board import GameBoard
        >>> from structs.zombie import ZombieType
        >>> gb: GameBoard = ...
        >>> def flow(fr: FlowRunner):
        ...     ...  # do something
        ...     gb.iz_place_zombie(0, 5, ZombieType.pole_vaulting)
        ...     yield delay(50, fr)
        ...     gb.iz_place_zombie(0, 5, ZombieType.pole_vaulting)
        ...     ...  # do other thing
        为连放双撑杆
    """
    return until(flow_runner.time + time)


def until_precise_digger(magnetshroom: Plant) -> CondFunc:
    """
    生成一个判断磁铁是否到达精确矿时间的函数

    Args:
        magnetshroom: 要判断cd的磁铁
    Examples:
        >>> from structs.game_board import GameBoard
        >>> from structs.zombie import ZombieType
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

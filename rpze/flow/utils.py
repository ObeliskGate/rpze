# -*- coding: utf_8 -*-
"""
简化flow编写的工具函数
"""
from flow.flow import FlowManager, CondFunc
from structs.plant import Plant


# flow utils
def until(time: int) -> CondFunc:
    """
    生成一个 判断时间是否到达 的函数

    Args:
        time: 到time时返回True
    Examples:
        >>> def flow(_):
        ...     yield until(100)
        ...     ...  # do something
        为一个 在time == 100时执行do something的flow
    """
    return lambda fr: fr.time == time


def delay(time: int, flow_manager: FlowManager) -> CondFunc:
    """
    生成一个 延迟time帧后返回True 的函数

    Args:
        time: 延迟用时间
        flow_manager: 当前FlowManager对象
    Examples:
        >>> from structs.game_board import GameBoard
        >>> from structs.zombie import ZombieType
        >>> gb: GameBoard = ...
        >>> def flow(fm: FlowManager):
        ...     ...  # do something
        ...     gb.iz_place_zombie(0, 5, ZombieType.pole_vaulting)
        ...     yield delay(50, fm)
        ...     gb.iz_place_zombie(0, 5, ZombieType.pole_vaulting)
        ...     ...  # do other thing
        为连放双撑杆
    """
    return until(flow_manager.time + time)


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

# -*- coding: utf_8 -*-
"""
ize 漏阳光相关函数
"""
from ..basic.gridstr import GridStr, get_grid_str
from ..rp_extend import RpBaseException
from ..structs.game_board import GameBoard, get_board
from ..structs.plant import Plant, PlantType

SUNFLOWER_HPS_ON_DROPPING_SUN: tuple[int, int, int, int, int, int, int, int] = \
    tuple(276 - 40 * i for i in range(7)) + (0,)  # type: ignore
"""向日葵掉落阳光时的血量"""


def get_sunflower_remaining_sun(sunflower: Plant) -> int:
    """
    获取向日葵剩余阳光

    Args:
        sunflower: 目标向日葵
    Returns:
        向日葵剩余阳光值
    Raises:
        RpBaseException: 出现未知的行为时
    """
    if sunflower.is_dead:
        return 0
    hp = sunflower.hp
    intervals = (300,) + SUNFLOWER_HPS_ON_DROPPING_SUN
    lo, hi = 0, len(intervals) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if intervals[mid] >= hp > intervals[mid + 1]:
            return (8 - mid) * 25
        if hp > intervals[mid]:
            hi = mid - 1
        else:
            lo = mid + 1
    raise RpBaseException("unexpected behaviour!")


def get_all_remaining_suns(board: GameBoard | None = None) -> dict[GridStr, int]:
    """
    获取所有向日葵剩余阳光

    Args:
        board: 要获取的 board. 为 None 时使用 get_board()
    Returns:
        一个字典, 形式为{向日葵所在的 x-y: 剩余阳光值}
    """
    if board is None:
        board = get_board()
    return {get_grid_str(sf.row, sf.col): get_sunflower_remaining_sun(sf)
            for sf in ~board.plant_list if sf.type_ is PlantType.sunflower}

# -*- coding: utf_8 -*-
"""
场地字符串相关的类型与函数
"""
from functools import lru_cache
from typing import TypeAlias

gridstr: TypeAlias = str
"""f'{row}-{col}'字符串, 作为本项目唯一以1开头的行列表示方式"""


@lru_cache()
def parse_grid_str(grid_str: gridstr) -> tuple[int, int]:
    """
    根据f'{row}-{col}'字符串返回(row, col)对象

    Args:
        grid_str: 形如'1-2'的字符串
    Returns:
        (row, col)元组
    Raises:
        ValueError: 无法识别的grid_str
    """
    spl = grid_str.split('-')
    if len(spl) != 2:
        raise ValueError(f"grid_str with wrong length: {grid_str}")
    return int(spl[0].strip()) - 1, int(spl[1].strip()) - 1


def get_grid_str(row: int, col: int) -> gridstr:
    """
    根据row, col返回gridstr
    Args:
        row: 行数
        col: 列数
    Returns:
        返回的gridstr
    """
    return f"{row + 1}-{col + 1}"

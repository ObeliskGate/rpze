# -*- coding: utf_8 -*-
"""
场地字符串相关的类型与函数
"""
from functools import lru_cache
from typing import TypeAlias

GridStr: TypeAlias = str
"""f'{row}-{col}'字符串, 作为本项目唯一以1开头的行列表示方式"""


@lru_cache()
def parse_grid_str(grid_str: GridStr) -> tuple[int, int]:
    """
    根据f'{row}-{col}'字符串返回(row, col)对象

    Args:
        grid_str: 形如'1-2'的字符串
    Returns:
        (row, col)元组
    """
    spl = grid_str.split('-')
    return int(spl[0].strip()) - 1, int(spl[1].strip()) - 1


def get_grid_str(row: int, col: int) -> GridStr:
    """
    根据row, col返回GridStr
    Args:
        row: 行数
        col: 列数
    Returns:
        返回的 GridStr 位置
    """
    return f"{row + 1}-{col + 1}"

# -*- coding: utf_8 -*-
"""
iztest常见操作
"""
from .consts import plant_abbr_to_type, zombie_abbr_to_type
from ..basic.gridstr import parse_grid_str
from ..basic.inject import ConnectedContext, enter_level
from ..flow.utils import delay
from ..rp_extend import Controller
from ..structs.game_board import get_board, GameBoard
from ..structs.plant import Plant
from ..structs.zombie import Zombie


def enter_ize(ctler: Controller) -> GameBoard:
    """
    进入ize关卡并等待至清除选卡僵尸

    Args:
        ctler: 被注入的游戏对象
    Returns:
        进入关卡的GameBoard对象
    """
    with ConnectedContext(ctler) as ctler:
        enter_level(ctler, 70)
        board = get_board(ctler)
        board.remove_cutscene_zombie()
        while ctler.read_u32(0x6a9ec0, 0x7fc) == 2:  # game scene == playing
            ctler.skip_frames()
    return board


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
    if (type_ := zombie_abbr_to_type.get(type_str)) is not None:
        return board.iz_place_zombie(row, col, type_)
    if (type_ := plant_abbr_to_type.get(type_str)) is not None:
        return board.iz_new_plant(row, col, type_)
    raise ValueError(f"invalid type_str: {type_str}")


async def repeat(place_str: str,
                 time: int = 2,
                 interval: int = 20,
                 board: GameBoard | None = None) -> list[Zombie | Plant | None]:
    """
    生成一个连续放东西的flow

    Args:
        place_str: 放置植物/僵尸的字符串
        time: 放僵尸个数
        interval: 放僵尸间隔时间
        board: 要放置的board. 为None时使用get_board()
    Returns:
        放置的植物或者僵尸列表
    Examples:
        >>> async def flow(_):
        ...    ...  # do something
        ...    await repeat("cg 1-6", time=3)
        为1-6三撑杆
    """
    ret = [place(place_str, board)]
    for _ in range(time - 1):
        await delay(interval)
        ret.append(place(place_str, board))
    return ret

import random
import typing

from ..structs.game_board import get_board
from ..structs.plant import Plant, PlantType


def randomize_generate_cd(plant: Plant) -> Plant:
    """
    令植物的generate_cd按照"放置充分长时间"后的结果随机化

    **仅对can_attack == True植物有效**; 但特判地刺, 地刺王无效.

    具体来说, 其generate_cd概率分布图像为一个梯形:
    上底为max_boot_delay - 14, 下底为max_boot_delay.

    Returns:
        返回传入的植物
    """
    if (not plant.can_attack) or plant.type_ in {PlantType.spikeweed, PlantType.spikerock}:
        return plant
    # 拆成[1, max_ - 14)和[max_ - 14, max_ + 1)两个区间
    # 不可以取0, 可以取max_, max_ - 14和前面概率相等为h
    # h * (max_ - 15) + (h + 0) * 16 / 2 = 1解这个方程, h为梯形的高
    h = 1 / ((max_ := plant.max_boot_delay) - 7)
    distribution = [h] * (max_ - 15) + [h / 15 * i for i in range(15, 0, -1)]
    plant.generate_cd = random.choices(population=range(1, max_ + 1), weights=distribution)[0]
    return plant


@typing.overload
def set_puff_x_offset(puff: Plant, offset: int):
    """
    为小喷设置x偏移

    Args:
        puff: 目标小喷
        offset: 小喷x偏移
    Raises:
        ValueError: offset不在范围内
    Examples:
        >>> p = ...
        >>> set_puff_x_offset(p, 3)
        为小喷设置x偏移为+3
    """


@typing.overload
def set_puff_x_offset(puff: Plant, offset: typing.Iterable[int]):
    """
    为小喷设置x偏移

    Args:
        puff: 目标小喷
        offset: 小喷x偏移范围
    Raises:
        ValueError: **最终随机结果的**偏移不在范围内.
    Examples:
        >>> p = ...
        >>> set_puff_x_offset(p, range(-5, 4))
        为小喷设置在整个范围内的随机x偏移
    """


def set_puff_x_offset(puff: Plant, offset):
    center_x = get_board(puff.controller).grid_to_pixel_x(puff.col, puff.row)
    offset = offset if isinstance(offset, int) else random.choice(list(offset))
    if not (-5 <= offset <= 4):
        raise ValueError(f"offset {offset} out of valid range of puff")
    puff.x = center_x + offset

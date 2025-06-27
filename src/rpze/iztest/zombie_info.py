from enum import Enum, auto

from ..structs.game_board import get_board
from ..structs.zombie import Zombie


class TieWearingZombieWalkingMode(Enum):
    ARM_SWING = auto()
    ARM_HANG = auto()
    DANCE = auto()


def get_tied_wearing_zombie_walking_mode(zombie: Zombie) -> TieWearingZombieWalkingMode:
    """
    获取穿着领带的僵尸行走模式

    Args:
        zombie: 要获取行走模式的僵尸
    Returns:
        穿着领带的僵尸行走模式
    Raises:
        ValueError: 如果无法识别行走模式
    """
    ctler = zombie.controller
    rlist = get_board(ctler).reanimation_list
    reanim = rlist.find(zombie.m_body_reanim_id)

    match reanim.m_frame_start:
        case 44:
            return TieWearingZombieWalkingMode.ARM_SWING
        case 91:
            return TieWearingZombieWalkingMode.ARM_HANG
        case 454:
            return TieWearingZombieWalkingMode.DANCE
        case _:
            raise ValueError(f"Unknown walking mode for zombie with reanim frame start {reanim.m_frame_start}")


def get_current_speed(zombie: Zombie) -> float:
    """
    拿到僵尸当前的速度参数

    Args:
        zombie: 要获得参数的僵尸
    Returns:
        速度参数
    """
    ctler = zombie.controller
    rlist = get_board(ctler).reanimation_list
    reanim = rlist.find(zombie.m_body_reanim_id)
    return reanim.get_track_velocity()

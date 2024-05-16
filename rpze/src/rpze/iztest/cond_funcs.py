# -*- coding: utf_8 -*-
"""
简化iztest的条件函数
"""
from ..flow.flow import FlowManager
from ..flow.utils import VariablePool, AwaitableCondFunc
from ..structs.plant import Plant


def until_precise_digger(magnet: Plant) -> AwaitableCondFunc:
    """
    生成一个等到磁铁到达精确矿时间的函数

    Args:
        magnet: 要判断cd的磁铁
    """
    return AwaitableCondFunc(lambda _: magnet.status_cd <= 587)  # 1500 - 913


def until_plant_die(plant: Plant) -> AwaitableCondFunc:
    """
    生成一个等到植物死亡的函数

    Args:
        plant: 要判断的植物
    """
    return AwaitableCondFunc(lambda _: plant.is_dead)


def until_plant_last_shoot(plant: Plant) -> AwaitableCondFunc:
    """
    生成一个 等到植物"本段最后一次连续攻击"的函数.

    Args:
        plant: 要判断的植物
    """

    def _cond_func(fm: FlowManager,
                   v=VariablePool(try_to_shoot_time=None, last_shooting_time=None)):
        if plant.generate_cd == 1:  # 下一帧开打
            v.try_to_shoot_time = fm.time + 1
        if v.try_to_shoot_time == fm.time and plant.launch_cd != 0:  # 在攻击时
            v.last_shooting_time = fm.time
            return False
        if v.try_to_shoot_time == fm.time and plant.launch_cd == 0:  # 不在攻击时
            if v.last_shooting_time is not None:
                return True, fm.time - v.last_shooting_time
            v.last_shooting_time = None
            return False  # 上一轮是攻击的 且 这一轮不攻击 返回True
        return False

    return AwaitableCondFunc(_cond_func)

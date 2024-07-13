# -*- coding: utf_8 -*-
"""
简化 iztest 编写的条件函数
"""
from ..flow.flow import FlowManager
from ..flow.utils import VariablePool, AwaitableCondFunc
from ..structs.plant import Plant


def until_precise_digger(magnet: Plant) -> AwaitableCondFunc[None]:
    """
    生成一个等到磁铁到达精确矿时间的函数

    Args:
        magnet: 要判断 cd 的磁铁
    """
    return AwaitableCondFunc(lambda _: magnet.status_cd <= 587)  # 587 - 590 by 寒风


def until_plant_die(plant: Plant) -> AwaitableCondFunc[None]:
    """
    生成一个等到植物死亡的函数

    Args:
        plant: 要判断的植物
    """
    return AwaitableCondFunc(lambda _: plant.is_dead)


def until_plant_last_shoot(plant: Plant, wait_until_150: bool = False) -> AwaitableCondFunc[int]:
    """
    生成一个 等到植物 "本段最后一次连续攻击结束后返回" 的函数.

    await 调用后返回"开打帧距离上一次攻击的距离"

    Args:
        plant: 要判断的植物
        wait_until_150: 是否等到上次开打150后再返回
    Examples:
        >>> async def flow(_):
        ...     plant = iz_test.ground["1-2"]  # noqa
        ...     t = await until_plant_last_shoot(plant)
        ...     assert 136 <= t <= 150  # t 即为攻击间隔时长
    """

    def _await_func(fm: FlowManager, v=VariablePool(
            try_to_shoot_time=None,
            last_shooting_time=None,
            until_150_ret=None)):
        if v.until_150_ret is not None:  # until 150 flag开了就走: 等到150后再返回
            if fm.time >= v.last_shooting_time + 150:
                return True, v.until_150_ret
            return False
        if plant.generate_cd == 1:  # 下一帧开打
            v.try_to_shoot_time = fm.time + 1
        if v.try_to_shoot_time == fm.time and plant.launch_cd != 0:  # 在攻击时
            v.last_shooting_time = fm.time
            return False
        if v.try_to_shoot_time == fm.time and plant.launch_cd == 0:  # 不在攻击时
            if v.last_shooting_time is not None:
                if not wait_until_150 or fm.time == v.last_shooting_time + 150:
                    return True, fm.time - v.last_shooting_time
                # 如果等150再返回 flag改not None开始走until逻辑
                v.until_150_ret = fm.time - v.last_shooting_time
                return False
            v.last_shooting_time = None
            return False  # 上一轮是攻击的 且 这一轮不攻击 返回True
        return False

    return AwaitableCondFunc(_await_func)

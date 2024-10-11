# -*- coding: utf_8 -*-
"""
简化 iztest 编写的条件函数
"""
from typing import Literal

from ..flow.flow import FlowManager
from ..flow.utils import VariablePool, AwaitableCondFunc
from ..structs.plant import Plant, PlantStatus, PlantType


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


def until_plant_last_shoot(plant: Plant, wait_until_mbd: bool = False) -> AwaitableCondFunc[int]:
    """
    生成一个 等到植物 "本段最后一次连续攻击结束后返回" 的函数.

    await 调用后返回"开打帧距离上一次攻击的距离"

    对裂荚处理逻辑与对其他植物有区别: 只关心第一发. 裂荚右与单发结果相同, 裂荚左与双发结果不同.

    Args:
        plant: 要判断的植物
        wait_until_mbd: 是否等到 上次开打经过最大攻击间隔后 再返回
    Examples:
        >>> async def flow(_):
        ...     plant = iz_test.ground["1-2"]  # noqa
        ...     t = await until_plant_last_shoot(plant)
        ...     assert plant.max_boot_delay - 14 <= t <= plant.max_boot_delay  # t 即为攻击间隔时长
    """

    shoot_next_gcd = 1 if plant.type_ is not PlantType.split_pea else 26  # 修正裂荚攻击时机
    mbd = plant.max_boot_delay

    def _await_func(fm: FlowManager, v=VariablePool(
            try_to_shoot_time=None,
            last_shooting_time=None,
            until_mbd_ret=None)):
        if v.until_mbd_ret is not None:  # until mbd flag开了就走: 等到最大攻击间隔后再返回
            if fm.time >= v.last_shooting_time + mbd:
                return True, v.until_mbd_ret
            return False
        if plant.generate_cd == shoot_next_gcd:  # 下一帧开打
            v.try_to_shoot_time = fm.time + 1
        if v.try_to_shoot_time == fm.time:
            if plant.launch_cd > 15:  # 判断大于15则处于攻击状态, 目的是兼容忧郁菇
                v.last_shooting_time = fm.time
                return False
            else:  # 不处于攻击状态
                if v.last_shooting_time is not None:
                    if not wait_until_mbd or fm.time == v.last_shooting_time + mbd:
                        return True, fm.time - v.last_shooting_time
                    # 如果等最大攻击间隔再返回 flag改not None开始走until逻辑
                    v.until_mbd_ret = fm.time - v.last_shooting_time
                    return False
                v.last_shooting_time = None
                return False  # 上一轮是攻击的 且 这一轮不攻击 返回True
        return False

    return AwaitableCondFunc(_await_func)


def until_plant_n_shoot(plant: Plant, n: int = 1, non_stop: bool = True) -> AwaitableCondFunc[None]:
    """
    生成一个 等到植物n次攻击 的函数

    Args:
        plant: 要判断的植物
        n: 攻击次数
        non_stop: 是否为不间断攻击
    """

    shoot_next_gcd = 1 if plant.type_ is not PlantType.split_pea else 26  # 修正裂荚攻击时机
    
    def _await_func(fm: FlowManager,
                    v=VariablePool(try_to_shoot_time=None, shots=0)):
        if plant.generate_cd == shoot_next_gcd:  # 下一帧开打
            v.try_to_shoot_time = fm.time + 1
        if v.try_to_shoot_time == fm.time:
            if plant.launch_cd > 15:  # 在攻击时
                v.shots += 1
            else:  # 不再攻击时
                if non_stop:  # 设置了不停止标志，则计数清零
                    v.shots = 0
        if v.shots == n:
            return True
        return False
    
    return AwaitableCondFunc(_await_func)


CountButterModeLiteral = Literal[0, 1, 2, "total", "nonstop", "continuous"]
"""数黄油函数 until_n_butter 的计数方法

    - 0 或 "total" 表示允许攻击中断
    - 1 或 "nonstop" 表示攻击不中断
    - 2 或 "continuous" 表示攻击不中断, 而且黄油必须连续投出
"""


def until_n_butter(plant: Plant, n: int = 1, mode: CountButterModeLiteral = 1) -> AwaitableCondFunc[None]:
    """
    生成一个 等到玉米攻击n发黄油 的函数

    Args:
        plant: 要判断的植物
        n: 攻击黄油次数
        mode: 字面量, 表示计数方法
    """
    match mode:
        case "total" | 0:
            mode_index = 0
        case "nonstop" | 1:
            mode_index = 1
        case "continuous" | 2:
            mode_index = 2
        case _:
            raise ValueError(f"invalid count mode: {mode}")

    def _await_func(fm: FlowManager, v=VariablePool(projs=0, try_to_shoot_time=None)):
        if plant.generate_cd == 1:  # 下一帧开打
            v.try_to_shoot_time = fm.time + 1
        if v.try_to_shoot_time == fm.time:
            if plant.status is PlantStatus.kernelpult_launch_butter:  # 出黄油
                v.projs += 1
            elif plant.launch_cd == 0:  # 攻击停止
                if mode_index != 0:
                    v.projs = 0
            else:  # 出玉米粒
                if mode_index == 2:
                    v.projs = 0
        if v.projs == n:
            return True 
        return False
    
    return AwaitableCondFunc(_await_func)

# -*- coding: utf_8 -*-
"""
简化flow编写的工具函数
"""
import warnings
from typing import overload

from .flow import FlowManager, AwaitableCondFunc, CondFunc, VariablePool


# flow utils
# 除去delay以外 所有的CondFunc factory以until + 情况命名
@overload
def until(time: int, /) -> AwaitableCondFunc:
    """
    生成一个 判断时间是否到达 的函数

    Args:
        time: 当前时间大于等于time时返回True
    Examples:
        >>> async def flow(_):
        ...     await until(100)
        ...     ...  # do something
        为一个 在time >= 100时执行do something的flow
    """


@overload
def until(cond_func: CondFunc, /) -> AwaitableCondFunc:
    """
    把cond_func函数包装为AwaitableCondFunc对象.

    Args:
        cond_func: 判断条件的函数
    Returns:
        一个包装的AwaitableCondFunc函数.
    """


def until(arg):
    if callable(arg):
        return AwaitableCondFunc(arg)
    if isinstance(arg, bool):
        warnings.warn("until(bool) is usually not what you want, use until(lambda _: bool) instead.",
                      SyntaxWarning,
                      stacklevel=2)
    return AwaitableCondFunc(lambda fm: fm.time >= arg)


def delay(time: int) -> AwaitableCondFunc:
    """
    生成一个 延迟time帧后返回True 的函数

    Args:
        time: 延迟用时间
    Raises:
        ValueError: time <= 0时候抛出.
    Examples:
        >>> async def flow(_):
        ...     ...  # do something
        ...     await delay(50)
        ...     ...  # do other thing
        为相隔50cs连续执行
    """
    if time <= 0:
        raise ValueError(f"time must be positive, not {time}")

    def _cond_func(fm: FlowManager, v=VariablePool(start_time=None)) -> bool:
        if v.start_time is None:
            v.start_time = fm.time
        if v.start_time + time - 1 <= fm.time:  # 所有CondFunc函数下一cs开始执行.
            return True
        return False

    return AwaitableCondFunc(_cond_func)

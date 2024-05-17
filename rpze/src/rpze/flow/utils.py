# -*- coding: utf_8 -*-
"""
简化flow编写的工具函数
"""
import warnings
from collections.abc import Callable, Awaitable, Generator
from typing import overload, Self, Any, TypeVar, Generic, TypeAlias

from .flow import CondFunc, FlowManager


class VariablePool:  # thanks Reisen
    """
    用于表示CondFunc中用于"伴随状态"的默认参数的变量池.
    具体属性由构造函数而定
    """

    def reset(self) -> Self:
        """
        重置变量池. 重置后变量池的属性值为初始值.

        Returns:
            self
        """
        self._args_list = list(self.origin_list)
        for k, v in self.origin_dict.items():
            setattr(self, k, v)
        return self

    def __init__(self, *args, **kwargs):
        """
        Args:
            *args: 匿名变量. 使用下标运算访问.
            **kwargs: 属性. 属性名=初始值
        """
        self._args_list = []
        self.origin_list = args
        self.origin_dict = kwargs
        self.reset()

    def __getitem__(self, item):
        return self._args_list[item]

    def __setitem__(self, key, value):
        self._args_list[key] = value

    def get_all_attrs(self) -> tuple[tuple, dict] | None:
        """
        获取所有属性的值

        Returns:
            所有匿名属性(in a tuple), 所有具名属性(in a dict)
        """
        return tuple(self._args_list), {k: getattr(self, k) for k in self.origin_dict}

    def __str__(self):
        t, d = self.get_all_attrs()
        return f"<{t}, {d}>"


_T_co = TypeVar("_T_co", covariant=True)
AwaitFunc: TypeAlias = Callable[[FlowManager], bool | tuple[bool, *tuple[Any, ...]]]


def _await_generator(t) -> Generator[Any, Any, _T_co]:
    ret = yield t
    return ret


class AwaitableCondFunc(Generic[_T_co], Callable, Awaitable):
    """
    包装Awaitable对象用于在flow中await 调用.

    泛型变量用于表示reveal_type(await AwaitableCondFunc[bool]) is bool
    这个type hint在PyCharm和mypy工作正常, pylance不工作.

    内层func应当返回bool或者(True, _T_co).

    Attributes:
        func: 内层CondFunc函数
    """
    __slots__ = ("func",)

    def __init__(self, func: AwaitFunc):
        self.func: AwaitFunc = func

    def __call__(self, fm: FlowManager) -> bool:
        """
        调用内层func. 确保AwaitableCondFunc自己也为CondFunc函数.

        忽略可能作为await返回值的_T_co而只返回第一位bool.
        """
        match self.func(fm):
            case (b, *_):
                return b
            case b:
                return b

    def __await__(self) -> Generator[AwaitFunc, Any, _T_co]:
        """
        让AwaitableCondFunc对象可以await.

        Returns:
            生成器对象. 唯一一个生成结果为self.func.
        """
        return _await_generator(self.func)

    def __and__(self, other: CondFunc) -> "AwaitableCondFunc[None]":
        """
        重载&运算符, 使得对象可以用&运算符, 像逻辑和运算一样连接

        Args:
            other: 另一个CondFunc对象

        Returns:
            一个新的AwaitableCondFunc对象. 该对象的func为self() and other.func
        """
        return AwaitableCondFunc(lambda fm: self(fm) and other(fm))

    def __rand__(self, other: CondFunc) -> "AwaitableCondFunc[None]":
        """
        重载&运算符, 使得对象可以用&运算符, 像逻辑和运算一样连接

        Args:
            other: 另一个CondFunc对象

        Returns:
            一个新的AwaitableCondFunc对象. 该对象的func为other.func and self()
        """
        return AwaitableCondFunc(lambda fm: other(fm) and self(fm))

    def __or__(self, other: CondFunc) -> "AwaitableCondFunc[None]":
        """
        重载|运算符, 使得对象可以用|运算符, 像逻辑或运算一样连接

        Args:
            other: 另一个CondFunc对象
        Returns:
            一个新的AwaitableCondFunc对象. 该对象的func为self() or other.func
        """
        return AwaitableCondFunc(lambda fm: self(fm) or other(fm))

    def __ror__(self, other: CondFunc) -> "AwaitableCondFunc[None]":
        """
        重载|运算符, 使得对象可以用|运算符, 像逻辑或运算一样连接

        Args:
            other: 另一个CondFunc对象
        Returns:
            一个新的AwaitableCondFunc对象. 该对象的func为other.func or self()
        """
        return AwaitableCondFunc(lambda fm: other(fm) or self(fm))

    def __invert__(self) -> "AwaitableCondFunc[None]":
        """
        重载~运算符, 使得对象可以用~运算符, 像逻辑非运算一样.

        Returns:
            一个新的AwaitableCondFunc对象. 该对象的func为not self()
        """
        return AwaitableCondFunc(lambda fm: not self(fm))

    def after(self, delay_time: int) -> Self:
        """
        生成一个 在满足原条件后过delay_time帧返回True的对象.
        Args:
            delay_time: 延迟时间
        Returns:
            一个新的AwaitableCondFunc对象.
        """

        def _await_func(fm: FlowManager, p=VariablePool(event_time=None, ret=None)):
            if p.event_time is None and (t := self.func(fm)):
                p.event_time = fm.time
                p.ret = t
            if p.event_time is not None and p.event_time + delay_time <= fm.time:
                return p.ret
            return False

        return AwaitableCondFunc(_await_func)


@overload
def until(time: int, /) -> AwaitableCondFunc[None]:
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
def until(cond_func: CondFunc, /) -> AwaitableCondFunc[None]:
    """
    把cond_func函数包装为AwaitableCondFunc对象.

    Args:
        cond_func: 判断条件的函数
    Returns:
        一个包装的AwaitableCondFunc函数.
    """


def until(arg) -> AwaitableCondFunc[None]:
    if callable(arg):
        return AwaitableCondFunc(arg)
    if isinstance(arg, bool):
        warnings.warn(
            "until(bool) is usually not what you want, use until(lambda _: bool) instead.",
            SyntaxWarning, stacklevel=2)
    return AwaitableCondFunc(lambda fm: fm.time >= arg)


def delay(time: int) -> AwaitableCondFunc[None]:
    """
    生成一个 延迟time帧后返回True的函数

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

    def _cond_func(fm, v=VariablePool(start_time=None)) -> bool:
        if v.start_time is None:
            v.start_time = fm.time
        if v.start_time + time - 1 <= fm.time:  # 所有CondFunc函数下一cs开始执行.
            return True
        return False

    return AwaitableCondFunc(_cond_func)

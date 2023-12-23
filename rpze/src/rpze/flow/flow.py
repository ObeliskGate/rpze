# -*- coding: utf_8 -*-
"""
流程控制相关的函数和类
"""

from __future__ import annotations

import heapq
from collections.abc import Callable, Awaitable, Coroutine
from enum import Enum, auto
from itertools import count
from typing import TypeAlias, Self


class TickRunnerResult(Enum):
    """TickRunner的返回值"""
    DONE = auto(),
    """本tick runner以后再也不执行时返回"""
    NEXT = auto(),
    """本tick runner以后还会执行时返回"""
    BREAK_RUN = auto()  # 不用异常打断. StopIteration形式的返回值和type hint系统匹配程度太差.
    """需要打断本次run时返回"""


CondFunc: TypeAlias = Callable[["FlowManager"], bool]
"""判断条件的函数"""
FlowCoroutine: TypeAlias = Coroutine[CondFunc, None, TickRunnerResult | None]
"""Flow返回的协程对象"""
Flow: TypeAlias = Callable[["FlowManager"], FlowCoroutine]
"""await AwaitableCondFunc函数的async def函数"""
TickRunner: TypeAlias = Callable[["FlowManager"], TickRunnerResult]
"""帧运行函数"""
PriorityTickRunner: TypeAlias = tuple[int, TickRunner]
"""带权重的帧运行函数"""


class VariablePool:  # thanks Reisen
    """
    用于表示CondFunc中用于"伴随状态"的默认参数的变量池.
    具体属性由构造函数而定
    """
    def __init__(self, *args, **kwargs):
        """
        Args:
            *args: 匿名变量. 使用下标运算访问.
            **kwargs: 属性. 属性名=初始值
        """
        self._args_list = list(args)
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __getitem__(self, item):
        return self._args_list[item]

    def __setitem__(self, key, value):
        self._args_list[key] = value


class AwaitableCondFunc(Callable, Awaitable):
    """
    包装CondFunc为Awaitable对象.

    Attributes:
        func: 内层CondFunc函数
    """

    def __init__(self, func: CondFunc):
        self.func: CondFunc = func

        def _generator(t):
            yield t
        self._generator = _generator

    def __call__(self, fm: FlowManager) -> bool:
        """
        调用内层func. 确保AwaitableCondFunc自己也为CondFunc函数.
        """
        return self.func(fm)

    def __await__(self):
        """
        让AwaitableCondFunc对象可以await.

        Returns:
            生成器对象. 唯一一个生成结果为self.func.
        """
        return self._generator(self.func)

    def __and__(self, other: CondFunc) -> Self:
        """
        重载&运算符, 使得对象可以用&运算符, 像逻辑和运算一样连接

        Args:
            other: 另一个CondFunc对象

        Returns:
            一个新的AwaitableCondFunc对象. 该对象的func为self.func and other.func
        """
        return AwaitableCondFunc(lambda fm: self.func(fm) and other(fm))

    def __or__(self, other: CondFunc) -> Self:
        """
        重载|运算符, 使得对象可以用|运算符, 像逻辑或运算一样连接

        Args:
            other: 另一个CondFunc对象
        Returns:
            一个新的AwaitableCondFunc对象. 该对象的func为self.func or other.func
        """
        return AwaitableCondFunc(lambda fm: self.func(fm) or other(fm))

    def __invert__(self) -> Self:
        """
        重载~运算符, 使得对象可以用~运算符, 像逻辑非运算一样.

        Returns:
            一个新的AwaitableCondFunc对象. 该对象的func为not self.func
        """
        return AwaitableCondFunc(lambda fm: not self.func(fm))

    def after(self, delay_time: int) -> Self:
        """
        生成一个 在满足原条件后过delay_time帧返回True的对象.
        Args:
            delay_time: 延迟时间
        Returns:
            一个新的AwaitableCondFunc对象.
        """
        def _cond_func(fm: FlowManager, p=VariablePool(event_time=None)) -> bool:
            if p.event_time is None and self.func(fm):
                p.event_time = fm.time
            if p.event_time is not None and p.event_time + delay_time <= fm.time:
                return True
            return False
        return AwaitableCondFunc(_cond_func)


class FlowManager:
    """
    运行Flow和TickRunner函数的对象

    Attributes:
        tick_runners: 所有TickRunner组成的函数, 运行时按顺序执行
        time: 每执行一次do自增1
    """
    def __init__(self, tick_runners: list[PriorityTickRunner], flows: list[Flow], flow_priority):
        """
        Args:
            tick_runners: tick_runner列表, 以PriorityTickRunner形式提供以便排序
            flows: flow列表
            flow_priority: flows执行优先级
        """
        self._flow_coro_list: list[list[CondFunc, FlowCoroutine]] \
            = [[lambda _: True, i(self)] for i in flows]

        def __flow_tick_runner(self_: FlowManager) -> TickRunnerResult:
            if not (fcl := self_._flow_coro_list):
                return TickRunnerResult.DONE
            pop_list = []
            for idx, (cond_func, flow) in enumerate(fcl):
                if cond_func(self_):
                    try:
                        fcl[idx][0] = flow.send(None)
                    except StopIteration as se:  # StopIteration.value为返回值
                        pop_list.append(idx)  # 早该换成链表了
                        if se.value is None:
                            continue
                        for i in pop_list[::-1]:
                            fcl.pop(i)
                        return se.value
                else:
                    continue
            for i in pop_list[::-1]:
                fcl.pop(i)
            return TickRunnerResult.NEXT

        _counter = count()
        tick_runner_heap = [(-priority, next(_counter), it) for priority, it in tick_runners]
        heapq.heapify(tick_runner_heap)
        heapq.heappush(tick_runner_heap, (-flow_priority, next(_counter), __flow_tick_runner))
        # -priority让priority越大优先级别越高
        self.tick_runners: list[TickRunner | None] = [i[2] for i in tick_runner_heap]
        self.time = 0

    def add(self) -> Callable[[TickRunner], TickRunner]:
        """
        运行时添加TickRunner的装饰器

        运行时添加的TickRunner会被放在最后执行. 即, 不支持加优先级, 但确保本帧执行.

        Examples:
            >>> flow_manager: FlowManager = ...
            >>> @flow_manager.add()
            ... def tr(fm: FlowManager) -> TickRunnerResult:
            ...     ...
            为装饰器形式使用

            >>> flow_manager: FlowManager = ...
            >>> def tr(fm: FlowManager) -> TickRunnerResult:
            ...     ...
            >>> flow_manager.add()(tr)
            为函数形式使用
        """
        def _decorator(tr: TickRunner):
            self.tick_runners.append(tr)
            return tr
        return _decorator

    def connect(self, cond: CondFunc, only_once: bool = False) \
            -> Callable[[Callable[[Self], TickRunnerResult | None]],
                        Callable[[Self], TickRunnerResult | None]]:
        """
        运行时把tick_runner绑定到cond上的方法, 与add使用方法相同
        
        即 在cond(self)返回true时执行func(self).

        Args:
            cond: 执行func的条件函数. 返回None时按照only_once判断; 返回TickRunnerResult时直接返回.
            only_once: 为True时 只要有一次满足cond则返回
        """
        def _decorator(tr: Callable[[Self], None]) -> Callable[[Self], None]:
            def __decorated_tick_runner(fm: FlowManager):
                if cond(fm):
                    ret = tr(fm)
                    if ret is None:
                        return TickRunnerResult.DONE if only_once else TickRunnerResult.NEXT
                    return ret
                return TickRunnerResult.NEXT
            self.add()(__decorated_tick_runner)
            return tr
        return _decorator

    def run(self) -> TickRunnerResult:
        """
        运行一次内部所有函数

        Returns:
            所有tick_runner都执行完毕时返回DONE, 内部有人打断时返回BREAK_RUN, 否则返回NEXT.
        """
        if not (trs := self.tick_runners):
            return TickRunnerResult.DONE
        pop_list = []
        for idx, func in enumerate(trs):
            if (ret := func(self)) is TickRunnerResult.DONE:
                pop_list.append(idx)  # 早该换成链表了
            elif ret is TickRunnerResult.BREAK_RUN:
                for i in pop_list[::-1]:
                    self.tick_runners.pop(i)
                return TickRunnerResult.BREAK_RUN
        self.time += 1
        for i in pop_list[::-1]:
            trs.pop(i)
        return TickRunnerResult.NEXT


class FlowFactory:
    """
    用于生成FlowManager的工厂对象

    Attributes:
        flow_list: 所有flow组成的flow_list
        tick_runner_list: 所有tick_runner组成的列表
    """
    def __init__(self):
        self.flow_list: list[Flow] = []
        self.tick_runner_list: list[PriorityTickRunner] = []

    def add_flow(self) -> Callable[[Flow], Flow]:
        """
        添加flow的方法, 与FlowManager.add使用方法相同
        """
        def _decorator(f: Flow) -> Flow:
            self.flow_list.append(f)
            return f
        return _decorator

    def add_tick_runner(self, priority: int = 0) -> Callable[[TickRunner], TickRunner]:
        """
        添加tick_runner的方法, 与FlowManager.add使用方法相同

        Args:
            priority: 权重 越大越优先执行
        """
        def _decorator(tr: TickRunner):
            self.tick_runner_list.append((priority, tr))
            return tr
        return _decorator

    def connect(self, cond: CondFunc, priority: int = 0, only_once: bool = False) \
            -> Callable[[Callable[[Self], TickRunnerResult | None]],
                        Callable[[Self], TickRunnerResult | None]]:
        """
        把tick_runner绑定到cond上的方法, 与FlowManager.add使用方法相同

        Args:
            cond: 执行func的条件函数. 返回None时按照only_once判断; 返回TickRunnerResult时直接返回.
            priority: 权重 越大越优先执行
            only_once: 为true时 仅当第一次满足cond时执行
        """
        def _decorator(tr) -> TickRunner:
            def __decorated_tick_runner(fm: FlowManager):
                if cond(fm):
                    ret = tr(fm)
                    if ret is None:
                        return TickRunnerResult.DONE if only_once else TickRunnerResult.NEXT
                    return ret
                return TickRunnerResult.NEXT
            self.add_tick_runner(priority)(__decorated_tick_runner)
            return tr
        return _decorator

    def build_manager(self, flow_priority: int = 0) -> FlowManager:
        """
        生成FlowManager的方法

        Args:
            flow_priority: flow在tick runner中的权重, 越大越优先执行
        Returns:
            生成的FlowManager对象
        """
        return FlowManager(self.tick_runner_list, self.flow_list, flow_priority)

# -*- coding: utf_8 -*-
"""
流程控制相关的函数和类
"""

from __future__ import annotations  # 标准连这个破玩意都拖了3个版本不默认是吧

import heapq
from collections.abc import Generator, Callable
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
FlowGenerator: TypeAlias = Generator[CondFunc, None, TickRunnerResult | None]
"""Flow返回的生成器"""
Flow: TypeAlias = Callable[["FlowManager"], FlowGenerator]
"""
yield CondFunc函数的生成器函数

要求 yield (FlowManager) -> bool 且 不返回或者return TickRunnerResult:
    - 当yield返回函数执行为True时候继续往下执行
    - 返回None则无异常. 返回其他值的时候 均打断Flow并且把返回值返回给FlowManager
"""
TickRunner: TypeAlias = Callable[["FlowManager"], TickRunnerResult]
"""帧运行函数"""
PriorityTickRunner: TypeAlias = tuple[int, TickRunner]
"""带权重的帧运行函数"""


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
        self._flow_generator_list: list[list[CondFunc, FlowGenerator]] \
            = [[lambda _: True, i(self)] for i in flows]

        def __flow_tick_runner(self_: FlowManager) -> TickRunnerResult:
            if not self_._flow_generator_list:
                return TickRunnerResult.DONE
            pop_list = []
            for idx, (cond_func, flow) in enumerate(self_._flow_generator_list):
                if cond_func(self_):
                    try:
                        self_._flow_generator_list[idx][0] = next(flow)
                    except StopIteration as se:  # StopIteration.value为generator返回值
                        pop_list.append(idx)  # 早该换成链表了
                        if se.value is None:
                            continue
                        for i in pop_list[::-1]:
                            self_._flow_generator_list.pop(i)
                        return se.value
                else:
                    continue
            for i in pop_list[::-1]:
                self_._flow_generator_list.pop(i)
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
            >>> flow_manager = FlowManager()
            >>> @flow_manager.add()
            ... def tr(fm: FlowManager) -> TickRunnerResult:
            ...     ...
            为装饰器形式使用

            >>> flow_manager = FlowManager()
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
            -> Callable[[Callable[[Self], TickRunnerResult | None]], Callable[[Self], TickRunnerResult | None]]:
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
        pop_list = []
        if (trs := self.tick_runners) is None:
            return TickRunnerResult.DONE
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
            -> Callable[[Callable[[Self], TickRunnerResult | None]], Callable[[Self], TickRunnerResult | None]]:
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

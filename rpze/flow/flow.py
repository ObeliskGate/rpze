# -*- coding: utf_8 -*-
"""
流程控制相关的函数和类
"""

from __future__ import annotations

import heapq
from collections.abc import Generator, Callable
from enum import Enum, auto
from itertools import count
from typing import TypeAlias, Any


class TickRunnerResult(Enum):
    DONE = auto(),
    NEXT = auto(),
    END_FLOW = auto()


CondFunc: TypeAlias = Callable[["FlowRunner"], bool]
FlowGenerator: TypeAlias = Generator[CondFunc, None, Any]
Flow: TypeAlias = Callable[["FlowRunner"], FlowGenerator]
TickRunner: TypeAlias = Callable[["FlowRunner"], TickRunnerResult]
PriorityTickRunner: TypeAlias = tuple[int, TickRunner]


class FlowRunner:
    """
    运行TickRunner函数的对象

    Attributes:
        tick_runners: 所有TickRunner组成的堆, 运行时按顺序执行
        time: 每执行一次do自增1
    """
    def __init__(self, tick_runners: list[PriorityTickRunner],
                 flows: list[Flow], flow_priority):
        """
        Args:
            tick_runners: tick_runner列表, 以PriorityTickRunner形式提供以便排序
            flows: flow列表
            flow_priority: flows执行优先级
        """
        self._flow_generator_list: list[list[CondFunc, FlowGenerator]] = [[lambda _: True, i(self)] for i in flows]

        def __flow_tick_runner(self_: FlowRunner):
            if not self_._flow_generator_list:
                return TickRunnerResult.DONE
            for idx, (cond_func, flow) in enumerate(self_._flow_generator_list):
                if cond_func(self_):
                    try:
                        self_._flow_generator_list[idx][0] = next(flow)
                    except StopIteration:
                        self_._flow_generator_list.pop(idx)
                else:
                    continue
            return TickRunnerResult.NEXT

        _counter = count()
        tick_runner_heap = [(-priority, next(_counter), it) for priority, it in tick_runners]
        heapq.heappush(tick_runner_heap, (-flow_priority, next(_counter), __flow_tick_runner))

        self.tick_runners: list[TickRunner | None] = [i[2] for i in tick_runner_heap]
        self.time = 0

    def add(self, tick_runner: TickRunner = None) -> Callable[[TickRunner], TickRunner]:
        """
        运行时添加TickRunner的装饰器

        不支持加权. 运行时添加的TickRunner会被放在最后执行.

        Examples:
            >>> flow_runner = FlowRunner()
            >>> @flow_runner.add()
            ... def tr(fr: FlowRunner) -> TickRunnerResult:
            ...     pass
            为装饰器形式使用

            >>> flow_runner = FlowRunner()
            >>> def tr(fr: FlowRunner) -> TickRunnerResult:
            ...     pass
            >>> flow_runner.add()(tick_runner)
            为函数形式使用
        """
        def _decorator(tr: TickRunner):
            self.tick_runners.append(tr)
            return tr
        return _decorator

    def connect(self, cond: CondFunc, only_once: bool = False) \
            -> Callable[[Callable[["FlowRunner"], Any]], TickRunner]:
        """
        运行时把tick_runner绑定到cond上的方法, 与add使用方法相同
        
        即 在cond(self)返回true时执行func(self).

        Args:
            cond: 执行func的条件函数
            only_once: 为true时 只要有一次满足cond则返回
        """
        def _decorator(tr: Callable[["FlowRunner"], Any]):
            def __decorated_tick_runner(fr: FlowRunner):
                if cond(fr):
                    tr(fr)
                    if only_once:
                        return TickRunnerResult.DONE
                return TickRunnerResult.NEXT
            self.add(__decorated_tick_runner)
            return __decorated_tick_runner
        return _decorator

    def run(self) -> bool:
        """
        运行一次内部所有函数

        Returns:
            所有tick_runner都执行完毕, 或有人返回停止运行时返回True
        """
        for idx, func in enumerate(self.tick_runners):
            if (ret := func(self)) is TickRunnerResult.DONE:
                self.tick_runners.pop(idx)  # 哎呀怎么有人从list里面pop东西呢
            elif ret is TickRunnerResult.END_FLOW:
                return True
        self.time += 1
        return not self.tick_runners


class FlowFactory:
    """
    用于生成FlowRunner的工厂对象

    Attributes:
        flow_list: 所有flow组成的flow_list
        tick_runner_list: 所有tick_runner组成的列表
    """
    def __init__(self):
        self.flow_list: list[Flow] = []
        self.tick_runner_list: list[PriorityTickRunner] = []

    def add_flow(self) -> Callable[[Flow], Flow]:
        """
        添加flow的方法, 与FlowRunner.add使用方法相同
        """
        def _decorator(f: Flow):
            self.flow_list.append(f)
            return f
        return _decorator

    def add_tick_runner(self, priority: int = 0) -> Callable[[TickRunner], TickRunner]:
        """
        添加tick_runner的方法, 与FlowRunner.add使用方法相同

        Args:
            priority: 权重 越大越优先执行
        """
        def _decorator(tr: TickRunner):
            self.tick_runner_list.append((priority, tr))
            return tr
        return _decorator

    def connect(self, cond: CondFunc, priority: int = 0, only_once: bool = False) \
            -> Callable[[Callable[[FlowRunner], Any]], TickRunner]:
        """
        把tick_runner绑定到cond上的方法, 与FlowRunner.add使用方法相同

        Args:
            cond: 执行func的条件函数
            priority: 权重 越大越优先执行
            only_once: 为true时 只要有一次满足cond则返回
        """
        def _decorator(tr: TickRunner):
            def __decorated_tick_runner(fr: FlowRunner):
                if cond(fr):
                    tr(fr)
                    if only_once:
                        return TickRunnerResult.DONE
                return TickRunnerResult.NEXT
            self.add_tick_runner(priority)(__decorated_tick_runner)
            return __decorated_tick_runner
        return _decorator

    def get_runner(self, flow_priority=0) -> FlowRunner:
        """
        生成FlowRunner的方法

        Args:
            flow_priority: flow在tick runner中的权重, 越大越优先执行
        Returns:
            生成的FlowRunner对象
        """
        return FlowRunner(self.tick_runner_list, self.flow_list, flow_priority)

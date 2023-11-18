# -*- coding: utf_8 -*-
"""
流程控制相关的函数和类
"""

from __future__ import annotations

import heapq
from collections import namedtuple
from collections.abc import Generator, Callable
from enum import Enum, auto
from itertools import count
from typing import TypeAlias


class TickRunnerResult(Enum):
    DONE = auto(),
    NEXT = auto()


CondFunc: TypeAlias = Callable[["FlowRunner"], bool]
FlowGenerator: TypeAlias = Generator[CondFunc, None, None]
Flow: TypeAlias = Callable[["FlowRunner"], FlowGenerator]
TickRunner: TypeAlias = Callable[["FlowRunner"], TickRunnerResult]
PriorityTickRunner = namedtuple(
    "PriorityTickRunner", ["priority", "tick_runner"])


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
        self._flow_generator_list: list[list[CondFunc, FlowGenerator]] =\
            [[lambda _: True, i(self)] for i in flows]

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

    def add(self, func: TickRunner = None):
        if func is None:
            def _decorator(tr: TickRunner):
                self.tick_runners.append(tr)
                return tr
            return _decorator
        self.tick_runners.append(func)

    def connect(self, cond: CondFunc, only_once: bool = False, tick_runner: TickRunner = None):
        if tick_runner is None:
            def _decorator(tr: TickRunner):
                def __decorator_tick_runner(fr: FlowRunner):
                    if cond(fr):
                        tr(fr)
                        if only_once:
                            return TickRunnerResult.DONE
                    return TickRunnerResult.NEXT
                self.add(__decorator_tick_runner)
                return __decorator_tick_runner
            return _decorator

        def __tick_runner(fr: FlowRunner):
            if cond(fr):
                tick_runner(fr)
                if only_once:
                    return TickRunnerResult.DONE
            return TickRunnerResult.NEXT
        self.add(__tick_runner)

    def run(self):
        for idx, func in enumerate(self.tick_runners):
            if func is None:
                continue
            ret = func(self)
            if ret is TickRunnerResult.DONE:
                self.tick_runners[idx] = None
        self.time += 1


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

    def add_flow(self, flow: Flow = None):
        if flow is None:
            def _decorator(f: Flow):
                self.flow_list.append(f)
                return f
            return _decorator
        else:
            self.flow_list.append(flow)

    def add_tick_runner(self, priority: int = 0, tick_runner: TickRunner = None):
        if tick_runner is None:
            def _decorator(tr: TickRunner):
                self.tick_runner_list.append((priority, tr))
                return tr
            return _decorator
        self.tick_runner_list.append((priority, tick_runner))

    def connect(self, cond: CondFunc, priority: int = 0, only_once: bool = False, tick_runner: TickRunner = None):
        if tick_runner is None:
            def _decorator(tr: TickRunner):
                def __decorator_tick_runner(fr: FlowRunner):
                    if cond(fr):
                        tr(fr)
                        if only_once:
                            return TickRunnerResult.DONE
                    return TickRunnerResult.NEXT
                self.add_tick_runner(priority, __decorator_tick_runner)
                return __decorator_tick_runner
            return _decorator

        def __tick_runner(fr: FlowRunner):
            if cond(fr):
                tick_runner(fr)
                if only_once:
                    return TickRunnerResult.DONE
            return TickRunnerResult.NEXT
        self.add_tick_runner(priority, __tick_runner)

    def get_runner(self, flow_priority=0) -> FlowRunner:
        return FlowRunner(self.tick_runner_list, self.flow_list, flow_priority)

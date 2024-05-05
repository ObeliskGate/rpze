# -*- coding: utf_8 -*-
"""
流程控制相关的函数和类
"""
from collections.abc import Callable, Coroutine
from enum import Enum, auto
from itertools import count
from typing import TypeAlias, Self


class TickRunnerResult(Enum):
    """TickRunner的返回值"""
    DONE = auto()
    """本tick runner以后再也不执行时返回"""
    BREAK_DONE = auto()  # 不用异常打断. StopIteration形式的返回值和type hint系统匹配程度太差.
    """需要打断本次运行并且以后不再运行本TickRunner时返回"""
    BREAK_ONCE = auto()
    """需要打断本次运行但以后还会运行本TickRunner时返回"""


CondFunc: TypeAlias = Callable[["FlowManager"], bool]
"""判断条件的函数"""
FlowCoroutine: TypeAlias = Coroutine[CondFunc, None, TickRunnerResult | None]
"""Flow返回的协程对象"""
Flow: TypeAlias = Callable[["FlowManager"], FlowCoroutine]
"""await AwaitableCondFunc函数的async def函数"""
TickRunner: TypeAlias = Callable[["FlowManager"], TickRunnerResult | None]
"""帧运行函数, 无返回值表示继续执行, 返回TickRunnerResult表示特殊行为"""


class FlowManager:
    """
    运行Flow和TickRunner函数的对象

    Attributes:
        tick_runners: 所有TickRunner组成的函数, 运行时按顺序执行
        destructor_list: 所有析构函数组成的函数, 在end()时按顺序执行
        time: 每执行一次do自增1
    """

    def __init__(self,
                 tick_runners: list[tuple[int, TickRunner]],
                 destructors: list[tuple[int, Callable[[Self], None]]],
                 flows: list[Flow],
                 flow_priority: int,
                 flow_destructor_priority: int):
        """
        Args:
            tick_runners: tick_runner列表, 以(priority, tick_runner)形式提供以便排序
            destructors: 析构列表, 在调用self.end()时执行, 以(priority, func)形式提供以便排序
            flows: flow列表
            flow_priority: flows执行优先级
            flow_destructor_priority: flows析构优先级
        """
        self.time = 0
        self._is_destructed = False
        self._flow_coro_list: list[list] = [[lambda _: True, i(self)] for i in flows]

        def _flow_tick_runner(self_: FlowManager) -> TickRunnerResult | None:
            if not (fcl := self_._flow_coro_list):
                return TickRunnerResult.DONE
            pop_list = []
            for idx, (cond_func, flow) in enumerate(fcl):
                try:
                    b = cond_func(self_)
                except BaseException as e:
                    flow.throw(e)
                    continue  # 如果能处理异常则继续执行
                if b:
                    try:
                        fcl[idx][0] = flow.send(None)
                    except StopIteration as se:  # StopIteration.value为返回值
                        pop_list.append(idx)
                        if se.value is None:
                            continue
                        for i in pop_list[::-1]:
                            fcl.pop(i)
                        return se.value
            for i in pop_list[::-1]:
                fcl.pop(i)

        _counter = count()
        tick_runner_list = [(-priority, next(_counter), it) for priority, it in tick_runners]
        tick_runner_list.append((-flow_priority, next(_counter), _flow_tick_runner))
        tick_runner_list.sort()
        # -priority让priority越大优先级别越高
        self.tick_runners: list[TickRunner] = [i[2] for i in tick_runner_list]

        def _flow_destructor(self_: FlowManager):
            for flow in self_._flow_coro_list:
                flow[1].close()

        destructor_list = [(-priority, next(_counter), it) for priority, it in destructors]
        destructor_list.append((-flow_destructor_priority, next(_counter), _flow_destructor))
        destructor_list.sort()
        self.destructor_list: list[Callable[[FlowManager], None]] = [i[2] for i in destructor_list]

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

    def add_destructor(self) -> Callable[[Callable[[Self], None]], Callable[[Self], None]]:
        """
        添加destructor的方法, 与FlowManager.add使用方法相同

        Returns:
            一个新的destructor函数
        """

        def _decorator(d: Callable[[FlowManager], None]) -> Callable[[FlowManager], None]:
            self.destructor_list.append(d)
            return d

        return _decorator

    def connect(self, cond: CondFunc, only_once: bool = False) -> Callable[[TickRunner], TickRunner]:
        """
        运行时把tick_runner绑定到cond上的方法, 与add使用方法相同
        
        即 在cond(self)返回true时执行func(self).

        Args:
            cond: 执行func的条件函数. 返回None时按照only_once判断; 返回TickRunnerResult时直接返回.
            only_once: 为True时 只要有一次满足cond则返回
        """

        def _decorator(tr: TickRunner) -> TickRunner:
            def _decorated_tick_runner(fm: FlowManager):
                if cond(fm):
                    ret = tr(fm)
                    if ret is None:
                        return TickRunnerResult.DONE if only_once else None
                    return ret

            self.add()(_decorated_tick_runner)
            return tr

        return _decorator

    def run(self) -> TickRunnerResult | None:
        """
        运行一次内部所有函数

        Returns:
            所有tick_runner都执行完毕或对象已经析构时返回DONE, 内部有人打断时返回BREAK_ONCE, 否则返回空.
        """
        if not (trs := self.tick_runners) or self._is_destructed:
            return TickRunnerResult.DONE
        pop_list = []

        def _end(_type):
            self.time += 1
            for it in pop_list[::-1]:
                trs.pop(it)
            return _type

        for idx, func in enumerate(trs):
            ret: TickRunnerResult | None = func(self)
            match ret:
                case None:
                    continue
                case TickRunnerResult.DONE:
                    pop_list.append(idx)  # 早该换成链表了
                case TickRunnerResult.BREAK_DONE:
                    pop_list.append(idx)
                    return _end(TickRunnerResult.BREAK_ONCE)
                case TickRunnerResult.BREAK_ONCE:
                    return _end(TickRunnerResult.BREAK_ONCE)
        return _end(None)

    def end(self):
        """
        结束运行时执行析构函数
        """
        self._is_destructed = True
        for d in self.destructor_list:
            d(self)


class FlowFactory:
    """
    用于生成FlowManager的工厂对象

    Attributes:
        flow_list: 所有flow组成的列表
        tick_runner_list: 所有tick_runner组成的列表
        destructor_list: 在FlowManager结束运行后会执行的所有函数
    """

    def __init__(self):
        self.flow_list: list[Flow] = []
        self.tick_runner_list: list[tuple[int, TickRunner]] = []
        self.destructor_list: list[tuple[int, Callable[[FlowManager], None]]] = []

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

    def add_destructor(self, priority: int = 0) \
            -> Callable[[Callable[[FlowManager], None]], Callable[[FlowManager], None]]:
        """
        添加destructor的方法, 与FlowManager.add使用方法相同

        Args:
            priority: 权重 越大越优先执行
        """

        def _decorator(d: Callable[[FlowManager], None]) -> Callable[[FlowManager], None]:
            self.destructor_list.append((priority, d))
            return d

        return _decorator

    def connect(self, cond: CondFunc, priority: int = 0, only_once: bool = False) \
            -> Callable[[TickRunner], TickRunner]:
        """
        把tick_runner绑定到cond上的方法, 与FlowManager.add使用方法相同

        Args:
            cond: 执行func的条件函数. 返回None时按照only_once判断; 返回TickRunnerResult时直接返回.
            priority: 权重 越大越优先执行
            only_once: 为true时 仅当第一次满足cond时执行
        """

        def _decorator(tr: TickRunner) -> TickRunner:
            def _decorated_tick_runner(fm: FlowManager):
                if cond(fm):
                    ret = tr(fm)
                    if ret is None:
                        return TickRunnerResult.DONE if only_once else None
                    return ret

            self.add_tick_runner(priority)(_decorated_tick_runner)
            return tr

        return _decorator

    def build_manager(self, flow_priority: int = 0, flow_destructor_priority: int = 0) -> FlowManager:
        """
        生成FlowManager的方法

        Args:
            flow_priority: flow在tick runner中的权重, 越大越优先执行
            flow_destructor_priority: flow析构函数在析构函数中的权重, 越大越优先执行
        Returns:
            生成的FlowManager对象
        """
        return FlowManager(self.tick_runner_list, self.destructor_list, self.flow_list,
                           flow_priority, flow_destructor_priority)

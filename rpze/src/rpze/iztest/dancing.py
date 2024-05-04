# -*- coding: utf_8 -*-
"""
mj相关操控
"""
from collections.abc import Callable
from enum import Enum
from typing import SupportsIndex, Literal, TypeAlias, Self, overload

from .iztest import IzTest
from ..flow.flow import FlowManager, TickRunnerResult, CondFunc
from ..flow.utils import AwaitableCondFunc
from ..rp_extend import ControllerError
from ..structs.game_board import GameBoard, get_board
from ..structs.zombie import Zombie, ZombieStatus

BackupPos: TypeAlias = Literal["w", "s", "a", "d"]
"""伴舞相对位置, w上, s下, a前, d后"""


@overload
def partner(mj: Zombie, item: SupportsIndex | BackupPos) -> Zombie | None:
    """
    获得mj的伴舞位置

    Args:
        mj: 目标mj
        item: 伴舞位置, 支持下标和字符串; 使用下表时按照伴舞位置的顺序, 0上, 1下, 2前, 3后
    Returns:
        伴舞位置的Zombie对象, 如果没有则返回None
    Raises:
        ValueError: 如果item不是有效位置
    """


@overload
def partner(mj: Zombie, item: str) -> tuple[Zombie | None, ...]:
    """
    获得mj的伴舞位置

    Args:
        mj: 目标mj
        item: 伴舞位置字符串, 按顺序返回

    Returns:
        一个元组, 按item中顺序返回伴舞位置的Zombie对象, 如果没有则返回None
    Examples:
        >>> partner(mj, "ws") == tuple(partner(mj, "w"), partner(mj, "s"))
        True
        >>> front, back = partner(mj, "ad")  # 获得前后伴舞
    """


def partner(mj: Zombie, item):
    zlist = get_board(mj.controller).zombie_list
    partners = [zlist.find(id_) for id_ in mj.partner_ids]
    if isinstance(item, SupportsIndex):
        return partners[item]
    if len(item) != 1:
        return tuple(partner(mj, i) for i in item)
    match item:
        case "w":
            return partners[0]
        case "s":
            return partners[1]
        case "a":
            return partners[2]
        case "d":
            return partners[3]
        case _:
            raise ValueError(f"{item} is not a valid partner pos")


def get_clock(board: GameBoard | None = None) -> int:
    """
    获取当前时钟

    Args:
        board: 默认None为使用get_board()
    Returns:
        当前时钟
    """
    if board is None:
        board = get_board()
    if (clock := board.mj_clock) >= 0:
        return clock % 460
    else:
        return -(-clock % 460)  # c/c++ %


def get_dancing_status(clock: int) -> ZombieStatus:
    """
    获取时钟对应的dancing状态

    Args:
        clock: 时钟时间
    Returns:
        当前时钟对应的僵尸状态
    """
    match clock:
        case t if t <= 11:
            return ZombieStatus.dancing_walking
        case 12:
            return ZombieStatus.dancing_armrise1  # 尝试召唤伙伴相位
        case 13 | 14 | 15:
            return ZombieStatus.dancing_armrise3
        case 16 | 17 | 18:
            return ZombieStatus.dancing_armrise2
        case 19 | 20 | 21:
            return ZombieStatus.dancing_armrise5
        case _:
            return ZombieStatus.dancing_armrise4


class DancingPhase(Enum):
    """
    mj相位, self.value表示该相位下的**一个**时钟值
    """
    TRYING_CALLING_PARTNER = 240  # 12 * 20
    DANCING = 260  # 13 * 20
    MOVING = 0


DancingPhaseLiteral: TypeAlias = DancingPhase | Literal["summon", "dance", "move", "s", "d", "m"]
"""mj相位字面量"""


def to_dancing_phase(literal: DancingPhaseLiteral) -> DancingPhase:
    """
    将字面量转换为DancingPhase

    Args:
        literal: 字面量
    Returns:
        转换后的DancingPhase对象
    Raises
        ValueError: 如果literal不是有效的相位字面量
    """
    match literal:
        case "summon" | "s" | DancingPhase.TRYING_CALLING_PARTNER:
            return DancingPhase.TRYING_CALLING_PARTNER
        case "dance" | "d" | DancingPhase.DANCING:
            return DancingPhase.DANCING
        case "move" | "m" | DancingPhase.MOVING:
            return DancingPhase.MOVING
        case _:
            raise ValueError(f"{literal} is not a dancing phase literal")


def dancing_status_to_phase(status: ZombieStatus) -> DancingPhase:
    """
    将僵尸状态转换为DancingPhase

    Args:
        status: 僵尸状态
    Returns:
        转换后的DancingPhase对象
    Raises:
        ValueError: 如果status不是mj特有的状态
    """
    match status:
        case ZombieStatus.dancing_walking:
            return DancingPhase.MOVING
        case ZombieStatus.dancing_armrise1:
            return DancingPhase.TRYING_CALLING_PARTNER
        case ZombieStatus.dancing_armrise2 | ZombieStatus.dancing_armrise3 | \
             ZombieStatus.dancing_armrise4 | ZombieStatus.dancing_armrise5:
            return DancingPhase.DANCING
        case _:
            raise ValueError(f"{status} is not a dancing phase")


def get_dancing_phase(board: GameBoard | None = None) -> DancingPhase:
    """
    获取当前时钟对应的DancingPhase

    Args:
        board: 游戏板对象, 默认None为使用get_board()
    Returns:
        当前时钟对应的DancingPhase
    """
    return dancing_status_to_phase(get_dancing_status(get_clock(board)))


class _DmTr(Callable):
    def __init__(self, iz_test: IzTest):
        self.iz_test = iz_test
        self.current_phase: DancingPhase | None = None  # None表示不控制
        self.next_phase: DancingPhase | None = None  # None表示没有"下一个"状态
        self.cond_to_next: CondFunc = lambda _: True

    def keep_phase(self, _: FlowManager):
        cp = self.current_phase
        board = get_board(self.iz_test.controller)
        if cp.value != get_clock(board):
            board.mj_clock = cp.value

    def switch_to_next_phase(self, fm: FlowManager):
        if not self.cond_to_next(fm):
            return
        self.current_phase = self.next_phase
        self.next_phase = None
        self.cond_to_next = lambda _: True

    def __call__(self, fm: FlowManager) -> TickRunnerResult | None:
        if self.next_phase is not None:
            self.switch_to_next_phase(fm)
        if self.current_phase is not None:
            self.keep_phase(fm)
        return None

    @property
    def waiting_next_phase(self) -> bool:
        return self.next_phase is not None

    @property
    def is_controlling(self) -> bool:
        return self.current_phase is not None

    def start_controlling(self, phase: DancingPhase):
        self.current_phase = phase

    def stop_controlling(self, phase: DancingPhase):
        get_board(self.iz_test.controller).mj_clock = phase.value
        self.current_phase = None
        self.next_phase = None


class DancingManipulator:
    """
    mj相位控制器, 即, "女仆秘籍"

    Attributes:
        start_phase: with语句开始时的相位
        end_phase: with语句结束时的相位
    """
    def __init__(self, tr: _DmTr,
                 start_phase: DancingPhaseLiteral,
                 end_phase: DancingPhaseLiteral):  # protected interface
        self.start_phase: DancingPhase = to_dancing_phase(start_phase)
        self.end_phase: DancingPhase = to_dancing_phase(end_phase)
        self._tr: _DmTr = tr

    def next_phase(self, phase: DancingPhaseLiteral, condition: CondFunc = lambda _: True):
        """
        设置下一个相位

        Args:
            phase: 下一个相位
            condition: 到下一个相位的条件, 默认为恒真, 即直接进入下一个相位
        """
        self._tr.cond_to_next = condition
        self._tr.next_phase = to_dancing_phase(phase)

    async def until_next_phase(self, phase: DancingPhaseLiteral, condition: CondFunc):
        """
        等待到下一个相位, 用于flow内部

        使用中等效于:
        >>> async def flow(_):
        ...     await until(condition)
        ...     self.next_phase(phase)

        Args:
            phase: 下一个相位
            condition: 到下一个相位的条件
        """
        await AwaitableCondFunc(condition)
        self.next_phase(phase)

    def stop(self, end_phase: DancingPhaseLiteral):
        """
        停止控制

        Args:
            end_phase: 停止控制时的相位
        """
        if self._tr.is_controlling:
            self._tr.stop_controlling(to_dancing_phase(end_phase))

    def start(self, first_phase: DancingPhaseLiteral):
        """
        开始控制

        Args:
            first_phase: 开始控制时的相位
        """
        if not self._tr.is_controlling:
            self._tr.start_controlling(to_dancing_phase(first_phase))

    def __enter__(self) -> Self:
        self.start(self.start_phase)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is ControllerError:
            return
        self.stop(self.end_phase)


def get_dancing_manipulator(iz_test: IzTest,
                            start_phase: DancingPhaseLiteral = DancingPhase.MOVING,
                            end_phase: DancingPhaseLiteral = DancingPhase.MOVING,
                            priority: int | None = None) -> DancingManipulator:
    """
    获取一个DancingManipulator

    Args:
        iz_test: 和DancingManipulator对应的IzTest对象
        start_phase: 开始时的相位
        end_phase: 结束时的相位
        priority: DancingManipulator的优先级, 默认为默认优先级
    Returns:
        构造的DancingManipulator对象
    """
    dm_tr = _DmTr(iz_test)
    if priority is None:
        iz_test.flow_factory.add_tick_runner()(dm_tr)
    else:  # more simple method here?
        iz_test.flow_factory.add_tick_runner(priority)(dm_tr)
    return DancingManipulator(dm_tr, start_phase, end_phase)

# -*- coding: utf_8 -*-
"""
iztools 全场测试功能模拟
"""
import time
from collections.abc import Callable
from msvcrt import kbhit, getwch
from random import randint
from typing import TypeAlias, Self, overload, NamedTuple, SupportsIndex
import warnings

from .consts import plant_abbr_to_type, zombie_abbr_to_type
from .operations import enter_ize
from .plant_modifier import randomize_generate_cd
from ..basic.gridstr import parse_grid_str, GridStr
from ..basic.inject import ConnectedContext
from ..flow.flow import FlowFactory, TickRunnerResult, FlowManager, DEFAULT_PRIORITY
from ..flow.utils import until
from ..rp_extend import Controller, HookPosition, RpBaseException
from ..structs.game_board import GameBoard, get_board
from ..structs.griditem import Griditem
from ..structs.plant import PlantStatus, PlantType, Plant
from ..structs.zombie import ZombieType, Zombie


class PlaceZombieOp(NamedTuple):
    """
    描述僵尸放置操作的对象

    Attributes:
        type_: 要放置的僵尸类型
        time: 放置的时间
        row: 放置的行, 从0开始
        col: 放置的列, 从0开始
    """
    type_: ZombieType
    time: int
    row: int
    col: int


def parse_place_zombie_op(op_str: str) -> PlaceZombieOp:
    """
    解析单条僵尸放置操作字符串

    Args:
        op_str: 格式为 "类型 时间 行-列", 如 "cg 0 4-6"
    Returns:
        对应的 PlaceZombieOp
    Raises:
        ValueError: 格式错误时抛出
    Examples:
        >>> parse_place_zombie_op("cg 0 4-6")
        PlaceZombieOp(type_=ZombieType.cone, time=0, row=3, col=5)
    """
    parts = op_str.strip().split()
    if len(parts) != 3:
        raise ValueError(f"op_str must have 3 parts (type time row-col), not {len(parts)}: {op_str!r}")
    row, col = parse_grid_str(parts[2])
    return PlaceZombieOp(type_=zombie_abbr_to_type[parts[0]], time=int(parts[1]), row=row, col=col)


PlantTypeList: TypeAlias = list[list[PlantType | None]]


def parse_plant_type_list(plant_type_str: str) -> tuple[PlantTypeList, PlantTypeList]:
    """
    根据 iztools 植物字符串生成植物列表

    使用+号表示延迟一轮种植, 即"调控栈位".

    Args:
        plant_type_str: 与 izt 要求相同的植物列表字符串.
    Returns:
        两个5 * 5列表, 分别表示第一轮, 第二轮种植的植物. 空白值由 None 填充
    Raises:
        ValueError: plant_type_string 格式错误时抛出
    """
    first_list: list[list[PlantType | None]] = [[None] * 5 for _ in range(5)]
    second_list: list[list[PlantType | None]] = [[None] * 5 for _ in range(5)]
    lines = plant_type_str.strip().splitlines(False)
    if (t := len(lines)) != 5:
        raise ValueError(f"plant_type_string must have 5 lines, instead of {t} lines")
    for row, line in enumerate(lines):
        line = line.strip()
        plus_plant_indices = [i - 1 for i, char in enumerate(line) if char == '+']
        if not plus_plant_indices:
            if (t := len(line)) != 5:
                raise ValueError(f"line {row} must have 5 plants, instead of {t} plants")
            first_list[row] = [plant_abbr_to_type[abbr] for abbr in line]
        else:
            if plus_plant_indices[0] == -1:
                raise ValueError(f"line {row} can't start with +")
            col = 0
            for (i, char) in enumerate(line):
                if char == "+":
                    continue
                if i in plus_plant_indices:
                    second_list[row][col] = plant_abbr_to_type[char]
                else:
                    first_list[row][col] = plant_abbr_to_type[char]
                col += 1
            if col != 5:
                raise ValueError(f"line {row} must have 5 plants, instead of {t} plants")
    return first_list, second_list


def parse_target_list(target_str: str) -> tuple[list[tuple[int, int]], list[int]]:
    """
    根据 iztools 目标字符串生成目标列表

    Args:
        target_str: 与 izt 要求相同的目标字符串
    Returns:
        两个列表, 分别表示目标植物和目标脑子的位置
    """
    poses = [parse_grid_str(pos) for pos in target_str.strip().split()]
    return [pos for pos in poses if pos[1] != -1], [pos[0] for pos in poses if pos[1] == -1]


def parse_zombie_place_list(place_zombie_str: str) -> list[PlaceZombieOp]:
    """
    根据 iztools 僵尸放置字符串生成僵尸放置列表

    Args:
        place_zombie_str: 与 izt 要求相同的僵尸放置字符串.
    Returns:
        一个列表, 返回所有僵尸操作, 用 PlaceZombieOp 表示
    Raises:
        ValueError: place_zombie_string 格式错误时抛出
    """
    lines = place_zombie_str.strip().splitlines(False)
    if (t := len(lines)) != 3:
        raise ValueError(f"place_zombie_string must have 3 lines, instead of {t} lines")
    types = [zombie_abbr_to_type[abbr] for abbr in lines[0].strip().split()]
    times = [int(time_) for time_ in lines[1].strip().split()]
    rows, cols = zip(*(parse_grid_str(pos) for pos in lines[2].strip().split()))  # zip(*iterable)转置
    if not (len(types) == len(times) == len(rows) == len(cols)):
        raise ValueError("length of types, times, rows and cols must be equal")
    return [PlaceZombieOp(*op) for op in zip(types, times, rows, cols)]


_Id: TypeAlias = tuple[int, int]


class _IzGround:
    def __init__(self, origin_plant_ids: list[list[_Id]], origin_brain_ids: list[_Id], izt: "IzTest") -> None:
        self.origin_plant_ids: list[list[_Id]] = origin_plant_ids
        self.origin_brain_ids: list[_Id] = origin_brain_ids
        self.zombie_ids: list[_Id] = []
        self.izt: "IzTest" = izt

    @overload
    def __getitem__(self, item: tuple[int, int]) -> Plant | Griditem | None:
        """
        通过(row, col)获得测试开始时对应位置的植物或脑子.

        Args:
            item: (row, col)元组
        Returns:
            对象不存在 or 已死亡返回None, 否则返回该植物/脑子.
        Examples:
            >>> ground: _IzGround = ...
            >>> plant = ground[0, 0]  # 获得1-1位置的植物
            >>> brain = ground[4, -1]  # 获得第5行的脑子
        """

    @overload
    def __getitem__(self, item: GridStr) -> Plant | Griditem | None:
        """
        通过 GridStr 获得测试开始时对应位置的植物或脑子.

        Args:
            item: GridStr 位置
        Returns:
            对象不存在 or 已死亡返回None, 否则返回该植物/脑子.
        Examples:
            >>> ground: _IzGround = ...
            >>> plant = ground["1-1"]  # 获得1-1位置的植物
            >>> brain = ground["5-0"]  # 获得第5行的脑子
        """
    
    @overload
    def __getitem__(self, item: str) -> list[Plant | Griditem | None]:
        """
        通过字符串获得测试开始时对应位置的植物或脑子列表.

        Args:
            item: 由空格分隔的 GridStr 位置字符串
        Returns:
            对象不存在 or 已死亡返回None, 否则返回该植物/脑子.
        Examples:
            >>> ground: _IzGround = ...
            >>> plants = ground["1-1 2-2"]  # 获得1-1, 2-2位置的植物列表
            >>> brains = ground["1-0 2-0 3-0 4-0 5-0"]  # 获得所有脑子的列表
        """

    def __getitem__(self, item):
        match item:
            case (row, -1):
                t = self.izt.game_board.griditem_list.find(*self.origin_brain_ids[row])
                return None if t is None or t.is_dead else t
            case (row, col):
                t = self.izt.game_board.plant_list.find(*self.origin_plant_ids[row][col])
                return None if t is None or t.is_dead else t
            case grid:
                grids = grid.split()
                if len(grids) > 1:
                    return [self.__getitem__(parse_grid_str(g)) for g in grids]
                return self.__getitem__(parse_grid_str(grid))

    def zombie(self, i: SupportsIndex) -> Zombie | None:
        """
        获得写在 IzTest init_str 上的第 i 个僵尸

        Args:
            i: 索引, 支持负数, 如-1表示"此时 init_str 上写的, 最近放置的僵尸"
        Returns:
            不存在 or 已死亡返回 None, 否则返回僵尸
        """
        try:
            id_ = self.zombie_ids[i]
        except IndexError:
            return None
        t = self.izt.game_board.zombie_list.find(*id_)
        return None if t is None or t.is_dead else t


class IzTest:
    """
    模拟iztools全场测试.

    Attributes:
        plant_type_lists: 两个5 * 5列表, 分别表示第一轮, 第二轮种植的植物. 空白值由 None 填充.
        place_zombie_list: 一个列表, 表示所有僵尸操作, 用 PlaceZombieOp 表示.
        repeat_time: 重复次数.
        mj_init_phase: mj 初始相位. None 表示随机.
        target_plants_pos: 目标植物的位置列表. 元素为(row, col).
        target_brains_pos: 目标脑子的位置列表. 元素为 row.
        controller: 测试使用的 Controller 对象.
        flow_factory: 生成测试逻辑的 FlowFactory 对象.
        reset_generate_cd: 是否重置植物的 generate_cd, 即, iztools"开启攻击间隔处理" is True.
        enable_default_check_end: 是否启用默认的判断输赢功能.
        start_check_end_time: 开始判断一次测试是否输赢的时间.
        wait_squashes: 是否等待所有目标窝瓜消失后再开始判断输赢.
        end_callback: 一次测试结束时的回调函数, 参数为是否成功 bool.
        check_tests_end_callback: 判断是否结束测试的回调函数.
            参数为(当前测试次数, 成功次数), 返回 None 表示不结束, 返回 float 表示结果概率.
        ground: 用于获取原始植物和脑子的对象, 仅在测试中调用有效.
    """

    def __init__(self, controller: Controller, reset_generate_cd: bool | None = None):
        """
        构造 IzTest 对象

        如此构造的对象不能直接使用! 需要调用 init_by_str 或 init_by_kwargs 初始化.

        Args:
            controller: 测试使用的 Controller 对象.
            reset_generate_cd: [[deprecated]] 请改用 init_by_kwargs 的同名参数.
        """
        if reset_generate_cd is not None:
            warnings.warn("reset_generate_cd in __init__ is deprecated, "
                          "use init_by_kwargs(reset_generate_cd=...) instead",
                          DeprecationWarning, stacklevel=2)
        self.reset_generate_cd: bool = True if reset_generate_cd is None else reset_generate_cd
        self.plant_type_lists: tuple[PlantTypeList, PlantTypeList] = ([], [])
        self.place_zombie_list: list[PlaceZombieOp] = []
        self.repeat_time: int = 0
        self.mj_init_phase: int | None = None
        self.target_plants_pos: list[tuple[int, int]] = []
        self.target_brains_pos: list[int] = []
        self.controller: Controller = controller
        self.flow_factory: FlowFactory = FlowFactory()
        self.reset_generate_cd: bool = reset_generate_cd
        self.enable_default_check_end: bool = False
        self.start_check_end_time: int = 0
        self.wait_squashes: bool = True
        self.end_callback: Callable[[bool], None] = lambda _: None
        self.check_tests_end_callback: Callable[[int, int], float | None] | None = None

        # 以下是运行时候会时刻改变的量. 不建议修改 / 读取

        self._flow_factory_set: bool = False  # 用于判断是否设置了flow_factory

        # 每次运行重置的量
        self._ground: _IzGround | None = None
        self._target_squashes: list[tuple[int, int]] = []  # 所有目标窝瓜
        self._target_plant_ids: list[tuple[int, int]] = []  # 所有目标植物
        self._target_brain_ids: list[tuple[int, int]] = []  # 所有目标脑子
        self._last_test_ended: bool = False  # 用于判断是否结束一次测试

        # 跨测试累计的量
        self._success_count: int = 0  # 成功次数
        self._test_time: int = 0  # 测试次数

    @property
    def game_board(self) -> GameBoard:
        """游戏 GameBoard 对象"""
        return get_board(self.controller)

    @property
    def ground(self) -> _IzGround:
        """用于获取原始植物和脑子的对象, 仅在测试中调用有效."""
        if self._ground is None:
            raise ValueError("ground is not initialized, call start_test first")
        return self._ground

    def init_by_kwargs(
            self, *,
            repeat_time: int = 1000,
            plant_type_lists: str | tuple[PlantTypeList, PlantTypeList] = "",
            target_pos: str | list[GridStr] = "",
            place_zombie_list: str | list[PlaceZombieOp | str] = "",
            enable_default_check_end: bool = True,
            start_check_end_time: int = 0,
            mj_init_phase: int | None = None,
            wait_squashes: bool = True,
            reset_generate_cd: bool = True,
            check_tests_end_callback: Callable[[int, int], float | None] | None = None,
            end_callback: Callable[[bool], None] | None = None,
    ) -> Self:
        """
        通过关键字参数初始化 iztest 对象

        各参数相互独立, 不存在隐式联动. 所有参数均为 keyword-only.
        调用侧也可以用 izt.init_by_kwargs(**my_dict) 传字典.

        Args:
            repeat_time: 重复次数. check_tests_end_callback 为 None 时必须为正整数;
                提供 check_tests_end_callback 时此值仅用于打印显示, 默认 1000.
            plant_type_lists: 植物列表. 传入 str 时格式与 iztools 相同 (5行), 传入已解析的 tuple 时直接使用.
                默认为空串, 即全空场地.
            target_pos: 目标位置. 传入 str 时为空格分隔的 GridStr, 传入 list[GridStr] 时为 GridStr 列表.
                行号用 R-0 表示脑子, R-C(C>0) 表示植物. 默认为空, 即无目标.
            place_zombie_list: 僵尸放置列表. 支持三种格式:
                - str: 与 iztools 相同的3行格式.
                - list[str]: 每个元素为 "类型 时间 行-列", 如 "cg 0 4-6".
                - list[PlaceZombieOp]: 直接使用已构造的对象列表.
                默认为空, 即不放置僵尸.
            enable_default_check_end: 是否启用内置判断输赢. 默认 True.
            start_check_end_time: 开始判断输赢的时刻. 默认 0, 不从僵尸时间自动推导.
            mj_init_phase: mj 初始相位. None 表示每轮随机. 合法值为 [0, 459]. 默认 None.
            wait_squashes: 是否等待所有目标窝瓜消失后再开始判断输赢. 默认 True.
            reset_generate_cd: 是否重置植物的 generate_cd (iztools"攻击间隔处理"). 默认 True.
            check_tests_end_callback: 判断是否结束全部测试的回调, 参数为 (测试次数, 成功次数),
                返回 None 继续, 返回 float 作为最终概率并结束. 默认 None, 即按 repeat_time 循环.
            end_callback: 单轮测试结束时的回调, 参数为是否成功. 默认 None, 即不覆盖已有回调.
        Returns:
            self
        Raises:
            ValueError: 参数格式或值非法时抛出
        Examples:
            >>> ctler: Controller = ...
            >>> iz_test = IzTest(ctler).init_by_kwargs(
            ...     repeat_time=1000,
            ...     target_pos="3-0 4-0 5-0 3-3",
            ...     plant_type_lists='''
            ...         .....
            ...         .....
            ...         bs3_c
            ...         b2ljh
            ...         blyl_''',
            ...     place_zombie_list=["cg 0 4-6",
            ...                        "cg 1 4-6",
            ...                        "xg 300 4-6",
            ...                        "ww 700 4-6"],
            ...     start_check_end_time=700)
            以上与 init_by_str 的默认例子等价. 注意 start_check_end_time 需显式传入.
        """
        if check_tests_end_callback is None and repeat_time < 1:
            raise ValueError(f"repeat_time must be a positive integer, not {repeat_time}")
        if mj_init_phase is not None and not (0 <= mj_init_phase < 460):
            raise ValueError(f"mj_init_phase must be in [0, 459] or None, not {mj_init_phase}")

        self.wait_squashes = wait_squashes
        self.mj_init_phase = mj_init_phase
        self.repeat_time = repeat_time
        self.start_check_end_time = start_check_end_time
        self.enable_default_check_end = enable_default_check_end
        self.reset_generate_cd = reset_generate_cd

        if isinstance(plant_type_lists, str):
            self.plant_type_lists = (parse_plant_type_list(plant_type_lists)
                                     if plant_type_lists.strip()
                                     else ([[None] * 5 for _ in range(5)],
                                           [[None] * 5 for _ in range(5)]))
        else:
            self.plant_type_lists = plant_type_lists

        if isinstance(place_zombie_list, str):
            self.place_zombie_list = (parse_zombie_place_list(place_zombie_list)
                                      if place_zombie_list.strip() else [])
        else:
            self.place_zombie_list = [
                parse_place_zombie_op(op) if isinstance(op, str) else op
                for op in place_zombie_list
            ]

        target_str = target_pos if isinstance(target_pos, str) else ' '.join(target_pos)
        if target_str.strip():
            self.target_plants_pos, self.target_brains_pos = parse_target_list(target_str)
        else:
            self.target_plants_pos, self.target_brains_pos = [], []

        for pos in self.target_plants_pos:
            if (self.plant_type_lists[0][pos[0]][pos[1]] is None and
                    self.plant_type_lists[1][pos[0]][pos[1]] is None):
                raise ValueError(f"target plant at {pos} is None")

        if check_tests_end_callback is not None:
            self.check_tests_end_callback = check_tests_end_callback
        if end_callback is not None:
            self.end_callback = end_callback

        return self

    def init_by_str(self, iztools_str: str,
                    wait_squashes: bool = True,
                    reset_generate_cd: bool = True) -> Self:
        """
        通过 iztools 字符串初始化 iztest 对象

        与 iztools 的输入格式不完全相同:
            - 允许首尾空行以及每行首尾空格.
            - 支持"测试次数"输入-1表示自定义结束行为:
                结束行为默认为测试无限次, 可以通过 self.check_tests_end() 设置何时结束.
            - 支持第二行空行表示无目标: 若此行为空, 则不启用内置的判断输赢功能.
            - 支持不输入8 9 10行表示不放置僵尸: 若此三行为空, 则不启用内置的判断输赢功能.
            - (暂且)不支持通过书写顺序调整僵尸编号, 可以通过 ObjList 相关接口调整.

        以下三个变量由此方法根据字符串内容自动推导, 而非由调用方显式控制:
            - enable_default_check_end: 目标行(第2行)非空时置 True, 否则保持 __init__ 默认值 False.
            - start_check_end_time: 有僵尸行(第8-10行)时置为所有僵尸中最晚的放置时间, 否则保持 0.
            - check_tests_end_callback: repeat_time 为 -1 时置为无限循环 lambda, 否则保持 None.

        在本方法中未提到的参数使用 init_by_kwargs 中说明的默认值, 如需控制这些参数请使用 init_by_kwargs.

        Args:
            iztools_str: iztools输入字符串
            wait_squashes: 是否等待所有窝瓜消失后再开始判断输赢. 默认为 True
            reset_generate_cd: 是否重置植物的 generate_cd (iztools "攻击间隔处理"). 默认 True
        Returns:
            self
        Raises:
            ValueError: 输入字符串格式错误时抛出
        Examples:
            >>> ctler: Controller = ...
            >>> iz_test = IzTest(ctler).init_by_str('''
            ...     1000 -1
            ...     3-0 4-0 5-0 3-3
            ...     .....
            ...     .....
            ...     bs3_c
            ...     b2ljh
            ...     blyl_
            ...     cg   cg   xg   ww
            ...     0    1    300  700
            ...     4-6  4-6  4-6  4-6''')
            如上为iztools默认例子的输入方式.
        """
        lines = iztools_str.strip().splitlines(False)

        if len(lines) == 7:
            place_zombie_ops: list[PlaceZombieOp] = []
            start_check_end_time = 0
        elif len(lines) == 10:
            place_zombie_ops = parse_zombie_place_list('\n'.join(lines[7:10]))
            start_check_end_time = max(op.time for op in place_zombie_ops)
        else:
            raise ValueError(f"iztools_str must have 7 or 10 lines, not {len(lines)} lines")

        repeat_time, mj_init_phase = map(int, lines[0].strip().split())
        if mj_init_phase < -1 or mj_init_phase >= 460:
            raise ValueError(f"mj_init_phase must be in [-1, 459], not {mj_init_phase}")
        if repeat_time < -1 or repeat_time == 0:
            raise ValueError(f"repeat_time must be positive or -1, not {repeat_time}")

        target_plants, target_brains = parse_target_list(lines[1])

        return self.init_by_kwargs(
            repeat_time=repeat_time if repeat_time != -1 else 0,
            plant_type_lists='\n'.join(lines[2:7]),
            target_pos=lines[1],
            place_zombie_list=place_zombie_ops,
            enable_default_check_end=bool(target_plants or target_brains),
            start_check_end_time=start_check_end_time,
            mj_init_phase=mj_init_phase if mj_init_phase != -1 else None,
            wait_squashes=wait_squashes,
            reset_generate_cd=reset_generate_cd,
            check_tests_end_callback=(lambda _, __: None) if repeat_time == -1 else None,
        )

    def on_game_end(self) -> Callable[[Callable[[bool], None]], Callable[[bool], None]]:
        """
        装饰器, 设置结束时的回调函数

        回调的 bool 参数为本次测试是否成功.

        Returns:
            添加用装饰器
        """

        def _decorator(func):
            self.end_callback = func
            return func

        return _decorator

    def end(self, succeeded: bool) -> TickRunnerResult:
        """
        返回本函数, 表示本次测试结束

        Args:
            succeeded: 成功则传入 True, 失败传入 False
        Returns:
            TickRunnerResult.BREAK_RUN
        """
        self._last_test_ended = True
        self.end_callback(succeeded)
        if succeeded:
            self._success_count += 1
        self._test_time += 1

        return TickRunnerResult.BREAK_DONE

    def check_end(self) -> TickRunnerResult | None:
        """
        默认的判断是否结束测试的函数

        Returns:
            如果结束则返回 TickRunnerResult.BREAK_RUN, 否则返回 None
        """
        board = self.game_board
        if self.wait_squashes:
            for ids in self._target_squashes:
                match board.plant_list.find(*ids):
                    case None:
                        continue
                    case squash:
                        if squash.m_state is not PlantStatus.NOTREADY:
                            return None

        if (all(board.griditem_list.find(*brain) is None for brain in self._target_brain_ids) and
                all(board.plant_list.find(*plant) is None for plant in self._target_plant_ids)):
            return self.end(True)
        if board.zombie_list.obj_num == 0:
            return self.end(False)
        return None

    def check_tests_end(self) \
            -> Callable[[Callable[[int, int], float | None]], Callable[[int, int], float | None]]:
        """
        装饰器, 设置判断是否结束测试的回调函数

        Returns:
            添加用装饰器
        """

        def _decorator(func):
            self.check_tests_end_callback = func
            return func

        return _decorator

    def set_flow_factory(self,
                         place_priority: int = DEFAULT_PRIORITY + 10,
                         check_end_priority: int = DEFAULT_PRIORITY - 10,
                         clean_priority: int = DEFAULT_PRIORITY - 10) -> Self:
        """
        设置 flow_factory

        Args:
            place_priority: 初始化及放置僵尸 tick runner 的优先级, 默认为 default + 10
            check_end_priority: 判断输赢 tick runner 的优先级, 默认为 default - 10
            clean_priority: 清理 tick runner 的优先级, 默认为 default - 10
        Returns:
            self
        Raises:
            RpBaseException: 已经设置过 flow_factory 时抛出
        """
        if self._flow_factory_set:
            raise RpBaseException("cannot set flow factory twice!")
        self._flow_factory_set = True

        @self.flow_factory.connect(until(0), only_once=True, priority=place_priority)
        def _init(_):
            # 清掉所有_ObjList的栈
            origin_plant_ids: list[list[_Id]] = [[None] * 5 for _ in range(5)]  # type: ignore
            origin_brain_ids: list[_Id] = [None] * 5  # type: ignore
            board = self.game_board
            board.plant_list.free_all().reset_stack()
            board.zombie_list.free_all().reset_stack()
            board.projectile_list.free_all().reset_stack()
            board.griditem_list.free_all().reset_stack()
            board.mj_clock = randint(0, 459) if self.mj_init_phase is None else self.mj_init_phase

            for plant_list in self.plant_type_lists:
                for row, line in enumerate(plant_list):
                    for col, type_ in enumerate(line):
                        if type_ is None:
                            continue
                        plant = board.iz_new_plant(row, col, type_)
                        # assert plant is not None
                        origin_plant_ids[row][col] = plant.id.tpl()
                        if self.reset_generate_cd:
                            randomize_generate_cd(plant)
                        if (row, col) in self.target_plants_pos:
                            self._target_plant_ids.append(plant.id.tpl())
                            if self.wait_squashes and type_ is PlantType.squash:
                                self._target_squashes.append(plant.id.tpl())

            for i in range(5):
                brain = self.game_board.new_iz_brain(i)
                origin_brain_ids[i] = brain.id.tpl()
                if i in self.target_brains_pos:
                    self._target_brain_ids.append(brain.id.tpl())

            self._ground = _IzGround(origin_plant_ids, origin_brain_ids, self)

        for op in self.place_zombie_list:
            @self.flow_factory.add_tick_runner(place_priority)
            def _place_zombie(fm: FlowManager, _op=op):
                if fm.time == _op.time:
                    t = self.game_board.iz_place_zombie(_op.row, _op.col, _op.type_)
                    self._ground.zombie_ids.append(t.id.tpl())
                    return TickRunnerResult.DONE
                return None

        if self.enable_default_check_end:
            @self.flow_factory.add_tick_runner(check_end_priority)
            def _check_end(fm: FlowManager):
                if fm.time >= self.start_check_end_time:
                    return self.check_end()
                return None

        @self.flow_factory.add_destructor(clean_priority)
        def _cleanup(_):
            # 重置每轮测试的运行时状态到默认值
            # _success_count 和 _test_time 是跨轮次累计统计量, 不在此重置
            self._ground = None
            self._target_plant_ids = []
            self._target_brain_ids = []
            self._target_squashes = []
            self._last_test_ended = False

        return self

    def start_test(self, jump_frame: bool = False,
                   speed_rate: float = 1.0,
                   print_interval: int = 10,
                   control_speed_key: str = '\x12'  # deprecated
                   ) -> tuple[float, float]:
        """
        开始测试

        Args:
            jump_frame: True 则以'跳帧'为初始测试状态
            speed_rate: 默认速度倍率. '非跳帧'时生效. 非法值会被截断到[0.05, 10.0]区间内
            print_interval: 每隔 print_interval 次测试打印一次结果. 输入0时代表不打印
            control_speed_key: [[deprecated]] '非跳帧'时切换 原速/默认速度倍率 的按键. 默认值为 Ctrl+R
        Returns:
            (测试概率, 使用时间)元组
        """
        if control_speed_key != '\x12':
            warnings.warn("deprecated param `control_speed_key`", DeprecationWarning)
        if self.controller.read_i32(0x6a9ec0, 0x7f8) != 70:  # gLawnApp->mGameMode != ize
            enter_ize(self.controller)
        start_time = time.time()
        last_time = start_time
        ctler = self.controller
        ctler.open_hook(HookPosition.CHALLENGE_I_ZOMBIE_SCORE_BRAIN)
        if not self._flow_factory_set:
            self.set_flow_factory()
        with ConnectedContext(ctler) as ctler:
            fd = round(10 / speed_rate)
            if fd == 0:
                frame_duration = 1
            elif fd > 200:
                frame_duration = 200
            else:
                frame_duration = fd
            if jump_frame:
                ctler.start_jump_frame()
            else:
                self.game_board.frame_duration = frame_duration
            ctler.skip_frames()

            def _one_test():
                nonlocal last_time
                _flow_manager = self.flow_factory.build_manager()
                ctler.skip_frames()
                while not self._last_test_ended:
                    _flow_manager.run()
                    if not ctler.is_jumping_frame() and kbhit() and getwch() == control_speed_key:
                        self.game_board.frame_duration = 10 \
                            if self.game_board.frame_duration != 10 else frame_duration
                    # print(_flow_manager.time)
                    ctler.skip_frames()
                _flow_manager.end()
                if print_interval and self._test_time % print_interval == 0:
                    print(f"ended {self._test_time} of {self.repeat_time}, "
                          f"success rate: {self._success_count / self._test_time:.2%}, "
                          f"using time: {(t := time.time()) - last_time:.2f}s.")
                    last_time = t

            if _callback := self.check_tests_end_callback:
                _one_test()  # no do while!
                while (result := _callback(self._test_time, self._success_count)) is None:
                    _one_test()
            else:
                for _ in range(self.repeat_time):
                    _one_test()
                result = self._success_count / self.repeat_time

            if jump_frame:
                ctler.end_jump_frame()
            else:
                self.game_board.frame_duration = 10
            ctler.close_hook(HookPosition.CHALLENGE_I_ZOMBIE_SCORE_BRAIN)
        return result, (time.time() - start_time)

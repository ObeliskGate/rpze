# -*- coding: utf_8 -*-
"""
iztools 全场测试功能模拟
"""
import time
from collections.abc import Callable
from msvcrt import kbhit, getwch
from random import randint
from typing import TypeAlias, Self, overload, NamedTuple, SupportsIndex

from .consts import plant_abbr_to_type, zombie_abbr_to_type
from .operations import enter_ize
from .plant_modifier import randomize_generate_cd
from ..basic.gridstr import parse_grid_str, GridStr
from ..basic.inject import ConnectedContext
from ..flow.flow import FlowFactory, TickRunnerResult, FlowManager
from ..flow.utils import until
from ..rp_extend import Controller, HookPosition, RpBaseException
from ..structs.game_board import GameBoard, get_board
from ..structs.griditem import Griditem
from ..structs.plant import PlantType, Plant
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


PlantTypeList: TypeAlias = list[list[PlantType | None]]


def parse_plant_type_list(plant_type_str: str) -> tuple[PlantTypeList, PlantTypeList]:
    """
    根据iztools植物字符串生成植物列表

    使用+号表示延迟一轮种植, 即"调控栈位".

    Args:
        plant_type_str: 与izt要求相同的植物列表字符串.
    Returns:
        两个5 * 5列表, 分别表示第一轮, 第二轮种植的植物. 空白值由None填充
    Raises:
        ValueError: plant_type_string格式错误时抛出
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
    根据iztools目标字符串生成目标列表

    Args:
        target_str: 与izt要求相同的目标字符串
    Returns:
        两个列表, 分别表示目标植物和目标脑子的位置
    """
    poses = [parse_grid_str(pos) for pos in target_str.strip().split()]
    return [pos for pos in poses if pos[1] != -1], [pos[0] for pos in poses if pos[1] == -1]


def parse_zombie_place_list(place_zombie_str: str) -> list[PlaceZombieOp]:
    """
    根据iztools僵尸放置字符串生成僵尸放置列表

    Args:
        place_zombie_str: 与izt要求相同的僵尸放置字符串.
    Returns:
        一个列表, 返回所有僵尸操作, 用PlaceZombieOp表示
    Raises:
        ValueError: place_zombie_string格式错误时抛出
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
        通过row, col获得测试开始时对应位置的植物或脑子.

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
        通过GridStr获得测试开始时对应位置的植物或脑子.

        Args:
            item: GridStr位置
        Returns:
            对象不存在 or 已死亡返回None, 否则返回该植物/脑子.
        Examples:
            >>> ground: _IzGround = ...
            >>> plant = ground["1-1"]  # 获得1-1位置的植物
            >>> brain = ground["5-0"]  # 获得第5行的脑子
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
                return self.__getitem__(parse_grid_str(grid))

    def zombie(self, i: SupportsIndex) -> Zombie | None:
        """
        获得写在IzTest init_str上的第i个僵尸

        Args:
            i: 索引, 支持负数, 如-1表示"此时init_str上写的最近放的僵尸"
        Returns:
            不存在 or 已死亡返回None, 否则返回僵尸
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
        plant_type_lists: 两个5 * 5列表, 分别表示第一轮, 第二轮种植的植物. 空白值由None(而非PlantType.none)填充.
        place_zombie_list: 一个列表, 表示所有僵尸操作, 用PlaceZombieOp表示.
        repeat_time: 重复次数.
        mj_init_phase: mj初始相位. None表示随机
        target_plants_pos: 目标植物的位置列表. 元素为(row, col)
        target_brains_pos: 目标脑子的位置列表. 元素为row
        controller: 测试使用的Controller对象.
        flow_factory: 生成测试逻辑的FlowFactory对象.
        reset_generate_cd: 是否重置植物的generate_cd, 即, iztools"开启攻击间隔处理"为True
        enable_default_check_end: 是否启用默认的判断输赢功能, 即, 需要手动设置判断时为False
        start_check_end_time: 开始判断一次测试是否输赢的时间, 默认为放下最后一个僵尸的时间.
        end_callback: 一次测试结束时的回调函数, 参数为是否成功bool.
        check_tests_end_callback: 判断是否结束测试的回调函数. 默认为None, 表示按照repeat_time次数重复测试.
            参数为(当前测试次数, 成功次数), 返回None表示不结束, 返回float表示计算概率.
        ground: 用于获取原始植物和脑子的对象. 仅在测试中调用有效.

    """

    def __init__(self, controller: Controller, reset_generate_cd: bool = True):
        """
        构造IzTest对象

        如此构造的对象不能直接使用! 大部分情况下需要调用init_by_str初始化.

        Args:
            controller: 测试使用的Controller对象.
            reset_generate_cd: 攻击间隔处理 in iztools
        """
        self.plant_type_lists: tuple[PlantTypeList, PlantTypeList] = ([], [])
        self.place_zombie_list: list[PlaceZombieOp] = []
        self.repeat_time: int = 0
        self.mj_init_phase: int | None = None
        self.target_plants_pos: list[tuple[int, int]] = []
        self.target_brains_pos: list[int] = []
        self.controller: Controller = controller
        self.flow_factory: FlowFactory = FlowFactory()
        self.reset_generate_cd: bool = reset_generate_cd
        self.enable_default_check_end: bool = True
        self.start_check_end_time: int = 0
        self.end_callback: Callable[[bool], None] = lambda _: None
        self.check_tests_end_callback: Callable[[int, int], float | None] | None = None
        self.ground: _IzGround | None = None

        # 运行时候会时刻改变的量. 不建议修改
        self._target_plants: list[Plant] = []  # 所有目标脑子
        self._target_brains: list[Griditem] = []  # 所有目标植物
        self._last_test_ended: bool = False  # 用于判断是否结束一次测试
        self._success_count: int = 0  # 成功次数
        self._test_time: int = 0  # 测试次数

        self._flow_factory_set: bool = False  # 用于判断是否设置了flow_factory

    @property
    def game_board(self) -> GameBoard:
        """游戏GameBoard对象"""
        return get_board(self.controller)

    def init_by_str(self, iztools_str: str) -> Self:
        """
        通过iztools字符串初始化iztest对象

        与iztools的输入格式不完全相同:
            - 允许首尾空行以及每行首尾空格.
            - 支持“测试次数”输入-1表示自定义结束行为, 结束行为默认为测试无限次, 需要self.check_tests_end()手动设置.
            - 支持第二行空行表示无目标: 若此行为空, 则不启用内置的判断输赢功能.
            - 支持不输入8 9 10行表示不放置僵尸: 若此行为空, 则不启用内置的判断输赢功能.
            - (暂且)不支持通过书写顺序调整僵尸编号.

        Args:
            iztools_str: iztools输入字符串
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
            self.place_zombie_list = []
            self.enable_default_check_end = False
        elif len(lines) == 10:
            self.place_zombie_list = parse_zombie_place_list('\n'.join(lines[7:10]))
            self.start_check_end_time = max(op.time for op in self.place_zombie_list)
        else:
            raise ValueError(f"iztools_str must have 7 or 10 lines, not {len(lines)} lines")

        repeat_time, mj_init_phase = map(int, lines[0].strip().split())
        if mj_init_phase < -1 or mj_init_phase >= 460:
            raise ValueError(f"mj_init_phase must be in [-1, 459], not {mj_init_phase}")
        self.mj_init_phase = mj_init_phase if mj_init_phase != -1 else None
        if repeat_time < -1 or repeat_time == 0:
            raise ValueError(f"repeat_time must be positive or -1, not {repeat_time}")
        if repeat_time != -1:
            self.repeat_time = repeat_time
        else:
            self.check_tests_end_callback = lambda _, __: None

        self.target_plants_pos, self.target_brains_pos = parse_target_list(lines[1])
        if self.target_plants_pos == [] and self.target_brains_pos == []:
            self.enable_default_check_end = False

        self.plant_type_lists = parse_plant_type_list('\n'.join(lines[2:7]))
        for target_pos in self.target_plants_pos:
            if (self.plant_type_lists[0][target_pos[0]][target_pos[1]] is None and
                    self.plant_type_lists[1][target_pos[0]][target_pos[1]] is None):
                raise ValueError(f"target plant at {target_pos} is None")
        return self

    def on_game_end(self) -> Callable[[Callable[[bool], None]], Callable[[bool], None]]:
        """
        装饰器, 设置结束时的回调函数

        回调的bool参数为本次测试是否成功.

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
            succeeded: 成功则传入True, 失败传入False
        Returns:
            TickRunnerResult.BREAK_RUN
        """
        self._last_test_ended = True
        self.end_callback(succeeded)
        if succeeded:
            self._success_count += 1
        self._test_time += 1

        self._target_plants = []
        self._target_brains = []

        return TickRunnerResult.BREAK_DONE

    def check_end(self) -> TickRunnerResult | None:
        """
        默认的判断是否结束测试的函数

        Returns:
            如果结束则返回TickRunnerResult.BREAK_RUN, 否则返回None
        """
        if (all(plant.is_dead for plant in self._target_plants) and
                all(brain.id.rank == 0 for brain in self._target_brains)):
            return self.end(True)
        if self.game_board.zombie_list.obj_num == 0:
            return self.end(False)

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
                         place_priority: int = 10,
                         check_end_priority: int = -10) -> Self:
        """
        设置flow_factory

        Args:
            place_priority: 初始化及放置僵尸tick runner的优先级, 默认为10
            check_end_priority: 判断输赢tick runner的优先级, 默认为-10
        Returns:
            self
        Raises:
            RpBaseException: 已经设置过flow_factory时抛出
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
                            self._target_plants.append(plant)

            for i in range(5):
                brain = self.game_board.new_iz_brain(i)
                origin_brain_ids[i] = brain.id.tpl()
                if i in self.target_brains_pos:
                    self._target_brains.append(brain)

            self.ground = _IzGround(origin_plant_ids, origin_brain_ids, self)

        for op in self.place_zombie_list:
            @self.flow_factory.add_tick_runner(place_priority)
            def _place_zombie(fm: FlowManager, _op=op):
                if fm.time == _op.time:
                    t = self.game_board.iz_place_zombie(_op.row, _op.col, _op.type_)
                    self.ground.zombie_ids.append(t.id.tpl())
                    return TickRunnerResult.DONE

        if self.enable_default_check_end:
            @self.flow_factory.add_tick_runner(check_end_priority)
            def _check_end(fm: FlowManager):
                if fm.time >= self.start_check_end_time:
                    return self.check_end()
        return self

    def start_test(self, jump_frame: bool = False,
                   speed_rate: float = 1.0,
                   print_interval: int = 10,
                   control_speed_key: str = '\x12') -> tuple[float, float]:
        """
        开始测试

        Args:
            jump_frame: True则开启跳帧测试.
            speed_rate: 速度倍率. 仅当jump_frame = False时有效.
            print_interval: 每隔print_interval次测试打印一次结果. 输入0时代表不打印
            control_speed_key: 非跳帧时切换原速/倍速的按键. 默认值为Ctrl+R
        Returns:
            (测试概率, 使用时间)元组
        """
        if self.controller.read_i32(0x6a9ec0, 0x7f8) != 70:  # gLawnApp->mGameMode == ize
            enter_ize(self.controller)
        start_time = time.time()
        last_time = start_time
        ctler = self.controller
        ctler.open_hook(HookPosition.CHALLENGE_I_ZOMBIE_SCORE_BRAIN)
        if not self._flow_factory_set:
            self.set_flow_factory()
        with ConnectedContext(ctler) as ctler:
            if jump_frame:
                ctler.start_jump_frame()
            else:
                frame_duration = 1 if (fd := round(10 / speed_rate)) == 0 else fd
                self.game_board.frame_duration = frame_duration
            ctler.skip_frames()

            def _one_test():
                nonlocal last_time
                _flow_manager = self.flow_factory.build_manager()
                ctler.skip_frames()
                while not self._last_test_ended:
                    _flow_manager.run()
                    if not jump_frame and kbhit() and getwch() == control_speed_key:
                        self.game_board.frame_duration = 10 \
                            if self.game_board.frame_duration != 10 else frame_duration
                    # print(_flow_manager.time)
                    ctler.skip_frames()
                self._last_test_ended = False
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

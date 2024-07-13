# -*- coding: utf_8 -*-
"""
注入, 打开游戏相关的函数和类.
"""
import os
import signal
import subprocess
import time
from collections.abc import Iterable
from contextlib import ContextDecorator, AbstractContextManager
from typing import Self, overload

from . import asm
from .exception import PvzStatusError
from ..rp_extend import Controller, ControllerError


def open_game(game_path: str, num: int = 1) -> list[int]:
    """
    通过路径, 将 pvz 作为子进程打开游戏
    
    Args:
        game_path: 游戏路径, 绝对相对路径均可
        num: 打开的游戏数量
    Returns:
        打开的所有游戏进程 process id 组成的列表
    """
    abs_path = os.path.abspath(game_path)
    route, exe_name = os.path.split(abs_path)
    current_directory = os.getcwd()
    ret = [0] * num
    try:
        os.chdir(route)
        for i in range(num):
            process = subprocess.Popen(f"\"{exe_name}\"")
            ret[i] = process.pid
    finally:
        os.chdir(current_directory)
    return ret


def inject(pids: Iterable[int],
           stdout=subprocess.DEVNULL,
           set_console: bool = True) -> list[Controller]:
    """
    对 pids 中的每一个进程注入 .dll
    
    Args:
        pids: 所有 process id
        stdout: inject程序标准输出流, 默认丢弃
        set_console: 是否打开游戏控制台
    Returns:
        所有进程的 Controller 对象组成的列表
    """
    current_dir = os.getcwd()
    try:
        os.chdir(os.path.dirname(__file__))
        dll_path = os.path.abspath("..\\bin\\rp_dll.dll")
        s = f'..\\bin\\rp_injector.exe {1 if set_console else 0} \"{dll_path}\" '
        s += ' '.join(str(i) for i in pids)
        subprocess.run(s, stdout=stdout)
    finally:
        os.chdir(current_dir)
    return [Controller(pid) for pid in pids]


def close_by_pids(pids: Iterable[int]) -> None:
    """
    通过 process id 关闭进程

    Args:
        pids: 需要关闭的 process id
    """
    for pid in pids:
        os.kill(pid, signal.SIGTERM)


class InjectedGame(AbstractContextManager):
    """
    描述被注入游戏的类

    Attributes:
        controller: 被注入游戏的控制器
    """
    @overload
    def __init__(self, process_id: int, /, close_when_exit: bool = True):
        """
        通过已经注入的 process id 构造 InjectedGame 对象

        Args:
            process_id: pvz 进程的 process id
            close_when_exit: 是否在退出时关闭 pvz 进程
        """

    @overload
    def __init__(self, game_path: str, /, close_when_exit: bool = True):
        """
        通过游戏路径构造 InjectedGame 对象

        Args:
            game_path: pvz 主程序路径
            close_when_exit: 是否在退出时关闭 pvz 进程
        """

    @overload
    def __init__(self, controller: Controller, /, close_when_exit: bool = True):
        """
        通过 Controller 对象构造 InjectedGame 对象

        Args:
            controller: 注入目标游戏的 Controller 对象
            close_when_exit: 是否在退出时关闭 pvz 进程
        """

    def __init__(self, arg, /, close_when_exit: bool = True):
        self._close_when_exit = close_when_exit
        if isinstance(arg, int):
            self.controller: Controller = Controller(arg)
        elif isinstance(arg, str):
            self.controller: Controller = inject(open_game(arg))[0]
        elif isinstance(arg, Controller):
            self.controller: Controller = arg
        else:
            raise TypeError("the parameter should be int, str or Controller instance")
        
    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is ControllerError:
            return
        self.controller.end()
        if (self._close_when_exit and
                exc_type is not KeyboardInterrupt):
            close_by_pids((self.controller.pid,))


class ConnectedContext(ContextDecorator):
    """
    创造已连接游戏的上下文

     Attributes:
         controller: 被注入游戏的控制器
         ensure_jump_frame: 是否保证跳帧, True 则保证跳帧, False 则保证不跳帧. 默认 None 不处理.
    """
    def __init__(self, controller: Controller, ensure_jump_frame: bool | None = None):
        self.controller: Controller = controller
        self.ensure_jump_frame = ensure_jump_frame
        self._is_connected: bool = False
        self._is_jumping: bool = False

    def __enter__(self) -> Controller:
        self._is_connected = self.controller.hook_connected()
        ctler = self.controller
        if not self._is_connected:
            ctler.start()
        if self.ensure_jump_frame is not None:
            self._is_jumping = ctler.is_jumping_frame()
            if self.ensure_jump_frame:
                ctler.start_jump_frame()
            else:
                ctler.end_jump_frame()
        return ctler

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is ControllerError:
            return
        ctler = self.controller
        if self.ensure_jump_frame is not None:
            if self._is_jumping:
                ctler.start_jump_frame()
            else:
                ctler.end_jump_frame()
        if not self._is_connected:
            ctler.end()
        else:
            ctler.start()


def enter_level(controller: Controller, game_mode: int, look_for_saved_game: bool = False) -> None:
    """
    进入游戏关卡

    Args:
        controller: 目标游戏的 Controller
        game_mode: 关卡对应数字
        look_for_saved_game: 是否尝试读档, **请切记默认情况会毁坏你原有的关卡存档!**
    Raises:
        PvzStatusError: 若不在载入界面, 主界面, 游戏中或小游戏选项卡界面使用此函数则抛出
        ControllerError: 若 Controller 对象未连接游戏则抛出
    """
    code = f"""
        push esi
        mov esi, [{0x6a9ec0}]
        mov eax, [esi + {0x7fc}]
        test eax, eax
        jz LCompleteLoading
        cmp eax, 1  // main screen
        je LDeleteGameSelector
        cmp eax, 7  // challenge selector screen
        je LDeleteChallengeScreen
        mov edx, [esi + {0x768}]
        test edx, edx  // have Board
        jnz LNewBoard
        LError:
        mov [{controller.result_address}], eax
        pop esi
        ret
        
        LDeleteChallengeScreen:
        call {0x44fd00}  // LawnApp::KillChallengeScreen(esi = LawnApp* this)
        jmp LPreNewGame
        
        LNewBoard:
        mov cl, [edx + {0x5760}]
        mov [esi + {0x88c}], cl  // deal with yeti
        jmp LPreNewGame
        
        LCompleteLoading:
        mov ecx, esi
        call {0x452cb0}  // LawnApp::LoadingCompleted(ecx = LawnApp* this)
        
        LDeleteGameSelector:
        call {0x44f9e0}  // LawnApp::KillGameSelector(esi = LawnApp* this)
        
        LPreNewGame:
        push {int(look_for_saved_game)}
        push {game_mode}
        call {0x44f560}  // LawnApp::PreNewGame
        xor eax, eax;
        mov [{controller.result_address}], eax;
        pop esi;
        ret;"""
    with ConnectedContext(controller, False) as ctler:
        if ctler.read_u32(0x6a9ec0, 0x76c) is not None:
            ctler.end()
            while not ctler.read_bool(0x6a9ec0, 0x76c, 0xa1):  # 是否加载成功bool, thanks for ghast
                if not ctler.global_connected():
                    raise ControllerError("global hook not connected")
                time.sleep(0.1)
            ctler.start()
        asm.run(code, ctler)
        ctler.skip_frames()
    if controller.result_i32:
        raise PvzStatusError("this function should be used at loading screen, "
                             "main selector screen, challenge selector screen or in the game"
                             f"while the current screen num is {controller.result_i32}")

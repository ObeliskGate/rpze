# -*- coding: utf_8 -*-
"""
注入, 打开游戏相关的函数和类.
"""
import os
import signal
import subprocess
import time
from typing import overload, Iterable

from . import asm
from ..rp_extend import Controller
from ..structs.game_board import GameBoard, get_board


def open_game(game_path: str, num: int = 1) -> list[int]:
    """
    通过路径, 将pvz作为python子进程打开游戏
    
    Args:
        game_path: 游戏路径, 绝对相对路径均可
        num: 打开的游戏数量
    Returns:
        打开的所有游戏进程process id组成的列表, 长度为num
    """
    abs_path = os.path.abspath(game_path)
    route, exe_name = os.path.split(abs_path)
    current_directory = os.getcwd()
    os.chdir(route)
    ret = [0] * num
    for i in range(num):
        process = subprocess.Popen(f"\"{exe_name}\"")
        ret[i] = process.pid
    os.chdir(current_directory)
    return ret


def inject(pids: Iterable[int]) -> list[Controller]:
    """
    对pids中的每一个进程注入dll
    
    Args:
        pids: 所有process id
    Returns:
        所有进程的Controller对象组成的列表
    """
    current_dir = os.getcwd()
    os.chdir(os.path.dirname(__file__))
    dll_path = os.path.abspath("..\\bin\\rp_dll.dll")
    s = f'..\\bin\\rp_injector.exe \"{dll_path}\" '
    s += ' '.join(str(i) for i in pids)
    try:
        subprocess.run(s)
    except Exception as e:
        raise e
    finally:
        os.chdir(current_dir)
    return [Controller(pid) for pid in pids]


def close_by_pids(pids: Iterable[int]) -> None:
    """
    通过process id关闭进程

    Args:
        pids: 需要关闭的 process id
    """
    for pid in pids:
        os.kill(pid, signal.SIGTERM)


class InjectedGame:
    """
    描述被注入游戏的类

    Attributes:
        controller: 被注入游戏的控制器
    """
    @overload
    def __init__(self, process_id: int, /, close_when_exit: bool = True):
        """
        通过process id构造InjectedGame对象

        Args:
            process_id: pvz进程的process id
            close_when_exit: 是否在退出时关闭pvz进程
        """

    @overload
    def __init__(self, game_path: str, /, close_when_exit: bool = True):
        """
        通过游戏路径构造InjectedGame对象

        Args:
            game_path: pvz主程序路径
            close_when_exit: 是否在退出时关闭pvz进程
        """

    @overload
    def __init__(self, controller: Controller, /, close_when_exit: bool = True):
        """
        通过Controller对象构造InjectedGame对象

        Args:
            controller: 注入目标游戏的Controller对象
            close_when_exit: 是否在退出时关闭pvz进程
        """

    def __init__(self, arg, close_when_exit: bool = True):
        self._close_when_exit = close_when_exit
        if isinstance(arg, int):
            self.controller: Controller = Controller(arg)
        elif isinstance(arg, str):
            self.controller: Controller = inject(open_game(arg))[0]
        elif isinstance(arg, Controller):
            self.controller: Controller = arg
        else:
            raise TypeError("the parameter should be int, str or Controller instance")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.controller.end()
        if self._close_when_exit:
            close_by_pids((self.controller.pid,))

    def enter_level(self, level_num: int, look_for_saved_game: bool = False) -> GameBoard:
        """
        进入游戏, 返回GameBoard对象.

        Args:
            level_num: 关卡对应数字
            look_for_saved_game: 是否尝试读档, **请切记默认情况会毁坏你原有的关卡存档!**
        Returns:
            GameBoard对象
        Raises:
            RuntimeError: 若不在载入界面, 主界面, 游戏中或小游戏选项卡界面使用此函数则抛出
        """
        code = f"""
            push esi;
            mov esi, [{0x6a9ec0}];
            mov eax, [esi + {0x7fc}];
            test eax, eax;
            jz LCompleteLoading;
            cmp eax, 1;  // main screen
            je LDeleteGameSelector;
            cmp eax, 7;  // challenge selector screen
            je LDeleteChallengeScreen;
            mov edx, [esi + {0x768}];
            test edx, edx;  // have Board
            jnz LNewBoard;
            LError:
            mov [{self.controller.result_address}], eax;
            pop esi;
            ret;
            
            LDeleteChallengeScreen:
            call 0x44fd00;  // LawnApp::KillChallengeScreen(esi = LawnApp* this)
            jmp LPreNewGame;
            
            LNewBoard:
            mov cl, [edx + {0x5760}]
            mov [esi + {0x88c}], cl
            jmp LPreNewGame;
            
            LCompleteLoading:
            mov ecx, esi;
            call {0x452cb0}; // LawnApp::LoadingCompleted(ecx = LawnApp* this)
            
            LDeleteGameSelector:
            call {0x44f9e0}; // LawnApp::KillGameSelector(esi = LawnApp* this)
            
            LPreNewGame:
            push {int(look_for_saved_game)};
            push {level_num};
            call 0x44f560;  // LawnApp::PreNewGame
            xor eax, eax;
            mov [{self.controller.result_address}], eax;
            pop esi;
            ret;"""
        with ConnectedContext(self.controller, False) as ctler:
            if ctler.read_bool([0x6a9ec0, 0x76c]):
                ctler.end()
                while not ctler.read_bool([0x6a9ec0, 0x76c, 0xa1]):  # 是否加载成功bool, thanks for ghast
                    time.sleep(0.1)
                ctler.start()
            asm.run(code, ctler)
            ctler.skip_frames()
            ret = get_board(ctler)
            
        if self.controller.result_i32:
            raise RuntimeError("this function should be used at loading screen, "
                               "main selector screen, challenge selector screen or in the game"
                               f"while the current screen num is {self.controller.result_i32}")
        return ret


def enter_ize(game: InjectedGame) -> GameBoard:
    """
    进入ize关卡.

    Args:
        game: 被注入的游戏对象
    Returns:
        进入的关卡, GameBoard对象
    """
    with ConnectedContext(game.controller) as ctler:
        board = game.enter_level(70)
        board.remove_cutscene_zombie()
        ctler.skip_frames()
    return board


class ConnectedContext:
    """
    创造已连接游戏的上下文

     Attributes:
         controller: 被注入游戏的控制器
         ensure_jump_frame: 是否保证跳帧, True则保证跳帧, False则保证不跳帧. 默认None不处理.
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

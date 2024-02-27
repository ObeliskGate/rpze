# -*- coding: utf_8 -*-
"""
注入, 打开游戏相关的函数和类.
"""
import os
import subprocess
from typing import overload

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


def inject(pids: list[int]) -> list[Controller]:
    """
    对pids中的每一个进程注入dll
    
    Args:
        pids: process id列表
    Returns:
        所有进程的Controller对象组成的列表
    """
    current_dir = os.getcwd()
    os.chdir(os.path.dirname(__file__))
    dll_path = os.path.abspath("..\\bin\\rp_dll.dll")
    s = f'..\\bin\\rp_injector.exe \"{dll_path}\" {len(pids)} '
    s += ' '.join([str(i) for i in pids])
    try:
        os.system(s)
    except Exception as e:
        raise e
    finally:
        os.chdir(current_dir)
    return [Controller(pid) for pid in pids]


class InjectedGame:
    """
    描述被注入游戏的类

    Attributes:
        controller: 被注入游戏的控制器
    """
    @overload
    def __init__(self, process_id: int, /):
        """
        通过process id构造InjectedGame对象

        Args:
            process_id: pvz进程的process id
        """

    @overload
    def __init__(self, game_path: str, /):
        """
        通过游戏路径构造InjectedGame对象

        Args:
            game_path: pvz主程序路径
        """

    @overload
    def __init__(self, controller: Controller, /):
        """
        通过Controller对象构造InjectedGame对象

        Args:
            controller: 注入目标游戏的Controller对象
        """

    def __init__(self, arg):
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

    def enter_level(self, level_num: int) -> GameBoard:
        """
        进入游戏, 返回GameBoard对象.

        **请切记这个函数会毁坏你原有的关卡存档!**

        Args:
            level_num: 关卡对应数字
        Returns:
            GameBoard对象
        Raises:
            RuntimeError: 若不在载入界面, 主界面, 游戏中或小游戏选项卡界面使用此函数则抛出
        """
        ctler = self.controller
        code = f"""
            push esi;
            mov esi, [{0x6a9ec0}];
            mov eax, [esi + {0x7fc}];
            test eax, eax;
            jz LCompleteLoading;
            cmp eax, 1;
            je LDeleteGameSelector;
            cmp eax, 7;
            je LDeleteChallengeScreen;
            cmp eax, 3;
            je LNewBoard;
            LError:
            mov [{ctler.result_address}], eax;
            pop esi;
            ret;
            
            LDeleteChallengeScreen:
            call 0x44fd00;  // LawnApp::KillChallengeScreen(esi = LawnApp* this)
            jmp LPreNewGame;
            
            LNewBoard:
            mov eax, [esi + {0x768}]
            mov cl, [eax + {0x5760}]
            mov [esi + {0x88c}], cl
            jmp LPreNewGame;
            
            LCompleteLoading:
            mov ecx, esi;
            call {0x452cb0}; // LawnApp::LoadingCompleted(ecx = LawnApp* this)
            
            LDeleteGameSelector:
            call {0x44f9e0}; // LawnApp::KillGameSelector(esi = LawnApp* this)
            
            LPreNewGame:
            push 0;
            push {level_num};
            call 0x44f560;  // LawnApp::PreNewGame
            xor eax, eax;
            mov [{ctler.result_address}], eax;
            pop esi;
            ret;"""
        with ConnectedContext(ctler) as ctler:
            ctler.before()
            if ctler.read_bool([0x6a9ec0, 0x76c]):
                ctler.end()
                while not ctler.read_bool([0x6a9ec0, 0x76c, 0xa1]):  # 是否加载成功bool, thanks for ghast
                    continue
                ctler.start()
                ctler.before()
            asm.run(code, ctler)
            ctler.next_frame()
            ctler.before()
            ctler.next_frame()
            ctler.before()
            ret = get_board(ctler)
            
        if self.controller.result_i32:
            raise RuntimeError("this function should be used at loading screen, "
                               "main selector screen or challenge selector screen, "
                               f"while the current screen num is {self.controller.result_i32}")
        return ret

class ConnectedContext:
    """
    创造已连接游戏的上下文

     Attributes:
         controller: 被注入游戏的控制器
    """
    def __init__(self, controller: Controller):
        self.controller: Controller = controller
        self._is_connected: bool = False

    def __enter__(self) -> Controller:
        self._is_connected = self.controller.hook_connected()
        if not self._is_connected:
            self.controller.start()
        return self.controller

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._is_connected:
            self.controller.end()

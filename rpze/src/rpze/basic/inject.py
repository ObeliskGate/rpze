# -*- coding: utf_8 -*-
from time import sleep
from typing import overload

import win32gui as win_g
import win32process as win_p
import os
import subprocess

from . import asm
from ..rp_extend import Controller
from ..structs.game_board import GameBoard, get_board


def find_window(window_name: str) -> int:
    """
    找到名称为str的窗口主进程pid
    
    Args:
        window_name: 窗口名字符串
    Returns:
        window_name主进程的process id
    """
    handle = win_g.FindWindow(None, window_name)
    _, pid = win_p.GetWindowThreadProcessId(handle)
    return pid


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
    for i in pids:
        s += str(i)
        s += ' '
    try:
        os.system(s)
    except RuntimeError as re:
        raise re
    finally:
        os.chdir(current_dir)
    return [Controller(pid) for pid in pids]


class InjectedGame:
    @overload
    def __init__(self, process_id: int):
        """
        通过process id构造InjectedGame对象

        Args:
            process_id: pvz进程的process id
        """

    @overload
    def __init__(self, game_path: str):
        """
        通过游戏路径构造InjectedGame对象

        Args:
            game_path: pvz主程序路径
        """

    @overload
    def __init__(self, controller: Controller):
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
            raise TypeError("the parameter shall be int, str or Controller")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.controller.end()

    def enter_level(self, level_num: int) -> GameBoard:
        """
        进入游戏, 返回GameBoard对象

        Args:
            level_num: 关卡对应数字
        Returns:
            GameBoard对象
        Raises:
            RuntimeError: 若不在载入界面, 主界面或小游戏选项卡界面使用此函数则抛出
        """
        code = f"""
            push esi;
            mov esi, [{0x6a9ec0}];
            mov eax, [esi + 0x7fc];
            test eax, eax;
            jz LCompleteLoading;
            cmp eax, 1;
            je LDeleteGameSelector;
            cmp eax, 7;
            je LDeleteChallengeScreen;     
            LError:
            mov [{self.controller.result_address}], eax;
            pop esi;
            ret;
            
            LDeleteChallengeScreen:
            mov edx, {0x44fd00}; // LawnApp::KillChallengeScreen(esi = LawnApp* this)
            call edx;
            jmp LPreNewGame;
            
            LCompleteLoading:
            mov ecx, esi;
            mov edx, {0x452cb0}; // LawnApp::LoadingCompleted(ecx = LawnApp* this)
            call edx;
            
            LDeleteGameSelector:
            mov edx, {0x44f9e0}; // LawnApp::KillGameSelector(esi = LawnApp* this)
            call edx;
            
            LPreNewGame:
            push 1;
            push {level_num};
            mov edx, {0x44f560}; // LawnApp::PreNewGame
            call edx;
            xor eax, eax;
            mov [{self.controller.result_address}], eax;
            pop esi;
            ret;"""  # copied from avz
        ctler = self.controller
        while not ctler.read_bool([0x6a9ec0, 0x76c, 0xa1]):  # 是否加载成功bool, thanks for ghast
            continue
        ctler.start()
        ctler.before()
        asm.run(code, ctler)
        ctler.next_frame()
        ctler.before()
        ctler.end()
        if self.controller.result_i32:
            raise RuntimeError("please use this function at loading screen, "
                               "selector screen or challenge selector screen")
        return get_board(ctler)

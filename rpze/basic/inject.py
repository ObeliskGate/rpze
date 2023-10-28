# -*- coding: utf_8 -*- 
import win32gui as wing
import win32process as winp
import os
import subprocess


def find_window(window_name: str) -> int:
    """
    找到名称为str的窗口主进程pid
    
    Args:
        window_name: 窗口名字符串
    Returns:
        window_name主进程的process id
    """
    handle = wing.FindWindow(None, window_name)
    _, pid = winp.GetWindowThreadProcessId(handle)
    return pid


def open_game(game_path: str, num: int=1) -> list[int]:
    """
    通过路径, 将pvz作为python子进程打开游戏
    
    Args:
        game_path: 游戏路径, 绝对相对路径均可
        num: 打开的游戏数量
    Returns:
        打开的所有游戏进程id组成的列表, 长度为num
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


def inject(pids: list[int]) -> None:
    """
    注入dll, pids为pid列表
    
    Args:
        pids: pid列表
    """
    dll_path = os.path.abspath(".\\bin\\rp_dll.dll")
    s = f'.\\bin\\rp_injector.exe \"{dll_path}\" {len(pids)} '
    for i in pids:
        s += str(i)
        s += ' '

    os.system(s)

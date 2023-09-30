# -*- coding: gbk -*- 

import win32api as win
import win32gui as wing
import win32process as winp
import os
import rp_extend as re

def find_window(window_name) -> int:
    """
    返回名称为str的窗口主进程pid
    """
    handle = wing.FindWindow(None, window_name)
    _, pid = winp.GetWindowThreadProcessId(handle)
    return pid

def inject(pids):
    s = f'..\\Release\\rp_injector.exe \"C:\\space\\projects\\rpz\\Release\\rp_dll.dll\" {len(pids)} '
    for i in pids:
        s += str(i)
        s += ' '
     
    os.system(s)

if __name__ == "__main__":  
    pid = find_window("Plants vs. Zombies")
    inject([pid])
    controller = re.Controller(pid)
    
    i = 0
    while True:
        i += 1;
        controller.next()

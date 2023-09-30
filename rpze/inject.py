import win32api as win
import win32gui as wing
import win32process as winp
import os

def find_window(window_name) -> int:
    """
    返回名称为str的窗口主进程pid
    """
    handle = wing.FindWindow(None, window_name)
    _, pid = winp.GetWindowThreadProcessId(handle)
    return pid

def inject(pids : list, in_debug=False):
    tmp = "Debug" if in_debug else "Release"
    s = f'..\\{tmp}\\rp_injector.exe \"C:\\space\\projects\\rpze\\{tmp}\\rp_dll.dll" {len(pids)} '
    print(s)
    for i in pids:
        s += str(i)
        s += ' '
     
    os.system(s)
import win32api as win
import win32gui as wing
import win32process as winp
import os

def find_window(window_name) -> int:
    """
    ��������Ϊstr�Ĵ���������pid
    """
    handle = wing.FindWindow(None, window_name)
    _, pid = winp.GetWindowThreadProcessId(handle)
    return pid

def inject(pids : list):
    s = f'..\\Release\\rp_injector.exe \"C:\\space\\projects\\rpz\\Release\\rp_dll.dll\" {len(pids)} '
    for i in pids:
        s += str(i)
        s += ' '
     
    os.system(s)
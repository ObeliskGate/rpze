# -*- coding: utf_8 -*-
"""
iztools 默认例子的测试
"""
from ..iztest.iztest import IzTest
from ..rp_extend import Controller


def default_test(ctler: Controller, jump_frame=True, time=1000):  # iztools 默认例子, 兼容性体现
    iz_test = IzTest(ctler).init_by_str(f'''
                 {time} -1
                 3-0 4-0 5-0 3-3
                 .....
                 .....
                 bs3_c
                 b2ljh
                 blyl_
                 cg   cg   xg   ww
                 0    1    300  700
                 4-6  4-6  4-6  4-6''')
    print(iz_test.start_test(jump_frame))

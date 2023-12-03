# -*- coding: utf_8 -*-
"""
iztools 默认例子的测试
"""
from ..flow.iztest import IzTest
from ..rp_extend import Controller


def default_test(ctler: Controller):
    iz_test = IzTest(ctler).init_by_str('''
                 1000 -1
                 3-0 4-0 5-0 3-3
                 .....
                 .....
                 bs3_c
                 b2ljh
                 blyl_
                 cg   cg   xg   ww
                 0    1    300  700
                 4-6  4-6  4-6  4-6''')
    print(iz_test.start_test())

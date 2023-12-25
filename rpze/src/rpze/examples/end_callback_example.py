# -*- coding: utf_8 -*-
"""
暂停测试过率演示.
"""
from ..flow.iztest import IzTest
from ..rp_extend import Controller


def end_test(ctler: Controller):
    iz_test = IzTest(ctler).init_by_str('''
                 -1 -1
                 2-0
                 .....
                 y_s_b
                 .....
                 .....
                 .....
                 tt
                 0
                 2-6''')

    @iz_test.if_end_test()
    def end_test_callback(test_time: int, success_time: int):
        z = 1.96
        diff = z / (success_time + z * z) * ((test_time - success_time) * success_time / test_time + z * z / 4) ** 0.5 \
            if test_time != 0 else 1
        if abs(diff) > 0.01:
            return None
        return (success_time + z * z / 2) / (test_time + z * z)

    print(iz_test.start_test(True))

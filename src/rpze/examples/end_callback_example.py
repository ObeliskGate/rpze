# -*- coding: utf_8 -*-
"""
暂停测试过率演示.
"""
from ..iztest.iztest import IzTest
from ..rp_extend import Controller


def end_test(ctler: Controller, jump_frame=True):
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

    @iz_test.check_tests_end()
    def end_test_callback(n, ns):  # n: 总次数, ns: 成功次数
        z = 1.96
        diff = z / (n + z * z) * ((n - ns) * ns / n + z * z / 4) ** 0.5
        if diff > 0.01:
            return None
        return (ns + z * z / 2) / (n + z * z)

    print(iz_test.start_test(jump_frame=jump_frame, print_interval=50))

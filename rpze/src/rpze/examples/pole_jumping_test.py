# -*- coding: utf_8 -*-
"""
欲速不达前置内容. 撑杆落地平均耗时测试.
"""
from ..flow.flow import FlowManager
from ..flow.iztest import IzTest
from ..rp_extend import Controller
from ..structs.zombie import ZombieStatus


def pole_jumping_test(ctler: Controller, row=8):  # izs对这种记录性多行兼容不是很好. 秀一下.
    t = IzTest(ctler).init_by_str(f"""
        1000 -1
        
        ....o
        ....o
        ....o
        ....o
        ....o
        cg       cg       cg       cg       cg
        0        0        0        0        0
        1-{row}  2-{row}  3-{row}  4-{row}  5-{row} 
        """)

    times = []
    tmp_time = [None] * 5

    @t.flow_factory.add_tick_runner()
    def tag_walking_pvz(fm: FlowManager):
        for idx, z in enumerate(~t.game_board.zombie_list):
            if (not tmp_time[idx]) and z.status == ZombieStatus.pole_vaulting_walking:
                tmp_time[idx] = fm.time

    @t.flow_factory.add_tick_runner()
    def check_end(_):
        nonlocal tmp_time
        if all(tmp_time):
            times.extend(tmp_time)
            tmp_time = [None] * 5
            return t.end(True)

    t.start_test(False, 100)
    print(sum(times) / len(times), len(times))

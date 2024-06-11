# -*- coding: utf_8 -*-
"""
生物钟 脚本示例
"""
from random import randint

from ..flow.utils import until
from ..iztest.cond_funcs import until_plant_last_shoot, until_plant_die
from ..iztest.iztest import IzTest
from ..iztest.operations import place, repeat
from ..rp_extend import Controller


def botanical_clock(ctler: Controller, jump_frame=False):  # 生物钟. 卡相位式非定态
    iz_test = IzTest(ctler).init_by_str('''
        1000 -1
        1-2 5-4
        zh_j5
        cptoh
        .....
        3lyp_
        hhwz1
        lz 
        0  
        2-6''')

    @iz_test.flow_factory.add_flow()
    async def place_zombie(_):
        ground = iz_test.ground
        flower = ground["2-5"]
        await until(lambda _: flower.hp <= 4)
        place("cg 2-6")  # 2-5花死前一瞬放撑杆
        star = ground["1-5"]
        await until_plant_last_shoot(star).after(151 - 96)
        # 上面randint不加是必过, 实际上需要判断星星打几下而不是直接找最后一下不攻击再放
        await repeat("xg 1-6")  # 星星最后一发攻击发出后1双鬼
        await until_plant_die(star).after(100)
        await repeat("cg 4-6")  # 星星死后4双杆
        await until_plant_die(ground["4-1"])
        place("cg 5-9")  # 三线死后5-9撑杆
        await until_plant_last_shoot(ground["5-5"]).after(151 + randint(0, 14))
        place("xg 5-6")  # 5-5最后一发攻击发出后5双鬼

    row_one_fail_count = 0
    row_five_fail_count = 0

    @iz_test.on_game_end()
    def end_callback(result: bool):
        if not result:
            nonlocal row_five_fail_count, row_one_fail_count
            if iz_test.ground["1-2"] is not None:
                row_one_fail_count += 1
            if iz_test.ground["5-4"] is not None:
                row_five_fail_count += 1

    iz_test.start_test(jump_frame, speed_rate=5)
    print(row_one_fail_count, row_five_fail_count)

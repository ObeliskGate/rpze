# -*- coding: utf_8 -*-
"""
生物钟 脚本示例
"""
from random import randint

from ..flow.iztest import IzTest
from ..flow.utils import until_plant_die, until_plant_last_shoot, repeat, place, until
from ..rp_extend import Controller


def botanical_clock(ctler: Controller):
    iz_test = IzTest(ctler).init_by_str('''
        1000 -1
        1-2 5-2
        zh_j5
        cptoh
        dsbhh
        3lyp_
        hhwz1
        lz 
        0  
        2-6''')

    @iz_test.flow_factory.add_flow()
    async def place_zombie(_):
        plist = iz_test.game_board.plant_list
        flower = plist["2-5"]
        await until(lambda _: flower.hp <= 4)
        place("cg 2-6")
        star = plist["1-5"]
        await until_plant_last_shoot(star).after(151 - 96)
        # 上面randint不加是必过, 需要判断星星打几下而不是直接找最后一下不攻击再放, 来不及
        await repeat("xg 1-6")
        await until_plant_die(star).after(100)
        await repeat("cg 4-6")
        await until_plant_die(plist["4-1"])  # 三线死亡
        place("cg 5-9")
        await until_plant_last_shoot(plist["5-5"]).after(151 + randint(0, 14))
        place("xg 5-6")

    row_one_fail_count = 0
    row_five_fail_count = 0

    @iz_test.on_game_end()
    def end_callback(result: bool):
        if not result:
            nonlocal row_five_fail_count
            nonlocal row_one_fail_count
            plant_list = iz_test.game_board.plant_list
            if plant_list.get_by_pos(0, 1) is not None:
                row_one_fail_count += 1
            if plant_list.get_by_pos(4, 1) is not None:
                row_five_fail_count += 1
            print(plant_list.get_by_pos(0, 1), plant_list.get_by_pos(4, 1))

    iz_test.start_test(jump_frame=True)
    print(row_one_fail_count, row_five_fail_count)

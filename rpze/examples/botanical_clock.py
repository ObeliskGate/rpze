# -*- coding: utf_8 -*-
"""
生物钟 脚本示例
"""
import random

from flow.flow import FlowManager
from flow.iztest import IzTest
from flow.utils import until_plant_die, delay, until_plant_last_shoot, continuous_place_zombie
from rp_extend import Controller
from structs.zombie import ZombieType


def botanical_clock(ctler: Controller):
    iz_test = IzTest(ctler).init_by_str('''
                    500 -1
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
    def place_zombie(_):
        board = iz_test.game_board
        flower = board.plant_list.get_by_pos(1, 4)
        yield lambda _: flower.hp <= 4
        board.iz_place_zombie(1, 5, ZombieType.pole_vaulting)
        star = board.plant_list.get_by_pos(0, 4)
        yield until_plant_last_shoot(star)
        yield delay(151 - 96 + random.randint(0, 14))
        # 上面randint不加是必过, 需要判断星星打几下而不是直接找最后一下不攻击再放, 来不及
        yield from continuous_place_zombie(board, 0, 5, ZombieType.imp)
        yield until_plant_die(star)
        yield delay(100)
        yield from continuous_place_zombie(board, 3, 5, ZombieType.pole_vaulting)
        yield until_plant_die(board.plant_list.get_by_pos(3, 0))  # 三线死亡
        board.iz_place_zombie(4, 8, ZombieType.pole_vaulting)
        yield until_plant_last_shoot(board.plant_list.get_by_pos(4, 4))
        yield delay(151 + random.randint(0, 14))
        board.iz_place_zombie(4, 5, ZombieType.imp)

    row_one_fail_count = 0
    row_five_fail_count = 0

    @iz_test.set_end_callback()
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

    iz_test.start_test(jump_frame=False)
    print(row_one_fail_count, row_five_fail_count)


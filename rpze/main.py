# -*- coding: utf_8 -*-   
from src.rpze.basic.inject import *
from src.rpze.examples.botanical_clock import botanical_clock
from src.rpze.flow import IzTest, FlowManager, VariablePool, AwaitableCondFunc, place
from src.rpze.structs import Plant, ProjectileType


def fun(ctler: Controller, jump_frame=True):
    iz_test = IzTest(ctler).init_by_str('''
        1000 -1
        3-0
        .....
        .....
        y3_s_
        .....
        .....
        cg cg 
        0  20
        3-6 3-6''')

    def count_butter(plant: Plant, n:int = 1):     #用来数黄油
        def _cond_func(fm: FlowManager,
                       v = VariablePool(try_to_shoot_time=None, butters = 0)):
            if plant.generate_cd == 1:  # 下一帧开打
                v.try_to_shoot_time = fm.time + 1
            if v.try_to_shoot_time == fm.time and plant.launch_cd != 0:  # 在攻击时
                for proj in ~iz_test.game_board.projectile_list:
                    if proj.type_ == ProjectileType.butter:
                        v.butters += 1                      #攻击的这一刻有黄油就加1
            if v.try_to_shoot_time == fm.time and plant.launch_cd == 0: #不再攻击时，计数清零
                v.butters = 0
            if v.butters == n:
                return True
            return False
        return AwaitableCondFunc(_cond_func)

    plist = iz_test.game_board.plant_list

    @iz_test.flow_factory.add_flow()
    async def place_zombie(_):
        y = plist["3-1"]
        await count_butter(y,2)
        place("lz 3-6")
    iz_test.start_test(jump_frame, speed_rate=1)


with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    board = game.enter_level(70)
    # fun(game.controller)
    ctler = game.controller
    ctler.start()
    ctler.before()
    for it in ~board.plant_list:
        print(it)
    ctler.next_frame()
    ctler.end()
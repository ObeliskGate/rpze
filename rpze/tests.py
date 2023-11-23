# -*- coding: utf_8 -*- 
import msvcrt as vc
import os
import time

import structs.game_board as gb
import structs.plant as plt
import structs.zombie as zmb
from flow.flow import FlowFactory, TickRunnerResult
from flow.utils import until_precise_digger, delay
from rp_extend import Controller


def basic_test(controller: Controller):
    start_time = 0
    b = True
    start_clock = int(time.time())
    while True:
        controller.before()
            
        if vc.kbhit():
            c = vc.getch()
            if c == b'j':
                b = False
                start_time = controller.get_time()
                start_clock = int(time.time())
                controller.start_jump_frame()
                print(c, start_time)
            elif c == b'u':
                print("u")
                board = gb.get_board(controller)
                board.plant_list.free_all()
                board.plant_list.reset_stack()
                for i in range(5):
                    board.iz_new_plant(4 - i, 1, plt.PlantType.cactus)
           
            elif c == b's':
                print(controller.get_time())
            elif c == b'r':
                print("sun", controller.read_i32([0x6a9ec0, 0x768, 0x5560]))
                controller.write_i32(8000, [0x6a9ec0, 0x768, 0x5560])
            elif c == b'c':
                print('c')
                asm_and_plant_test(controller)
            elif c == b'q':
                print('q')
                controller.end()
                print("sun", controller.read_i32([0x6a9ec0, 0x768, 0x5560]))
                os.system("pause")
                break
            elif c == b't':
                print(c)
                zombie_list_test(controller)
            elif c == b'g':
                print(c)
                griditem_test(controller)

        if (not b) and (controller.get_time() >= start_time + 1e6):
            controller.end_jump_frame()
            print("end", int(time.time()) - start_clock)
            b = True

        controller.next_frame()


def asm_and_plant_test(ctler):
    plist = gb.get_board(ctler).plant_list
    plant = gb.get_board(ctler).iz_new_plant(1, 3, plt.PlantType.cabbagepult)
    if plant is not None:
        print(plant.type_.name)
        print(plant)
        print(plant.__repr__())
        print(help(plt.Plant.launch_cd))
    for p in (p for p in plist if not p.is_dead):  # 我不知道为什么pycharm认为plist不是可迭代对象
        print(p)


def zombie_list_test(ctler):
    zlist = gb.get_board(ctler).zombie_list

    print(gb.get_board(ctler).iz_place_zombie(0, 3, zmb.ZombieType.dancing))
    for z in ~zlist:
        if z.type_ == zmb.ZombieType.dancing:
            for _id in z.partner_ids:
                if backup := zlist.find(_id):
                    print(backup)
                    print(zlist.find(backup.master_id) == z)


def griditem_test(ctler):
    glist = gb.get_board(ctler).griditem_list
    for g in ~glist:
        print(f"{g}, hp is {g.brain_hp}")


def flow_test(ctler):
    flow_manager = None
    while True:
        ctler.before()
        if vc.kbhit():
            c = vc.getch()
            if c == b't':
                board = gb.get_board(ctler)
                for p in ~board.plant_list:
                    p.die()
                magnet = board.iz_new_plant(2, 2, plt.PlantType.magnetshroom)
                board.iz_place_zombie(1, 4, zmb.ZombieType.digger)
                ff = FlowFactory()

                @ff.add_flow()  # vscode说这些函数都没用过...
                def place_digger_flow(fm):
                    for i in range(5):
                        yield until_precise_digger(magnet)
                        board.iz_new_plant(i, 1, plt.PlantType.split_pea)
                        board.iz_new_plant(i, 0, plt.PlantType.snow_pea)
                        board.iz_place_zombie(i, 5, zmb.ZombieType.digger)
                    yield delay(1500, fm)
                    board.iz_new_plant(1, 1, plt.PlantType.split_pea)
                    board.iz_new_plant(1, 0, plt.PlantType.snow_pea)
                    board.iz_place_zombie(1, 5, zmb.ZombieType.digger)

                @ff.add_tick_runner()
                def add_sun_tick_runner(_):
                    board.sun_num += 10
                    if board.sun_num >= 9990:
                        board.sun_num = 9990
                        return TickRunnerResult.DONE
                    return TickRunnerResult.NEXT

                flow_manager = ff.get_manager()
        if flow_manager is not None:
            flow_manager.run()
        ctler.next_frame()

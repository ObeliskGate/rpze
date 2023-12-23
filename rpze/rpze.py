# -*- coding: utf_8 -*-   
import src.rpze.basic.inject as inject
from src.rpze.examples.iztools_example import default_test
from src.rpze.structs.zombie import ZombieType

with inject.InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    board = game.enter_level(70)
    default_test(game.controller)
    # game.controller.start()
    # game.controller.before()
    # board.plant_list.free_all()
    # game.controller.start_jump_frame()
    # while True:
    #     game.controller.before()
    #     try:
    #         p = board.iz_place_zombie(0, 0, ZombieType.screendoor)
    #     except ValueError as ve:
    #         print(ve)
    #         break
    #     print(p)
    #     p.die_no_loot()
    #     # p = board.iz_new_plant(0, 0, 0)
    #     # p.die()
    #     game.controller.next_frame()

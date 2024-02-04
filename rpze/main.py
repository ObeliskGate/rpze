# -*- coding: utf_8 -*-   
from src.rpze.basic import InjectedGame
from src.rpze.examples.botanical_clock import botanical_clock
from src.rpze.examples.iztools_example import default_test
from src.rpze.flow import set_puff_x_offset
from src.rpze.structs import PlantType

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    board = game.enter_level(70)
    ctler = game.controller
    ctler.start()
    ctler.before()
    print(board.grid_to_pixel(1, 1))
    board.plant_list.free_all()
    puff = board.iz_new_plant(1, 1, PlantType.puffshroom)
    # set_puff_x_offset(puff, 3)
    ctler.end()

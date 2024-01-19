# -*- coding: utf_8 -*-   
from src.rpze.basic import InjectedGame
from src.rpze.examples.botanical_clock import botanical_clock
from src.rpze.examples.iztools_example import default_test
from src.rpze.structs import PlantType

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    board = game.enter_level(70)
    ctler = game.controller
    botanical_clock(ctler, False)
    # ctler.start()
    # ctler.before()
    # for plant in board.get_plants_on_lawn(1, 1):
    #     print(plant)
    # print(board.plant_list.get_by_grid(1, 1))

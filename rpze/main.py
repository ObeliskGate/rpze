# -*- coding: utf_8 -*-

from src.rpze.basic.inject import InjectedGame
from src.rpze.basic.inject import enter_ize
from src.rpze.examples.botanical_clock import botanical_clock

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe", True) as game:
    ctler = game.controller
    board = enter_ize(game)
    botanical_clock(ctler, True)

# c1, c2 = inject(open_game(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe", 2))
# g1, g2 = InjectedGame(c1), InjectedGame(c2)
# b1, b2 = enter_ize(g1), enter_ize(g2)
# with ConnectedContext(c1):
#     b1.plant_list.free_all()
#     get_board(c1)
#     place("1 1-1")
#     place("1 1-2")
# sleep(1)
# with ConnectedContext(c2):
#     b2.plant_list.free_all()
#     get_board(c2)
#     place("2 1-1")
#     place("2 1-2")

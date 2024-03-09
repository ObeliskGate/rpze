# -*- coding: utf_8 -*-

from src.rpze.basic.inject import InjectedGame, inject, open_game
from src.rpze.basic.inject import enter_ize
from src.rpze.examples.botanical_clock import botanical_clock

inject(open_game(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe", 3))

# with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
#     ctler = game.controller
#     board = enter_ize(game)
#     botanical_clock(ctler, True)


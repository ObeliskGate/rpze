# -*- coding: utf_8 -*-

from src.rpze.basic.inject import InjectedGame
from src.rpze.basic.inject import enter_ize
from src.rpze.examples.botanical_clock import botanical_clock

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe", True) as game:
    ctler = game.controller
    board = enter_ize(game)
    botanical_clock(ctler, True)

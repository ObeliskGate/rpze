# -*- coding: utf_8 -*-   

from rpze import *
from rpze.basic import InjectedGame
from rpze.examples.botanical_clock import botanical_clock

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    board = game.enter_level(70)
    ctler = game.controller
    botanical_clock(ctler, False)
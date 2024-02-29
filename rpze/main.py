# -*- coding: utf_8 -*-

from src.rpze.basic.inject import *

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    ctler = game.controller
    board = enter_ize(game)
    ctler.start()
    ctler.before()
    ctler.next_frame()
    ctler.before()
    board.remove_cutscene_zombie()

# -*- coding: utf_8 -*-

from src.rpze.basic.inject import ConnectedContext, InjectedGame, enter_level
from src.rpze.examples.botanical_clock import botanical_clock
from src.rpze.iztest.operations import enter_ize

from time import sleep
from src.rpze.basic.asm import run

with InjectedGame(r"G:\pvz\en\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe", False) as game:
    # enter_ize(game.controller)
    # enter_level(game.controller, 70)
    botanical_clock(game.controller, True)
    # sleep(1)
    # with ConnectedContext(game.controller):
    #     run("push 0; ret;", game.controller)
    pass
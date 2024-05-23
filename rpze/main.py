# -*- coding: utf_8 -*-

from src.rpze.basic.inject import InjectedGame
from src.rpze.examples.botanical_clock import botanical_clock

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    botanical_clock(game.controller, jump_frame=False)

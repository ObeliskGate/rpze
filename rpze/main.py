# -*- coding: utf_8 -*-   
from src.rpze.basic.inject import *
from src.rpze.examples.botanical_clock import botanical_clock

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    game.enter_level(70)
    botanical_clock(game.controller)

# -*- coding: utf_8 -*-   
import src.rpze.basic.inject as inject
from src.rpze.examples.pole_jumping_test import pole_jumping_test
from src.rpze.examples.botanical_clock import botanical_clock

with inject.InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    game.enter_level(70)
    botanical_clock(game.controller)

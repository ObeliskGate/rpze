# -*- coding: utf_8 -*-

from src.rpze.basic.inject import InjectedGame
from src.rpze.examples.iztools_example import default_test

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    default_test(game.controller)

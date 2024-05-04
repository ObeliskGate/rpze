# -*- coding: utf_8 -*-

from src.rpze.basic.inject import InjectedGame
from src.rpze.examples.dancing_example import dancing_example

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    dancing_example(game.controller, False)

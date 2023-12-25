# -*- coding: utf_8 -*-   
from src import rpze
from src.rpze.examples.iztools_example import default_test
from src.rpze.examples.botanical_clock import botanical_clock
from src.rpze.examples.end_callback_example import end_test

with rpze.InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    board = game.enter_level(70)
    end_test(game.controller)

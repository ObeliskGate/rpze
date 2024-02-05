# -*- coding: utf_8 -*-   
from src.rpze.flow import *
from src.rpze.basic.inject import *

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    game.enter_level(70)

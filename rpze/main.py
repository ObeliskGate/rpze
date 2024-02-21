# -*- coding: utf_8 -*-   
from src.rpze.basic.inject import *
from src.rpze.examples.botanical_clock import botanical_clock
from src.rpze.flow import IzTest, FlowManager, VariablePool, AwaitableCondFunc, place
from src.rpze.structs import Plant, ProjectileType


with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    board = game.enter_level(70)
    ctler = game.controller
    ctler.start()
    ctler.before()
    ctler.next_frame()
    ctler.before()
    for p in ~board.plant_list:
        p.die()
    ctler.next_frame()
    ctler.before()
    board.plant_list.set_next_idx(10)
    board.plant_list.set_next_idx(0)
    board.plant_list.set_next_idx(6)
    ctler.end()

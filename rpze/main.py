# -*- coding: utf_8 -*-
from src.rpze.basic.inject import InjectedGame
from src.rpze.examples.dancing_example import dancing_example
from src.rpze.iztest import enter_ize
from src.rpze.structs.game_board import GameBoard

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe", False) as game:
    board = enter_ize(game.controller)
    help(GameBoard.sun_num)
    board.challenge_survival_stage = 1

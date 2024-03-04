# -*- coding: utf_8 -*-

from src.rpze.basic.inject import InjectedGame
from src.rpze.basic.inject import enter_ize
from src.rpze.examples.botanical_clock import botanical_clock

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    ctler = game.controller
    board = enter_ize(game)
    botanical_clock(ctler, True)
    # ctler.start()
    # print(board.game_time, board.mj_clock)
    # ctler.start_jump_frame()
    # print(board.game_time, board.mj_clock)
    # ctler.skip_frames()
    # print(board.game_time)
    # ctler.skip_frames(3)
    # print(board.game_time, board.mj_clock)
    # ctler.skip_frames(num=4)
    # print(board.game_time, board.plant_list.get_by_grid(1, 1))
    # print(ctler.is_jumping_frame())
    # board = enter_ize(game)
    # print(ctler.is_jumping_frame())
    # print(board.game_time)
    # ctler.end_jump_frame()
    # board = enter_ize(game)
    # print(ctler.is_jumping_frame())
    # print(board.game_time)

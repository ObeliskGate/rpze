# -*- coding: utf_8 -*-   
from src.rpze.basic.inject import *

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    board = game.enter_level(70)
    game.controller.start()
    game.controller.before()
    board.plant_list.free_all()
    h = board.iz_new_plant(0, 4, 1)
    z = board.iz_place_zombie(0, 5, 0)

    def get_coin_count():
        return game.controller.read_i32([0x6a9ec0, 0x768, 0xf4])

    print(c := get_coin_count())
    game.controller.next_frame()
    while True:
        game.controller.before()
        if c == get_coin_count() - 1:
            print(h.hp)
            c = get_coin_count()
        if h.is_dead:
            print("end", get_coin_count())
            break
        game.controller.next_frame()

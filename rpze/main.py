# -*- coding: utf_8 -*-   
from src.rpze.basic import InjectedGame
from src.rpze.examples.botanical_clock import botanical_clock
from src.rpze.structs import PlantType
import matplotlib.pyplot as plt

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    board = game.enter_level(70)
    ctler = game.controller
    botanical_clock(ctler)
    ctler.start()
    ctler.before()
    board.plant_list.free_all()
    plant = board.iz_new_plant(1, 1, PlantType.pea_shooter)
    print(plant)
    max_ = plant.max_boot_delay
    time = board.game_time
    data = []
    ctler.start_jump_frame()
    ctler.next_frame()
    print(time)
    while True:
        ctler.before()
        if board.game_time >= time + 1e7:
            if not data:
                print('start', board.game_time)
            data.append(plant.generate_cd)
            if len(data) > 1e7:
                break
        ctler.next_frame()

    n, _, _ = plt.hist(data, bins=150)
    all_ = sum(n)
    print(", ".join([f"{i + 1}: {(x / all_):.3%}" for i, x in enumerate(n)]))
    plt.show()

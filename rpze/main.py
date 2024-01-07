# -*- coding: utf_8 -*-   
from src.rpze.basic import InjectedGame
from src.rpze.examples.botanical_clock import botanical_clock
from src.rpze.examples.iztools_example import default_test

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    board = game.enter_level(70)
    ctler = game.controller
    default_test(ctler)
    # ctler.start()
    # ctler.before()
    # print(ctler.read_bytes(8, [0x6a9ec0, 0x768, 0xa8, 0x0]))
    # ctler.write_bytes(b"plants", [0x6a9ec0, 0x768, 0xa8, 0x0])
    # print(ctler.read_bytes(8, [0x6a9ec0, 0x768, 0xa8, 0x0]))
    # for _ in range(10):
    #     print(ctler.read_bytes(8, [0x6a9ec0, 0x768, 0xa8, 0x0]), ctler.read_i32([0x6a9ec0, 0x768, 0x5560]))
    # ctler.end()

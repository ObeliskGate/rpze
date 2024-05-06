# -*- coding: utf_8 -*-

from src.rpze.basic.inject import InjectedGame
from src.rpze.examples.dancing_example import dancing_example
import time


def time_test(w):
    def _wrapper(*args, **kwargs):
        start = time.time()
        for _ in range(10000000):
            w(*args, **kwargs)
        print(time.time() - start)

    return _wrapper()


with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe", False) as game:
    ctler = game.controller
    ctler.start()
    time_test(lambda: ctler.read_u32(0x6A9EC0))
    time_test(lambda: ctler.read_u32(0x6A9EC0, 0x768, 0xac))
    ctler.end()
    time_test(lambda: ctler.read_u32(0x6A9EC0))
    time_test(lambda: ctler.read_u32(0x6A9EC0, 0x768))

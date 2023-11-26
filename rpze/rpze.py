# -*- coding: utf_8 -*-   
import basic.inject as inject
from examples.iztools_example import default_test
from rp_extend import Controller, HookPosition
from tests import flow_test, basic_test

if __name__ == "__main__":
    pids = inject.open_game(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe")
    ctler = inject.inject(pids)[0]
    input("press enter to start test")
    default_test(ctler)

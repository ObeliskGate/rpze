# -*- coding: utf_8 -*-
from src.rpze.basic.inject import InjectedGame, ConnectedContext
from src.rpze.examples.botanical_clock import botanical_clock
from src.rpze.iztest import enter_ize
from src.rpze.rp_extend import SyncMethod

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    board = enter_ize(ctler := game.controller)
    print(ctler.sync_method, ctler.jumping_sync_method)
    ctler.sync_method = SyncMethod.MUTEX
    ctler.jumping_sync_method = SyncMethod.SPIN
    print(ctler.sync_method, ctler.jumping_sync_method)
    botanical_clock(ctler, jump_frame=False)

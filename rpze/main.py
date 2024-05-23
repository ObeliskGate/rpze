# -*- coding: utf_8 -*-
import time

from src.rpze.basic.inject import InjectedGame, ConnectedContext
from src.rpze.examples.botanical_clock import botanical_clock
from src.rpze.iztest import enter_ize
from src.rpze.rp_extend import SyncMethod, HookPosition

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    game.controller.open_hook(HookPosition.CHALLENGE_I_ZOMBIE_PLACE_PLANTS)
    board = enter_ize(ctler := game.controller)
    time.sleep(1)
    print(ctler.sync_method, ctler.jumping_sync_method)
    ctler.sync_method = SyncMethod.MUTEX
    ctler.jumping_sync_method = SyncMethod.SPIN
    print(ctler.sync_method, ctler.jumping_sync_method)
    botanical_clock(ctler, jump_frame=False)

# -*- coding: utf_8 -*-   
import src.rpze.basic.inject as inject
from src.rpze.flow.iztest import IzTest
from src.rpze.flow.utils import until, place, delay

with inject.InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    game.enter_level(70)
    t = IzTest(game.controller).init_by_str("""
        1000 -1
        2-0 5-0
        ..5..
        cdl_h
        .....
        ..ohp
        hsbjt
        tt
        0
        4-6""")

    @t.flow_factory.add_flow()
    async def place_zombie(_):
        plist = t.game_board.plant_list
        p1 = plist["4-4"]
        await until(lambda _: p1.hp < 300)
        place("tt 2-6")
        await delay(550)
        place("cg 5-6")

    t.start_test(jump_frame=True)

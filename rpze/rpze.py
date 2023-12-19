# -*- coding: utf_8 -*-   
import src.rpze.basic.inject as inject
from src.rpze.flow.iztest import IzTest
from src.rpze.flow.utils import until, place, delay

if __name__ == "__main__":
    pids = inject.open_game(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe")
    ctler = inject.inject(pids)[0]
    input("press enter to start test")
    t = IzTest(ctler).init_by_str("""
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
        await until(lambda _: plist["4-4"].hp < 300)
        place("tt 2-6")
        await until(lambda _: plist["4-4"].hp <= 4).after(150)
        # await delay(450)
        place("cg 5-6")

    row_five_fail_count = 0
    row_one_fail_count = 0

    @t.on_game_end()
    def end_callback(result: bool):
        if not result:
            global row_five_fail_count
            global row_one_fail_count
            plist = t.game_board.plant_list
            if plist["5-3"] is not None:
                row_five_fail_count += 1
            if plist["2-1"] is not None:
                row_one_fail_count += 1

    t.start_test(jump_frame=False)
    print(row_one_fail_count, row_five_fail_count)

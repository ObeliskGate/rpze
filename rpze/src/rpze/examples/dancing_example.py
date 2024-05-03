# -*- coding: utf_8 -*-
"""
单刀赴会 脚本示例; 女仆脚本演示
"""
from ..flow.utils import until
from ..iztest.dancing import get_dancing_manipulator, partner
from ..iztest.iztest import IzTest
from ..rp_extend import Controller
from ..structs.zombie import ZombieStatus


def dancing_example(ctler: Controller, jump_frame=True):
    iz_test = IzTest(ctler).init_by_str("""
        5 -1
        1-0 2-5 2-0
        ppo5s
        1ljys
        ...3.
        .....
        .....
        mj
        0
        1-9
        """)

    dm = get_dancing_manipulator(iz_test, "move")

    @iz_test.flow_factory.add_tick_runner()
    def extra_check_end(_):
        if iz_test.game_board.zombie_list[0].is_dead:
            return iz_test.end(False)

    @iz_test.flow_factory.add_flow()
    async def flow(_):
        board = iz_test.game_board
        mj = board.zombie_list[0]
        await until(lambda _: board.zombie_list.obj_num >= 4)
        first_front, first_back = partner(mj, "ad")

        with dm:
            await dm.until_next_phase("summon", lambda _: mj.x < 350)
            await until(lambda _: first_front.is_dead)
            while True:
                await dm.until_next_phase(
                    "move", lambda _:
                    mj.status is ZombieStatus.dancing_summoning)
                await dm.until_next_phase(
                    "summon", lambda _: mj.status is not ZombieStatus.dancing_summoning
                    or first_back.int_x < mj.int_x - 5)
                if first_back.int_x < mj.int_x - 5:
                    dm.next_phase("dance")
                    await dm.until_next_phase(
                        "move", lambda _:
                        mj.status is not ZombieStatus.dancing_summoning)
                    break
            await dm.until_next_phase(
                "summon", lambda _:
                mj.x < 205 or (not first_back.is_dead and first_back.is_eating))
            # print(first_back, first_back.int_x, mj.int_x)

            while True:
                await dm.until_next_phase(
                    "move", lambda _:
                    mj.status is ZombieStatus.dancing_summoning
                    or iz_test.ground["1-3"] is None)
                if iz_test.ground["1-3"] is None:
                    dm.next_phase("move")
                    break
                await dm.until_next_phase(
                    "summon",
                    lambda _: mj.status is not ZombieStatus.dancing_summoning)
            await dm.until_next_phase("summon", lambda _: mj.x < 120)
            await dm.until_next_phase("move", lambda _: iz_test.ground["1-1"] is None)

    @iz_test.on_game_end()
    def on_game_end(result):
        if not result:
            print(iz_test.game_board.zombie_list[0].x, iz_test.game_board.zombie_list[0].y)

    iz_test.start_test(jump_frame=jump_frame, speed_rate=2)

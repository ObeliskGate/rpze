# -*- coding: utf_8 -*-
"""
单刀赴会 脚本示例; 女仆脚本演示
"""
from ..flow.utils import until
from ..iztest.dancing import get_dancing_manipulator, partner
from ..iztest.iztest import IzTest
from ..rp_extend import Controller
from ..structs.zombie import ZombieStatus


def dancing_example(ctler: Controller, jump_frame=False):
    iz_test = IzTest(ctler).init_by_str("""
        1000 -1
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
        if iz_test.ground.zombie(0).is_dead:  # mj死亡直接判负, 以免测试卡死
            return iz_test.end(False)

    @iz_test.flow_factory.add_flow()
    async def flow(_):
        board = iz_test.game_board
        mj = iz_test.ground.zombie(0)
        await until(lambda _: board.zombie_list.obj_num >= 4)
        first_front, first_back = partner(mj, "ad")

        with dm:  # 等召唤出来开始控制
            await dm.until_next_phase("summon", lambda _: mj.x < 350)  # 走到5列开始站着召唤
            await until(lambda _: first_front.is_dead)  # 等前伴舞死后开始运后伴舞
            while True:
                await dm.until_next_phase(
                    "move", lambda _:
                    mj.status is ZombieStatus.dancing_summoning)  # 运后伴舞: 等mj召唤的时候相位切前进
                await dm.until_next_phase(
                    "summon", lambda _:
                    mj.status is not ZombieStatus.dancing_summoning  # 运后伴舞: 等mj召唤结束切回试图召唤
                    or first_back.int_x < mj.int_x - 5)  # 特判结束条件: 前伴舞走到mj前面一点的时候
                if first_back.int_x < mj.int_x - 5:
                    dm.next_phase("dance")  # 前伴舞走到mj前面一点的时候切换到跳舞, 省着走到太前面导致后续暴毙
                    await dm.until_next_phase(
                        "move", lambda _:
                        mj.status is not ZombieStatus.dancing_summoning)  # 等mj召唤结束切到走路相位
                    break
            await dm.until_next_phase(
                "summon", lambda _:
                mj.x < 205 or (not first_back.is_dead and first_back.is_eating))  # 到三列了停下来运后伴舞
            # print(first_back, first_back.int_x, mj.int_x)

            while True:
                await dm.until_next_phase(
                    "move", lambda _:
                    mj.status is ZombieStatus.dancing_summoning)
                if iz_test.ground["1-3"] is None:  # 运后伴舞, 这里要求少点等坚果死了往前走就行
                    dm.next_phase("move")
                    break
                await dm.until_next_phase(
                    "summon", lambda _:
                    mj.status is not ZombieStatus.dancing_summoning)
            await dm.until_next_phase("summon", lambda _: mj.x < 120)  # 走到二列停下来召唤吃1-1小喷
            await dm.until_next_phase("move", lambda _: iz_test.ground["1-1"] is None)  # 1-1死了收官

    @iz_test.on_game_end()
    def on_game_end(result):
        if not result:  # 过率是完爆, 死率疑似来源于后伴舞和mj一起走的时候步伐不同步导致mj被打(?
            print(iz_test.ground.zombie(0).is_dead.x, iz_test.ground.zombie(0).is_dead.y)

    iz_test.start_test(jump_frame=jump_frame, speed_rate=2)

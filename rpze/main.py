# -*- coding: utf_8 -*-
import csv

from src.rpze.basic.inject import InjectedGame
from src.rpze.basic.inject import enter_ize
from src.rpze.flow import FlowManager
from src.rpze.iztest import IzTest

with InjectedGame(r"C:\space\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe") as game:
    ctler = game.controller
    enter_ize(game)
    # botanical_clock(ctler)
    test = IzTest(ctler).init_by_str('''
        10000 -1

        1ssss
        .....
        .....
        .....
        .....
        tt
        0
        1-6''')

    data = [[], [], [], [], []]
    flags = [False, False, False, False, False]

    @test.flow_factory.add_tick_runner()
    def tr(fr: FlowManager):
        global flags
        board = test.game_board
        for idx, plant in enumerate(board.plant_list):
            if not flags[idx] and plant.is_dead:
                data[idx].append(fr.time)
                flags[idx] = True
                if idx == 0:
                    flags = [False, False, False, False, False]
                    return test.end(True)

    test.start_test(True, speed_rate=5)

    # 指定你想要创建的CSV文件的名称
    filename = r'C:\space\projects\python\time_data2.csv'

    # 使用 'w' 参数打开文件以写入，如果是在Windows上，可能还需要加上newline=''参数来避免在每行之间加入额外的空行
    with open(filename, 'w', newline='') as csvfile:
        # 创建一个csv.writer对象，用于写入数据
        csvwriter = csv.writer(csvfile)

        # 通过writerows方法写入数据
        csvwriter.writerows(data)

    print(f"数据已成功写入 {filename}")

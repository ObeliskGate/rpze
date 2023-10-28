# -*- coding: utf_8 -*- 
import msvcrt as vc
import os
import time
from rp_extend import Controller
import structs.plant as plt
import structs.zombie as zmb


def basic_test(controller: Controller):
    start_time = 0
    b = False
    start_clock = int(time.time())
    while True:
        controller.before()
        if vc.kbhit():
            c = vc.getch()
            if c == b'j':
                b = False
                start_time = controller.get_time()
                start_clock = int(time.time())
                controller.start_jump_frame()
                print(c, start_time)
            elif c == b's':
                print(controller.get_time())
            elif c == b'r':
                print("sun", controller.read_i32([0x6a9ec0, 0x768, 0x5560]))
            elif c == b'c':
                print('c')
                asm_and_plant_test(controller)
            elif c == b'q':
                print('q')
                controller.end()
                print("sun", controller.read_i32([0x6a9ec0, 0x768, 0x5560]))
                os.system("pause")
                break
            elif c == b't':
                print(c)
                zombie_list_test(controller)

        if (not b) and (controller.get_time() >= start_time + 1e6):
            controller.end_jump_frame()
            print("end", int(time.time()) - start_clock)
            b = True

        controller.next_frame()


def asm_and_plant_test(ctler):
    plist = plt.get_plant_list(ctler)
    plant = plist.plain_new_plant(1, 3, plt.PlantType.cabbagepult)
    print(plant.type_.name)
    print(plant)
    print(plant.__repr__())
    print(help(plant.launch_cd))
    for p in (p for p in plist if not p.is_dead):
        print(p)

    for p in plist.alive_iterator:
        print(p)


def zombie_list_test(ctler):
    zlist = zmb.get_zombie_list(ctler)

    print(zlist.izombie_place_zombie(0, 3, zmb.ZombieType.dancing))
    for z in zlist.alive_iterator:
        if z.type_ == zmb.ZombieType.dancing:
            for _id in z.partner_ids:
                if backup := zlist.find(_id):
                    print(backup)
                    print(zlist.find(backup.master_id) == z)

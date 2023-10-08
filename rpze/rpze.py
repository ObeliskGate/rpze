# -*- coding: utf_8 -*-   
import basic.inject as inject
import msvcrt as vc
import time
from rp_extend import Controller
import basic.asm as asm
import structs.plant as Plant
import structs.zombie as z

def izombie_place_zombie(x: int, y: int, _type: int, ctler: Controller):
    p_challenge = ctler.read_i32([0x6a9ec0, 0x768, 0x160])
    code = f'''
        push edx;
        mov eax, {y};
        push {x};
        push {_type};
        mov ecx, {p_challenge}; // 注释
        mov edx, 0x42a0f0;
        call edx;
        pop edx;
        ret;''' 
    print(code)
    asm.run(code, ctler)

    return ctler.result_i32

def basic_test(controller: Controller):
    start_time = 0
    b = False
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
                plant = Plant.normal_place_plant(3, 1, 1, controller)
                print(plant.x)
                plant.x = 400
                print(plant.SIZE)
                print(plant.x)
            elif c == b'q':
                print('q')
                controller.end()
                break
            elif c == b't':
                print(c)
        
        if (not b) and (controller.get_time() >= start_time + 1e6):
            controller.end_jump_frame()
            print("end", int(time.time()) - start_clock)
            b = True
        controller.next_frame()

if __name__ == "__main__":  
    pids = inject.open_game(r"C:\Users\32985\Desktop\pvz\Plants vs. Zombies 1.0.0.1051 EN\PlantsVsZombies.exe")
    inject.inject(pids)
    ctler = Controller(pids[0])
    basic_test(ctler)
    

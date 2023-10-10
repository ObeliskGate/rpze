import msvcrt as vc
import time
from rp_extend import Controller
import basic.asm as asm
import structs.plant as plt

def izombie_place_zombie(x: int, y: int, _type: int, ctler: Controller):
    p_challenge = ctler.read_i32([0x6a9ec0, 0x768, 0x160])
    code = f'''
        push edx;
        mov eax, {y};
        push {x};
        push {_type};
        mov ecx, {p_challenge};
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
                plant = plt.plain_new_plant(1, 3, plt.PlantType.cabbagepult, controller)
                print(plant._type.name)
                print(plant)
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
# -*- coding: utf_8 -*-   
import basic.inject as inject
import msvcrt as vc
import time
from rp_extend import Controller
import basic.asm as asm

def izombie_place_zombie(x: int, y: int, _type: int, ctl: Controller):
    p_challenge = ctl.read_i32([0x6a9ec0, 0x768, 0x160])
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
    asm.run(code, ctl)

def basic_test(controller):
    start_time = 0
    b = False
    while True:
        if controller.is_blocked():
            continue;
        if vc.kbhit():
            c = vc.getch()
            if c == b'j':
                start_time = controller.get_time()
                start_clock = int(time.time())
                controller.start_jump_frame()
                print(c, start_time)
            elif c == b's':
                print(controller.get_time())
            elif c == b'r':
                start_clock = time.time()
                print("start", start_time)
                for _ in range(1000000):
                    a = controller.read_i32([0x6a9ec0])
                    a = controller.read_i32([a + 0x768])
                    a = controller.read_i32([a + 0x5560])
                print("end", int(time.time()) - start_clock)
            elif c == b'c':
                izombie_place_zombie(6, 1, 1, controller)
        
            
        if (not b) and (controller.get_time() >= start_time + 1e6):
            controller.end_jump_frame()
            print("end", int(time.time()) - start_clock)
            b = True
        controller.next()

if __name__ == "__main__":  
    pid = inject.find_window("Plants vs. Zombies")
    inject.inject([pid], False)
    ctl = Controller(pid)
    basic_test(ctl)
    
    

# -*- coding: gbk -*- 
import inject
import rp_extend as re

if __name__ == "__main__":  
    pid = inject.find_window("Plants vs. Zombies")
    inject.inject([pid])
    controller = re.Controller(pid)
    
    i = 0
    while True:
        i += 1;
        controller.next()

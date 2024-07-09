#include "stdafx.h"
#include "rp_dll.h"
#include "dllexport.h"
#include "InsertHook.h"

volatile uint32_t initOptions = 0;

extern "C"
{
    RP_API uint32_t setEnv(uint32_t* options)
    {
        init();
        InsertHook::addInsert(reinterpret_cast<void*>(0x452650),
            [](const HookContext&)  // main loop LawnApp::UpdateFrames 
            {
                static bool flag = false; // at the first time, we need to get the mutex
                static auto pSharedMemory = SharedMemory::getInstance();
                if (!flag)
                {
                    initInThread(pSharedMemory);
                    flag = true;
                    
                }
                mainHook<0>(pSharedMemory);
            });        
        return 0;
    }
}
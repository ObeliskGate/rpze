#include "stdafx.h"
#include "rp_dll.h"
#include "dllexport.h"

volatile uint32_t initOptions = 0;

extern "C"
{
    RP_API uint32_t setEnv(uint32_t* options)
    {
        // std::cout << "setEnv in thread, options: " << *options << std::endl;
        initOptions = *options;
#ifndef NDEBUG
        std::cout << *options << "  init in thread, options: " << initOptions << std::endl;
#endif
        return 0;
    }
}
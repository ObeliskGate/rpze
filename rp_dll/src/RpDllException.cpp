#include "RpDllException.h"


RpDllException::RpDllException(const char* message) : RpDllException(message, 
    std::format("Uncaught {}, message: \n{}", typeid(*this).name(), message))
{ }
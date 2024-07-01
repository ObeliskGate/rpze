#include "RpDllException.h"


RpDllException::RpDllException(const char* message) : std::exception(message)
{ 
    auto& self = *this;
    self.messageWhenNotCaught = std::format("Uncaught {}, message: \n{}", typeid(self).name(), message);
}
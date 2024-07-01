#include "RpDllException.h"


RpDllException::RpDllException(std::string_view message) : message(message)
{ 
    auto& self = *this;
    self.messageWhenNotCaught = std::format("Uncaught {}, message: \n{}", typeid(self).name(), message);
}
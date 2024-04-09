#include "stdafx.h"
#include "MemoryException.h"

MemoryException::MemoryException(const char* message_, DWORD pid_) :
	std::exception(("pid " + std::to_string(pid_) + " " + message_).c_str()), pid(pid_) {}

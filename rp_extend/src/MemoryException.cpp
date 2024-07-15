#include "MemoryException.h"

MemoryException::MemoryException(std::string_view message_, DWORD pid_) :
	pid(pid_), message(std::format("pid {} - {}", pid_, message_)){}

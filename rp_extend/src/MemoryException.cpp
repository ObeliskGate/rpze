#include "MemoryException.h"

MemoryException::MemoryException(std::string_view message_, DWORD pid_) :
	message(std::format("pid {} - {}", pid_, message_)), pid(pid_) {}

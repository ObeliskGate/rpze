#pragma once

class MemoryException : public std::exception
{
	using std::exception::exception;
	DWORD pid;
public:
	MemoryException(const char* message_, DWORD pid_);
	DWORD processId() const { return pid; }
};

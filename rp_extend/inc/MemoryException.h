#pragma once
#include "stdafx.h"

class MemoryException : public std::exception
{
	DWORD pid;
	std::string message;
public:
	explicit MemoryException(std::string_view messageView, DWORD pid_);

	DWORD getPid() const { return pid; }
	virtual const char* what() const override { return message.c_str(); }
};

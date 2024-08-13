#pragma once
#include "stdafx.h"

class RpDllBaseException : public std::exception
{
public:
    virtual const char* whatWhenNotCaught() const = 0;
};

class RpDllException : public RpDllBaseException
{
    std::string message;
    std::string messageWhenNotCaught;
public:
    explicit RpDllException(std::string_view message_, std::string_view messageWhenNotCaught_): 
        message(message_), messageWhenNotCaught(messageWhenNotCaught_) { }

    explicit RpDllException(std::string_view message);

    virtual const char* whatWhenNotCaught() const override { return messageWhenNotCaught.c_str(); }

    virtual const char* what() const override { return message.c_str(); }
};

template <typename T>
requires std::derived_from<std::decay_t<T>, std::exception> 
    && (!std::derived_from<std::decay_t<T>, RpDllBaseException>)
std::string printStlException(const T& e)
{
    return std::format("Uncaught STL exception {}, message: \n{}", typeid(e).name(), e.what());
}
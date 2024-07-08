#pragma once
#include <concepts>
#include <exception>
#include <string>
#include <format>

class RpDllBaseException : public std::exception
{
public:
    virtual const char* whatWhenNotCaught() const = 0;
};

class RpDllException : public RpDllBaseException
{
    std::string messageWhenNotCaught;
    std::string message;
public:
    explicit RpDllException(std::string_view message, std::string_view messageWhenNotCaught): 
        message(message), messageWhenNotCaught(messageWhenNotCaught) { }

    explicit RpDllException(std::string_view message);

    virtual const char* whatWhenNotCaught() const override { return messageWhenNotCaught.c_str(); }

    virtual const char* what() const override { return message.c_str(); }
};

template <typename T>
requires std::derived_from<std::decay_t<T>, std::exception> 
    && (!std::derived_from<std::decay_t<T>, RpDllBaseException>)
std::string printStlException(T&& e)
{
    return std::format("Uncaught STL exception {}, message: \n{}", typeid(e).name(), e.what());
}
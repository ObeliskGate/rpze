#include <exception>
#include <string>
#include <format>

class RpDllException : public std::exception
{
    using std::exception::exception;
    std::string messageWhenNotCaught;
public:
    explicit RpDllException(std::string_view message, std::string_view messageWhenNotCaught): 
        std::exception(message.data()), messageWhenNotCaught(messageWhenNotCaught) { }

    explicit RpDllException(const char* message);

    virtual const char* whatWhenNotCaught() const { return messageWhenNotCaught.c_str(); }
};

template <typename T>
requires std::is_base_of_v<std::exception, std::decay_t<T>> && (!std::is_base_of_v<RpDllException, std::decay_t<T>>)
std::string printStlException(T&& e)
{
    return std::format("Uncaught STL exception {}, message: \n{}", typeid(e).name(), e.what());
}
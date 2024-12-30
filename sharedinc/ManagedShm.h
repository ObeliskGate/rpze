#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <concepts>
#include <memory>
#include <string>

namespace bi = boost::interprocess;

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

std::string toShmName(std::string_view name, std::optional<DWORD> pid = {}) {
    auto p = pid.value_or(GetCurrentProcessId());
    return std::format("__rp_dll_shared_affix_{}_{}", p, name);
}

template<typename T>
concept SharedMemoryCompatible = std::is_standard_layout_v<T> && 
                                std::is_trivially_copyable_v<T> &&
                                !std::is_pointer_v<T>;

template<SharedMemoryCompatible T>
class ManagedShm {
public:
    explicit ManagedShm(std::string_view name, bool create = true);
    ~ManagedShm();

    [[nodiscard]] T& get() noexcept { return *dataPtr; }
    [[nodiscard]] const T& get() const noexcept { return *dataPtr; }

    // Prevent copying and assignment
    ManagedShm(const ManagedShm&) = delete;
    ManagedShm& operator=(const ManagedShm&) = delete;
    // Prevent moving
    ManagedShm(ManagedShm&&) = delete;
    ManagedShm& operator=(ManagedShm&&) = delete;

private:
    void cleanup() noexcept;

    std::string shmName;
    std::unique_ptr<bi::shared_memory_object> shmObject;
    std::unique_ptr<bi::mapped_region> mappedRegion;
    T* dataPtr = nullptr;
};

// Implementation
template<SharedMemoryCompatible T>
ManagedShm<T>::ManagedShm(std::string_view name, bool create)
    : shmName(name)
{
    if (create) {
        shmObject = std::make_unique<bi::shared_memory_object>(
            bi::create_only,
            shmName.c_str(),
            bi::read_write
        );
        shmObject->truncate(sizeof(T));
    }
    else {
        shmObject = std::make_unique<bi::shared_memory_object>(
            bi::open_only,
            shmName.c_str(),
            bi::read_write
        );
    }

    mappedRegion = std::make_unique<bi::mapped_region>(
        *shmObject,
        bi::read_write
    );

    if (create) {
        dataPtr = new (mappedRegion->get_address()) T();
    } else {
        dataPtr = static_cast<T*>(mappedRegion->get_address());
    }
}

template<SharedMemoryCompatible T>
void ManagedShm<T>::cleanup() noexcept {
    if (dataPtr) {
        dataPtr->~T();
        dataPtr = nullptr;
    }

    mappedRegion.reset();
    shmObject.reset();

    bi::shared_memory_object::remove(shmName.c_str());
}

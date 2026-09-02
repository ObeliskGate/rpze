#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <type_traits>

enum class ObjType : uint16_t
{
    Plant = 0,
    Zombie,
    Projectile,
    GridItem,
};

inline constexpr size_t OBJ_TYPE_COUNT = 4;
inline constexpr size_t OBJ_UUID_SLOT_COUNT = 1024;

struct ObjTypeInfo
{
    uint32_t BOARD_ARRAY_OFFSET;
    uint32_t ITEM_SIZE;
};

inline constexpr std::array<ObjTypeInfo, OBJ_TYPE_COUNT> OBJ_TYPE_INFO{{
    {0x0AC, 0x148}, // Plant
    {0x090, 0x158}, // Zombie
    {0x0C8, 0x090}, // Projectile
    {0x11C, 0x0E8}, // GridItem
}};

constexpr size_t objTypeIndex(ObjType type) noexcept
{
    return static_cast<size_t>(type);
}

constexpr bool isValidObjType(ObjType type) noexcept
{
    return objTypeIndex(type) < OBJ_TYPE_COUNT;
}

constexpr const ObjTypeInfo& getObjTypeInfo(ObjType type) noexcept
{
    return OBJ_TYPE_INFO[objTypeIndex(type)];
}

constexpr uint32_t getObjStride(ObjType type) noexcept
{
    return getObjTypeInfo(type).ITEM_SIZE + sizeof(uint32_t);
}

union ObjUuid
{
    struct Fields
    {
        uint32_t uuidCnt;
        uint16_t index;
        ObjType type;
    } fields;

    uint64_t value;

    constexpr ObjUuid() noexcept : fields{} {}

    constexpr ObjUuid(uint32_t uuidCnt, uint16_t index, ObjType type) noexcept
        : fields{uuidCnt, index, type}
    {}

    constexpr uint64_t asValue() const noexcept
    {
        return std::bit_cast<uint64_t>(fields);
    }

    constexpr explicit operator bool() const noexcept { return fields.uuidCnt != 0; }

    constexpr bool operator==(const ObjUuid& other) const noexcept
    {
        return asValue() == other.asValue();
    }
};

struct ObjArrayMeta
{
    uint32_t dataArrayPtr;
    uint32_t blockPtr;
    uint32_t maxSize;
    uint32_t uuidCnt[OBJ_UUID_SLOT_COUNT];
};

struct ObjMeta
{
    ObjArrayMeta arrays[OBJ_TYPE_COUNT];
};

static_assert(std::is_standard_layout_v<ObjUuid::Fields>);
static_assert(sizeof(ObjUuid::Fields) == 8);
static_assert(sizeof(ObjUuid) == 8);
static_assert(offsetof(ObjUuid::Fields, uuidCnt) == 0);
static_assert(offsetof(ObjUuid::Fields, index) == 4);
static_assert(offsetof(ObjUuid::Fields, type) == 6);
static_assert(sizeof(ObjArrayMeta) == 0x100C);
static_assert(sizeof(ObjMeta) == 0x4030);

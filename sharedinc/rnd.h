#pragma once

#include "obj_uuid.h"

inline constexpr size_t RND_EXACT_CAPACITY = 1024;

enum class UuidRndHook : uint16_t
{
    ZOMBIE_JACK_COUNTDOWN = 0,
    ZOMBIE_JACK_EARLY_EXPLOSION,
    ZOMBIE_SPAWN_OTHER,
    ZOMBIE_SPAWN_POLE,
    ZOMBIE_SPAWN_ZAMBONI,
    ZOMBIE_SPAWN_CATAPULT,
    ZOMBIE_SPAWN_GARGANTUAR,
    ZOMBIE_GARLIC_DIRECTION,
    ZOMBIE_JALAPENO_COUNTDOWN,
    ZOMBIE_BUNGEE_HEIGHT,
    ZOMBIE_DANCER_SLIDE,
    ZOMBIE_YETI_ESCAPE,
    ZOMBIE_POGO_INITIAL,
    ZOMBIE_FREEZE_FIRST,
    ZOMBIE_FREEZE_REPEAT,
    PLANT_KERNEL_BUTTER,
    PLANT_BOWLING_DIRECTION,
    PLANT_PRODUCTION_INITIAL,
    PLANT_PRODUCTION_INTERVAL,
    PLANT_ATTACK_INITIAL,
    PLANT_ATTACK_INTERVAL,
    ZOMBIE_SPEED_JACK,
    ZOMBIE_SPEED_LADDER,
    ZOMBIE_SPEED_DOLPHIN,
    ZOMBIE_SPEED_NORMAL,
    TIED_ZOMBIE_WALK_ANIM,
    Count
};

enum class RndHook : uint16_t
{
    BOARD_LOOT = 0,
    BOARD_WAVE_COUNTDOWN,
    BOARD_SUN_INTERVAL,
    CHALLENGE_IZE_PLANT_REDUCTION,
    BOARD_ACTIVATION_RATIO,
    Count
};

inline constexpr size_t UUID_RND_HOOK_COUNT = static_cast<size_t>(UuidRndHook::Count);
inline constexpr size_t RND_HOOK_COUNT = static_cast<size_t>(RndHook::Count);
inline constexpr size_t RND_CONFIG_COUNT = UUID_RND_HOOK_COUNT + RND_HOOK_COUNT;

constexpr size_t rndConfigIndex(UuidRndHook hook) noexcept
{
    return static_cast<size_t>(hook);
}

constexpr size_t rndConfigIndex(RndHook hook) noexcept
{
    return UUID_RND_HOOK_COUNT + static_cast<size_t>(hook);
}

constexpr bool isValidRndHook(UuidRndHook hook) noexcept
{
    return static_cast<size_t>(hook) < UUID_RND_HOOK_COUNT;
}

constexpr bool isValidRndHook(RndHook hook) noexcept
{
    return static_cast<size_t>(hook) < RND_HOOK_COUNT;
}

enum class RndDefaultKind : uint8_t
{
    Original,
    Fixed
};

enum class RndValueKind : uint8_t
{
    I32,
    F32
};

enum class RndTarget : uint8_t
{
    Plant,
    Zombie,
    Board,
    Challenge
};

struct RndHookInfo
{
    RndValueKind valueKind;
    RndTarget target;
};

inline constexpr auto RND_HOOK_INFO = std::array{
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Plant},
    RndHookInfo{RndValueKind::I32, RndTarget::Plant},
    RndHookInfo{RndValueKind::I32, RndTarget::Plant},
    RndHookInfo{RndValueKind::I32, RndTarget::Plant},
    RndHookInfo{RndValueKind::I32, RndTarget::Plant},
    RndHookInfo{RndValueKind::I32, RndTarget::Plant},
    RndHookInfo{RndValueKind::F32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::F32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::F32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::F32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Zombie},
    RndHookInfo{RndValueKind::I32, RndTarget::Board},
    RndHookInfo{RndValueKind::I32, RndTarget::Board},
    RndHookInfo{RndValueKind::I32, RndTarget::Board},
    RndHookInfo{RndValueKind::I32, RndTarget::Challenge},
    RndHookInfo{RndValueKind::F32, RndTarget::Board}
};

static_assert(UUID_RND_HOOK_COUNT == 26 && RND_HOOK_COUNT == 5 && RND_CONFIG_COUNT == 31);
static_assert(RND_HOOK_INFO.size() == RND_CONFIG_COUNT);

union RndValue
{
    int32_t i32;
    uint32_t u32;
    float f32;
};

struct RndExactSlot
{
    ObjUuid uuid;
    RndValue value;
    UuidRndHook hook;
    uint16_t padding;
};

struct RndHookConfig
{
    uint8_t enabled;
    RndDefaultKind defaultKind;
    uint16_t padding;
    RndValue defaultValue;
};

struct RndRegion
{
    uint32_t exactCount, reserved;
    RndHookConfig configs[RND_CONFIG_COUNT];
    RndExactSlot slots[RND_EXACT_CAPACITY];
};

inline ObjUuid rndUuidSnapshot(const volatile ObjUuid& uuid) noexcept
{
    return {uuid.fields.uuidCnt, uuid.fields.index, uuid.fields.type};
}

inline size_t rndLowerBound(const volatile RndRegion& region, UuidRndHook hook,
                           const ObjUuid& uuid) noexcept
{
    size_t first = 0, count = region.exactCount;
    const auto key = uuid.asValue();
    while (count)
    {
        const size_t step = count / 2, mid = first + step;
        const auto slotHook = region.slots[mid].hook;
        if (slotHook < hook || (slotHook == hook &&
            rndUuidSnapshot(region.slots[mid].uuid).asValue() < key))
        {
            first = mid + 1;
            count -= step + 1;
        }
        else
            count = step;
    }
    return first;
}

#define RND_LAYOUT(T, SIZE) static_assert(std::is_standard_layout_v<T> && std::is_trivially_copyable_v<T> && sizeof(T) == SIZE)
RND_LAYOUT(RndValue, 4);
RND_LAYOUT(RndHookInfo, 2);
RND_LAYOUT(RndExactSlot, 16);
RND_LAYOUT(RndHookConfig, 8);
RND_LAYOUT(RndRegion, 0x4100);
#undef RND_LAYOUT

static_assert(offsetof(RndValue, i32) == 0 && offsetof(RndValue, u32) == 0 && offsetof(RndValue, f32) == 0);
static_assert(offsetof(RndHookInfo, valueKind) == 0 && offsetof(RndHookInfo, target) == 1);
static_assert(offsetof(RndExactSlot, uuid) == 0 && offsetof(RndExactSlot, value) == 8 && offsetof(RndExactSlot, hook) == 12 && offsetof(RndExactSlot, padding) == 14);
static_assert(offsetof(RndHookConfig, enabled) == 0 && offsetof(RndHookConfig, defaultKind) == 1 && offsetof(RndHookConfig, padding) == 2 && offsetof(RndHookConfig, defaultValue) == 4);
static_assert(offsetof(RndRegion, exactCount) == 0 && offsetof(RndRegion, reserved) == 4);
static_assert(offsetof(RndRegion, configs) == 0x8 && offsetof(RndRegion, slots) == 0x100);

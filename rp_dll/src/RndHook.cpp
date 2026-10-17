#include "RndHook.h"

#include "SharedMemory.h"

#include <array>

namespace
{
    uint32_t fromEbx(const HookContext& context) noexcept { return context.ebx; }
    uint32_t fromEsi(const HookContext& context) noexcept { return context.esi; }
    uint32_t fromEdi(const HookContext& context) noexcept { return context.edi; }

    struct UuidHookSpec
    {
        UuidRndHook hook;
        uintptr_t call;
        uintptr_t continueAddress;
        ObjResolver objResolver;
    };

    struct HookSpec
    {
        RndHook hook;
        uintptr_t call;
        uintptr_t continueAddress;
    };

    constexpr std::array<UuidHookSpec, 22> UUID_INTEGER_HOOKS{{
        {
            UuidRndHook::ZOMBIE_JACK_COUNTDOWN,
            0x522FD2, 0x522FD7, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_JACK_EARLY_EXPLOSION,
            0x522FE8, 0x522FED, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_SPAWN_OTHER,
            0x52259F, 0x5225A4, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_SPAWN_POLE,
            0x522CDB, 0x522CE0, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_SPAWN_ZAMBONI,
            0x522DEF, 0x522DF4, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_SPAWN_CATAPULT,
            0x522E91, 0x522E96, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_SPAWN_GARGANTUAR,
            0x523D38, 0x523D3D, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_GARLIC_DIRECTION,
            0x52B907, 0x52B90C, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_JALAPENO_COUNTDOWN,
            0x523A8B, 0x523A90, fromEsi,
        },
        {
            UuidRndHook::ZOMBIE_BUNGEE_HEIGHT,
            0x522A26, 0x522A2B, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_DANCER_SLIDE,
            0x5234FE, 0x523503, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_YETI_ESCAPE,
            0x522972, 0x522977, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_POGO_INITIAL,
            0x5232B5, 0x5232BA, fromEdi,
        },
        {
            UuidRndHook::ZOMBIE_FREEZE_FIRST,
            0x532420, 0x532425, fromEsi,
        },
        {
            UuidRndHook::ZOMBIE_FREEZE_REPEAT,
            0x53240F, 0x532414, fromEsi,
        },
        {
            UuidRndHook::PLANT_KERNEL_BUTTER,
            0x45F1E5, 0x45F1EA, fromEsi,
        },
        {
            UuidRndHook::PLANT_BOWLING_DIRECTION,
            0x4630F4, 0x4630F9, fromEdi,
        },
        {
            UuidRndHook::PLANT_PRODUCTION_INITIAL,
            0x45DED0, 0x45DED5, fromEbx,
        },
        {
            UuidRndHook::PLANT_PRODUCTION_INTERVAL,
            0x45FA91, 0x45FA96, fromEdi,
        },
        {
            UuidRndHook::PLANT_ATTACK_INITIAL,
            0x45DEE2, 0x45DEE7, fromEbx,
        },
        {
            UuidRndHook::PLANT_ATTACK_INTERVAL,
            0x45F8BA, 0x45F8BF, fromEsi,
        },
        {
            UuidRndHook::TIED_ZOMBIE_WALK_ANIM,
            0x52F3D4, 0x52F3D9, fromEdi,
        },
    }};

    constexpr std::array<UuidHookSpec, 4> UUID_FLOAT_HOOKS{{
        {
            UuidRndHook::ZOMBIE_SPEED_JACK,
            0x524C3D, 0x524C42, fromEsi,
        },
        {
            UuidRndHook::ZOMBIE_SPEED_LADDER,
            0x524C14, 0x524C19, fromEsi,
        },
        {
            UuidRndHook::ZOMBIE_SPEED_DOLPHIN,
            0x524BEB, 0x524BF0, fromEsi,
        },
        {
            UuidRndHook::ZOMBIE_SPEED_NORMAL,
            0x524B97, 0x524B9C, fromEsi,
        }
    }};

    constexpr std::array<HookSpec, 5> INTEGER_HOOKS{{
        {
            RndHook::BOARD_LOOT,
            0x41CEA8, 0x41CEAD,
        },
        {
            RndHook::BOARD_WAVE_COUNTDOWN,
            0x4140C4, 0x4140C9,
        },
        {
            RndHook::BOARD_SUN_INTERVAL,
            0x413BBE, 0x413BC3,
        },
        {
            RndHook::CHALLENGE_IZE_PLANT_REDUCTION,
            0x42AFA6, 0x42AFAB,
        },
        {
            RndHook::CHALLENGE_IZE_PLANT_REDUCTION,
            0x42B019, 0x42B01E,
        }
    }};

    constexpr std::array<HookSpec, 1> FLOAT_HOOKS{{
        {
            RndHook::BOARD_ACTIVATION_RATIO,
            0x414087, 0x41408C,
        }
    }};

    static_assert(UUID_INTEGER_HOOKS.size() == 22);
    static_assert(INTEGER_HOOKS.size() == 5);
    static_assert(UUID_FLOAT_HOOKS.size() == 4);
    static_assert(FLOAT_HOOKS.size() == 1);
    static_assert(UUID_INTEGER_HOOKS.size() + INTEGER_HOOKS.size() == 27);
    static_assert(UUID_FLOAT_HOOKS.size() + FLOAT_HOOKS.size() == 5);
    static_assert(RND_CONFIG_COUNT == 31);

    std::optional<ObjType> objectType(RndTarget target) noexcept
    {
        switch (target)
        {
        case RndTarget::Plant: return ObjType::Plant;
        case RndTarget::Zombie: return ObjType::Zombie;
        case RndTarget::Board:
        case RndTarget::Challenge: return {};
        }
        return {};
    }

    std::optional<ObjUuid> resolveUuid(const Shm& shm, ObjType type,
        uint32_t objectPtr) noexcept
    {
        if (objectPtr == 0)
            return {};

        const auto& meta = shm.objMeta.arrays[objTypeIndex(type)];
        if (meta.blockPtr == 0 || objectPtr < meta.blockPtr)
            return {};

        const auto stride = getObjStride(type);
        const auto delta = objectPtr - meta.blockPtr;
        if (stride == 0 || delta % stride != 0)
            return {};

        const auto index = delta / stride;
        const auto limit = std::min(meta.maxSize,
            static_cast<uint32_t>(OBJ_UUID_SLOT_COUNT));
        if (index >= limit)
            return {};

        const auto uuidCnt = meta.uuidCnt[index];
        if (uuidCnt == 0)
            return {};

        return ObjUuid{uuidCnt, static_cast<uint16_t>(index), type};
    }

    std::optional<uint32_t> defaultBits(
        const volatile RndHookConfig& config) noexcept
    {
        if (config.defaultKind != RndDefaultKind::Fixed)
            return {};
        return config.defaultValue.u32;
    }
}

std::optional<uint32_t> rndQueryBits(UuidRndHook hook, const HookContext& context,
    ObjResolver objResolver)
{
    if (!isValidRndHook(hook))
        return {};
    const auto hookIndex = rndConfigIndex(hook);

    auto& shm = SharedMemory::getInstance()->shm();
    if (shm.globalState == HookState::NOT_CONNECTED)
        return {};

    volatile auto& region = shm.rnd;
    volatile auto& config = region.configs[hookIndex];
    // Keep the disabled path free of object metadata and exact-table reads.
    if (!config.enabled)
        return {};

    const auto target = RND_HOOK_INFO[hookIndex].target;
    const auto type = objectType(target);
    if (!type)
        return defaultBits(config);

    const auto uuid = resolveUuid(shm, *type, objResolver(context));
    if (!uuid)
        return defaultBits(config);

    const auto exactCount = region.exactCount;
    if (exactCount > RND_EXACT_CAPACITY)
        return defaultBits(config);

    const auto position = rndLowerBound(region, hook, *uuid);
    if (position < exactCount)
    {
        const auto& slot = region.slots[position];
        if (slot.hook == hook &&
            rndUuidSnapshot(slot.uuid).asValue() == uuid->asValue())
            return slot.value.u32;
    }
    return defaultBits(config);
}

std::optional<uint32_t> rndQueryBits(RndHook hook)
{
    if (!isValidRndHook(hook))
        return {};

    auto& shm = SharedMemory::getInstance()->shm();
    if (shm.globalState == HookState::NOT_CONNECTED)
        return {};

    volatile auto& config = shm.rnd.configs[rndConfigIndex(hook)];
    if (!config.enabled)
        return {};
    return defaultBits(config);
}

void resetRndForBoard()
{
    auto& region = SharedMemory::getInstance()->shm().rnd;
    for (size_t i = 0; i < RND_CONFIG_COUNT; ++i)
    {
        auto& config = region.configs[i];
        config.enabled = 0;
        config.defaultKind = RndDefaultKind::Original;
        config.padding = 0;
        config.defaultValue.u32 = 0;
    }
    region.exactCount = 0;
}

void initializeRndHooks()
{
    for (const auto& spec : UUID_INTEGER_HOOKS)
    {
        const auto hook = spec.hook;
        const auto objResolver = spec.objResolver;
        InsertHook::addReplace(
            reinterpret_cast<void*>(spec.call),
            reinterpret_cast<void*>(spec.continueAddress),
            [hook, objResolver](const HookContext& context) -> std::optional<uint32_t>
            {
                return rndQueryBits(hook, context, objResolver);
            });
    }

    for (const auto& spec : INTEGER_HOOKS)
    {
        const auto hook = spec.hook;
        InsertHook::addReplace(
            reinterpret_cast<void*>(spec.call),
            reinterpret_cast<void*>(spec.continueAddress),
            [hook](const HookContext&) -> std::optional<uint32_t>
            {
                return rndQueryBits(hook);
            });
    }

    for (const auto& spec : UUID_FLOAT_HOOKS)
    {
        const auto hook = spec.hook;
        const auto objResolver = spec.objResolver;
        InsertHook::addFloatReplace(
            reinterpret_cast<void*>(spec.call),
            reinterpret_cast<void*>(spec.continueAddress),
            [hook, objResolver](const HookContext& context) -> std::optional<uint32_t>
            {
                return rndQueryBits(hook, context, objResolver);
            });
    }

    for (const auto& spec : FLOAT_HOOKS)
    {
        const auto hook = spec.hook;
        InsertHook::addFloatReplace(
            reinterpret_cast<void*>(spec.call),
            reinterpret_cast<void*>(spec.continueAddress),
            [hook](const HookContext&) -> std::optional<uint32_t>
            {
                return rndQueryBits(hook);
            });
    }
}

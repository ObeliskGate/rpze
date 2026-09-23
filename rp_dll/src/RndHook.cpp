#include "RndHook.h"

#include "SharedMemory.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>

namespace
{
    uint32_t fromEbx(const HookContext& context) noexcept { return context.ebx; }
    uint32_t fromEsi(const HookContext& context) noexcept { return context.esi; }
    uint32_t fromEdi(const HookContext& context) noexcept { return context.edi; }

    struct IntegerHookSpec
    {
        RndHook hook;
        std::string_view name;
        uintptr_t call;
        uintptr_t continueAddress;
        ObjResolver objResolver;
        std::array<uint8_t, 5> signature;
    };

    struct FloatHookSpec
    {
        RndHook hook;
        std::string_view name;
        uintptr_t signatureAddress;
        uintptr_t call;
        uintptr_t continueAddress;
        ObjResolver objResolver;
        std::array<uint8_t, 27> signature;
    };

    constexpr std::array<IntegerHookSpec, 26> INTEGER_HOOKS{{
        {
            RndHook::ZOMBIE_JACK_COUNTDOWN, "ZOMBIE_JACK_COUNTDOWN",
            0x522FD2, 0x522FD7, fromEdi,
            {0xE8, 0x29, 0xC4, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_JACK_EARLY_EXPLOSION, "ZOMBIE_JACK_EARLY_EXPLOSION",
            0x522FE8, 0x522FED, fromEdi,
            {0xE8, 0x13, 0xC4, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_SPAWN_OTHER, "ZOMBIE_SPAWN_OTHER",
            0x52259F, 0x5225A4, fromEdi,
            {0xE8, 0x5C, 0xCE, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_SPAWN_POLE, "ZOMBIE_SPAWN_POLE",
            0x522CDB, 0x522CE0, fromEdi,
            {0xE8, 0x20, 0xC7, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_SPAWN_ZAMBONI, "ZOMBIE_SPAWN_ZAMBONI",
            0x522DEF, 0x522DF4, fromEdi,
            {0xE8, 0x0C, 0xC6, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_SPAWN_CATAPULT, "ZOMBIE_SPAWN_CATAPULT",
            0x522E91, 0x522E96, fromEdi,
            {0xE8, 0x6A, 0xC5, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_SPAWN_GARGANTUAR, "ZOMBIE_SPAWN_GARGANTUAR",
            0x523D38, 0x523D3D, fromEdi,
            {0xE8, 0xC3, 0xB6, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_GARLIC_DIRECTION, "ZOMBIE_GARLIC_DIRECTION",
            0x52B907, 0x52B90C, fromEdi,
            {0xE8, 0xF4, 0x3A, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_JALAPENO_COUNTDOWN, "ZOMBIE_JALAPENO_COUNTDOWN",
            0x523A8B, 0x523A90, fromEsi,
            {0xE8, 0x70, 0xB9, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_BUNGEE_HEIGHT, "ZOMBIE_BUNGEE_HEIGHT",
            0x522A26, 0x522A2B, fromEdi,
            {0xE8, 0xD5, 0xC9, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_DANCER_SLIDE, "ZOMBIE_DANCER_SLIDE",
            0x5234FE, 0x523503, fromEdi,
            {0xE8, 0xFD, 0xBE, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_YETI_ESCAPE, "ZOMBIE_YETI_ESCAPE",
            0x522972, 0x522977, fromEdi,
            {0xE8, 0x89, 0xCA, 0x08, 0x00}
        },
        {
            RndHook::ZOMBIE_POGO_INITIAL, "ZOMBIE_POGO_INITIAL",
            0x5232B5, 0x5232BA, fromEdi,
            {0xE8, 0x46, 0xC1, 0x08, 0x00}
        },
        {
            RndHook::BOARD_LOOT, "BOARD_LOOT",
            0x41CEA8, 0x41CEAD, nullptr,
            {0xE8, 0x53, 0x25, 0x19, 0x00}
        },
        {
            RndHook::ZOMBIE_FREEZE_FIRST, "ZOMBIE_FREEZE_FIRST",
            0x532420, 0x532425, fromEsi,
            {0xE8, 0xDB, 0xCF, 0x07, 0x00}
        },
        {
            RndHook::ZOMBIE_FREEZE_REPEAT, "ZOMBIE_FREEZE_REPEAT",
            0x53240F, 0x532414, fromEsi,
            {0xE8, 0xEC, 0xCF, 0x07, 0x00}
        },
        {
            RndHook::BOARD_WAVE_COUNTDOWN, "BOARD_WAVE_COUNTDOWN",
            0x4140C4, 0x4140C9, nullptr,
            {0xE8, 0x37, 0xB3, 0x19, 0x00}
        },
        {
            RndHook::BOARD_SUN_INTERVAL, "BOARD_SUN_INTERVAL",
            0x413BBE, 0x413BC3, nullptr,
            {0xE8, 0x3D, 0xB8, 0x19, 0x00}
        },
        {
            RndHook::PLANT_KERNEL_BUTTER, "PLANT_KERNEL_BUTTER",
            0x45F1E5, 0x45F1EA, fromEsi,
            {0xE8, 0x16, 0x02, 0x15, 0x00}
        },
        {
            RndHook::PLANT_BOWLING_DIRECTION, "PLANT_BOWLING_DIRECTION",
            0x4630F4, 0x4630F9, fromEdi,
            {0xE8, 0x07, 0xC3, 0x14, 0x00}
        },
        {
            RndHook::PLANT_PRODUCTION_INITIAL, "PLANT_PRODUCTION_INITIAL",
            0x45DED0, 0x45DED5, fromEbx,
            {0xE8, 0x2B, 0x15, 0x15, 0x00}
        },
        {
            RndHook::PLANT_PRODUCTION_INTERVAL, "PLANT_PRODUCTION_INTERVAL",
            0x45FA91, 0x45FA96, fromEdi,
            {0xE8, 0x6A, 0xF9, 0x14, 0x00}
        },
        {
            RndHook::PLANT_ATTACK_INITIAL, "PLANT_ATTACK_INITIAL",
            0x45DEE2, 0x45DEE7, fromEbx,
            {0xE8, 0x19, 0x15, 0x15, 0x00}
        },
        {
            RndHook::PLANT_ATTACK_INTERVAL, "PLANT_ATTACK_INTERVAL",
            0x45F8BA, 0x45F8BF, fromEsi,
            {0xE8, 0x41, 0xFB, 0x14, 0x00}
        },
        {
            RndHook::CHALLENGE_IZE_PLANT_REDUCTION, "CHALLENGE_IZE_PLANT_REDUCTION",
            0x42AFA6, 0x42AFAB, nullptr,
            {0xE8, 0x55, 0x44, 0x18, 0x00}
        },
        {
            RndHook::CHALLENGE_IZE_PLANT_REDUCTION, "CHALLENGE_IZE_PLANT_REDUCTION",
            0x42B019, 0x42B01E, nullptr,
            {0xE8, 0xE2, 0x43, 0x18, 0x00}
        }
    }};

    constexpr std::array<FloatHookSpec, 5> FLOAT_HOOKS{{
        {
            RndHook::BOARD_ACTIVATION_RATIO, "BOARD_ACTIVATION_RATIO",
            0x414071, 0x414087, 0x41408C, nullptr,
            {
                0xD9, 0x05, 0x24, 0x54, 0x66, 0x00, 0x83, 0xEC, 0x08,
                0xD9, 0x5C, 0x24, 0x04, 0xD9, 0x05, 0xC0, 0x93, 0x67,
                0x00, 0xD9, 0x1C, 0x24, 0xE8, 0x24, 0xDC, 0x0F, 0x00
            }
        },
        {
            RndHook::ZOMBIE_SPEED_JACK, "ZOMBIE_SPEED_JACK",
            0x524C27, 0x524C3D, 0x524C42, fromEsi,
            {
                0xD9, 0x05, 0x44, 0x96, 0x67, 0x00, 0x83, 0xEC, 0x08,
                0xD9, 0x5C, 0x24, 0x04, 0xD9, 0x05, 0x40, 0x96, 0x67,
                0x00, 0xD9, 0x1C, 0x24, 0xE8, 0x6E, 0xD0, 0xFE, 0xFF
            }
        },
        {
            RndHook::ZOMBIE_SPEED_LADDER, "ZOMBIE_SPEED_LADDER",
            0x524BFE, 0x524C14, 0x524C19, fromEsi,
            {
                0xD9, 0x05, 0x4C, 0x96, 0x67, 0x00, 0x83, 0xEC, 0x08,
                0xD9, 0x5C, 0x24, 0x04, 0xD9, 0x05, 0x48, 0x96, 0x67,
                0x00, 0xD9, 0x1C, 0x24, 0xE8, 0x97, 0xD0, 0xFE, 0xFF
            }
        },
        {
            RndHook::ZOMBIE_SPEED_DOLPHIN, "ZOMBIE_SPEED_DOLPHIN",
            0x524BD5, 0x524BEB, 0x524BF0, fromEsi,
            {
                0xD9, 0x05, 0x54, 0x96, 0x67, 0x00, 0x83, 0xEC, 0x08,
                0xD9, 0x5C, 0x24, 0x04, 0xD9, 0x05, 0x50, 0x96, 0x67,
                0x00, 0xD9, 0x1C, 0x24, 0xE8, 0xC0, 0xD0, 0xFE, 0xFF
            }
        },
        {
            RndHook::ZOMBIE_SPEED_NORMAL, "ZOMBIE_SPEED_NORMAL",
            0x524B81, 0x524B97, 0x524B9C, fromEsi,
            {
                0xD9, 0x05, 0x60, 0x96, 0x67, 0x00, 0x83, 0xEC, 0x08,
                0xD9, 0x5C, 0x24, 0x04, 0xD9, 0x05, 0x70, 0x96, 0x67,
                0x00, 0xD9, 0x1C, 0x24, 0xE8, 0x14, 0xD1, 0xFE, 0xFF
            }
        }
    }};

    constexpr uintptr_t INTEGER_TARGET = 0x5AF400;
    constexpr uintptr_t FLOAT_TARGET = 0x511CB0;

    static_assert(INTEGER_HOOKS.size() == 26);
    static_assert(FLOAT_HOOKS.size() == 5);
    static_assert(RND_HOOK_COUNT == 30);

    [[noreturn]] void fatalRnd(std::string_view hookName, uintptr_t address,
        std::string_view reason)
    {
        std::fprintf(stderr, "RND hook %.*s at 0x%08lX: %.*s\n",
            static_cast<int>(hookName.size()), hookName.data(),
            static_cast<unsigned long>(address),
            static_cast<int>(reason.size()), reason.data());
        std::fflush(stderr);
        TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
        std::abort();
    }

    std::string signatureText(const uint8_t* bytes, size_t size)
    {
        std::string text;
        for (size_t i = 0; i < size; ++i)
        {
            if (i != 0)
                text.push_back(' ');
            text += std::format("{:02X}", bytes[i]);
        }
        return text;
    }

    int32_t decodeRel32(const uint8_t* bytes) noexcept
    {
        const auto value = static_cast<uint32_t>(bytes[0]) |
            (static_cast<uint32_t>(bytes[1]) << 8) |
            (static_cast<uint32_t>(bytes[2]) << 16) |
            (static_cast<uint32_t>(bytes[3]) << 24);
        return static_cast<int32_t>(value);
    }

    uintptr_t rel32Target(uintptr_t nextInstruction,
        const uint8_t* relativeBytes) noexcept
    {
        return static_cast<uintptr_t>(
            static_cast<intptr_t>(nextInstruction) +
            static_cast<intptr_t>(decodeRel32(relativeBytes)));
    }

    template <size_t N>
    void verifySignature(std::string_view hookName, uintptr_t address,
        const std::array<uint8_t, N>& expected,
        std::array<uint8_t, N>& actual)
    {
        std::memcpy(actual.data(), reinterpret_cast<const void*>(address), actual.size());
        if (actual == expected)
            return;

        const auto reason = std::format("signature mismatch; expected {} actual {}",
            signatureText(expected.data(), expected.size()),
            signatureText(actual.data(), actual.size()));
        fatalRnd(hookName, address, reason);
    }

    void verifyIntegerSignature(const IntegerHookSpec& spec)
    {
        std::array<uint8_t, 5> actual{};
        verifySignature(spec.name, spec.call, spec.signature, actual);
        const auto target = rel32Target(spec.call + spec.signature.size(),
            actual.data() + 1);
        if (target != INTEGER_TARGET)
        {
            fatalRnd(spec.name, spec.call,
                std::format("CALL target mismatch; expected 0x{:08X} actual 0x{:08X}",
                    static_cast<unsigned int>(INTEGER_TARGET),
                    static_cast<unsigned int>(target)));
        }
    }

    void verifyFloatSignature(const FloatHookSpec& spec)
    {
        std::array<uint8_t, 27> actual{};
        verifySignature(spec.name, spec.signatureAddress, spec.signature, actual);
        const auto callOffset = spec.call - spec.signatureAddress;
        const auto target = rel32Target(spec.call + 5,
            actual.data() + static_cast<size_t>(callOffset) + 1);
        if (target != FLOAT_TARGET)
        {
            fatalRnd(spec.name, spec.call,
                std::format("CALL target mismatch; expected 0x{:08X} actual 0x{:08X}",
                    static_cast<unsigned int>(FLOAT_TARGET),
                    static_cast<unsigned int>(target)));
        }
    }

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

    template <typename Install>
    void installOrFatal(std::string_view hookName, uintptr_t address,
        Install&& install)
    {
        try
        {
            install();
        }
        catch (const std::exception& error)
        {
            fatalRnd(hookName, address,
                std::format("installation failed status=exception: {}", error.what()));
        }
        catch (...)
        {
            fatalRnd(hookName, address,
                "installation failed status=unknown");
        }
    }
}

std::optional<uint32_t> rndQueryBits(RndHook hook, const HookContext& context,
    ObjResolver objResolver)
{
    const auto hookIndex = static_cast<size_t>(hook);
    if (hookIndex >= RND_HOOK_COUNT)
        return {};

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
    if (!type || !objResolver)
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

void resetRndForBoard()
{
    auto& region = SharedMemory::getInstance()->shm().rnd;
    for (size_t i = 0; i < RND_HOOK_COUNT; ++i)
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
    // Verify every pending CALL before installing the first RND hook.
    for (const auto& spec : INTEGER_HOOKS)
        verifyIntegerSignature(spec);
    for (const auto& spec : FLOAT_HOOKS)
        verifyFloatSignature(spec);

    for (const auto& spec : INTEGER_HOOKS)
    {
        const auto hook = spec.hook;
        const auto call = spec.call;
        const auto continueAddress = spec.continueAddress;
        const auto objResolver = spec.objResolver;
        installOrFatal(spec.name, call, [call, continueAddress, hook, objResolver]
        {
            InsertHook::addReplace(
                reinterpret_cast<void*>(call),
                reinterpret_cast<void*>(continueAddress),
                [hook, objResolver](const HookContext& context) -> std::optional<uint32_t>
                {
                    return rndQueryBits(hook, context, objResolver);
                });
        });
    }

    for (const auto& spec : FLOAT_HOOKS)
    {
        const auto hook = spec.hook;
        const auto call = spec.call;
        const auto continueAddress = spec.continueAddress;
        const auto objResolver = spec.objResolver;
        installOrFatal(spec.name, call, [call, continueAddress, hook, objResolver]
        {
            InsertHook::addFloatReplace(
                reinterpret_cast<void*>(call),
                reinterpret_cast<void*>(continueAddress),
                [hook, objResolver](const HookContext& context) -> std::optional<uint32_t>
                {
                    return rndQueryBits(hook, context, objResolver);
                });
        });
    }
}

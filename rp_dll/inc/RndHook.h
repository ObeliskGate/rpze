#pragma once

#include "InsertHook.h"
#include "rnd.h"

using ObjResolver = uint32_t (*)(const HookContext&) noexcept;

// Resolve the object only for enabled UUID hooks.
std::optional<uint32_t> rndQueryBits(UuidRndHook hook, const HookContext& context,
    ObjResolver objResolver);
std::optional<uint32_t> rndQueryBits(RndHook hook);

// Install the complete RND hook registry.
void initializeRndHooks();

// Clear all per-board RND configuration and exact-entry state.
void resetRndForBoard();

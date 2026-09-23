#pragma once

#include "InsertHook.h"
#include "rnd.h"

using ObjResolver = uint32_t (*)(const HookContext&) noexcept;

// Resolve the object only for enabled object hooks; nullptr denotes a global hook.
std::optional<uint32_t> rndQueryBits(RndHook hook, const HookContext& context,
    ObjResolver objResolver);

// Install the complete RND hook registry after all signatures have been verified.
void initializeRndHooks();

// Clear all per-board RND configuration and exact-entry state.
void resetRndForBoard();

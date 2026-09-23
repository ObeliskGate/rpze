#include "Memory.h"

#include <cstring>

namespace
{
	size_t checkedRndHookIndex(RndHook hook, DWORD pid)
	{
		const auto index = static_cast<size_t>(hook);
		if (index >= RND_HOOK_COUNT)
			throw MemoryException("rnd: invalid hook", pid);
		return index;
	}

	bool hasRndExact(const volatile RndRegion& region, RndHook hook) noexcept
	{
		const auto first = rndLowerBound(region, hook, ObjUuid{});
		return first < region.exactCount && region.slots[first].hook == hook;
	}

	bool matchesRndSlot(const volatile RndExactSlot& slot, RndHook hook,
		const ObjUuid& uuid) noexcept
	{
		return slot.hook == hook &&
			rndUuidSnapshot(slot.uuid).asValue() == uuid.asValue();
	}

	void resetRndConfig(volatile RndHookConfig& config) noexcept
	{
		config.enabled = 0;
		config.defaultKind = RndDefaultKind::Original;
		config.padding = 0;
		config.defaultValue.u32 = 0;
	}
}

volatile RndRegion& Memory::checkedRnd() const
{
	if (!isShmPrepared())
		throw MemoryException("rnd: main loop not prepared", pid);

	auto& region = shm().rnd;
	if (region.exactCount > RND_EXACT_CAPACITY)
		throw MemoryException("rnd: exact table count out of range", pid);
	return region;
}

void Memory::rndSet(RndHook hook, const ObjUuid& uuid, uint32_t bits)
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	const auto exactCount = static_cast<size_t>(region.exactCount);
	const auto position = rndLowerBound(region, hook, uuid);
	auto* slots = const_cast<RndExactSlot*>(region.slots);

	if (position < exactCount && matchesRndSlot(region.slots[position], hook, uuid))
	{
		region.slots[position].value.u32 = bits;
	}
	else
	{
		if (exactCount == RND_EXACT_CAPACITY)
			throw MemoryException("rnd: exact table is full", pid);
		std::memmove(slots + position + 1, slots + position,
			(exactCount - position) * sizeof(RndExactSlot));
		region.slots[position].uuid.fields.uuidCnt = uuid.fields.uuidCnt;
		region.slots[position].uuid.fields.index = uuid.fields.index;
		region.slots[position].uuid.fields.type = uuid.fields.type;
		region.slots[position].value.u32 = bits;
		region.slots[position].hook = hook;
		region.slots[position].padding = 0;
		region.exactCount = static_cast<uint32_t>(exactCount + 1);
	}

	region.configs[hookIndex].enabled = 1;
}

std::optional<uint32_t> Memory::rndGet(RndHook hook, const ObjUuid& uuid) const
{
	auto& region = checkedRnd();
	checkedRndHookIndex(hook, pid);
	const auto position = rndLowerBound(region, hook, uuid);
	if (position >= region.exactCount || !matchesRndSlot(region.slots[position], hook, uuid))
		return std::nullopt;
	return region.slots[position].value.u32;
}

bool Memory::rndRemove(RndHook hook, const ObjUuid& uuid)
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	const auto exactCount = static_cast<size_t>(region.exactCount);
	const auto position = rndLowerBound(region, hook, uuid);
	if (position >= exactCount || !matchesRndSlot(region.slots[position], hook, uuid))
		return false;

	auto* slots = const_cast<RndExactSlot*>(region.slots);
	std::memmove(slots + position, slots + position + 1,
		(exactCount - position - 1) * sizeof(RndExactSlot));
	region.exactCount = static_cast<uint32_t>(exactCount - 1);

	region.configs[hookIndex].enabled = static_cast<uint8_t>(
		hasRndExact(region, hook) || region.configs[hookIndex].defaultKind == RndDefaultKind::Fixed);
	return true;
}

void Memory::rndSetDefault(RndHook hook, std::optional<uint32_t> bits)
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	auto& config = region.configs[hookIndex];
	config.defaultKind = bits.has_value() ? RndDefaultKind::Fixed : RndDefaultKind::Original;
	config.padding = 0;
	config.defaultValue.u32 = bits.value_or(0);
	config.enabled = static_cast<uint8_t>(bits.has_value() || hasRndExact(region, hook));
}

std::optional<uint32_t> Memory::rndGetDefault(RndHook hook) const
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	const auto& config = region.configs[hookIndex];
	if (config.defaultKind != RndDefaultKind::Fixed)
		return std::nullopt;
	return config.defaultValue.u32;
}

bool Memory::rndEnabled(RndHook hook) const
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	return region.configs[hookIndex].enabled != 0;
}

void Memory::rndClear(std::optional<RndHook> hook)
{
	auto& region = checkedRnd();
	auto* slots = const_cast<RndExactSlot*>(region.slots);
	const auto exactCount = static_cast<size_t>(region.exactCount);

	if (!hook.has_value())
	{
		for (size_t index = 0; index < RND_HOOK_COUNT; ++index)
			region.configs[index].enabled = 0;
		for (size_t index = 0; index < RND_HOOK_COUNT; ++index)
			resetRndConfig(region.configs[index]);
		region.exactCount = 0;
		return;
	}

	const auto selected = *hook;
	const auto hookIndex = checkedRndHookIndex(selected, pid);
	region.configs[hookIndex].enabled = 0;

	const auto first = rndLowerBound(region, selected, ObjUuid{});
	size_t last = first;
	while (last < exactCount && region.slots[last].hook == selected)
		++last;
	if (last != first)
	{
		std::memmove(slots + first, slots + last,
			(exactCount - last) * sizeof(RndExactSlot));
		region.exactCount = static_cast<uint32_t>(exactCount - (last - first));
	}

	resetRndConfig(region.configs[hookIndex]);
}

#include "Memory.h"

#include <cstring>

namespace
{
	size_t checkedRndHookIndex(UuidRndHook hook, DWORD pid)
	{
		if (!isValidRndHook(hook))
			throw MemoryException("rnd: invalid hook", pid);
		return rndConfigIndex(hook);
	}

	size_t checkedRndHookIndex(RndHook hook, DWORD pid)
	{
		if (!isValidRndHook(hook))
			throw MemoryException("rnd: invalid hook", pid);
		return rndConfigIndex(hook);
	}

	std::pair<size_t, size_t> rndExactRange(
		const volatile RndRegion& region, UuidRndHook hook) noexcept
	{
		const auto first = rndLowerBound(region, hook, ObjUuid{});
		const auto exactCount = static_cast<size_t>(region.exactCount);
		size_t last = first;
		while (last < exactCount && region.slots[last].hook == hook)
			++last;
		return { first, last };
	}

	bool hasRndExact(const volatile RndRegion& region, UuidRndHook hook) noexcept
	{
		const auto first = rndLowerBound(region, hook, ObjUuid{});
		return first < region.exactCount && region.slots[first].hook == hook;
	}

	bool matchesRndSlot(const volatile RndExactSlot& slot, UuidRndHook hook,
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

void Memory::rndUuidSet(UuidRndHook hook, const ObjUuid& uuid, uint32_t bits)
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

std::optional<uint32_t> Memory::rndUuidGet(UuidRndHook hook, const ObjUuid& uuid) const
{
	auto& region = checkedRnd();
	checkedRndHookIndex(hook, pid);
	const auto position = rndLowerBound(region, hook, uuid);
	if (position >= region.exactCount || !matchesRndSlot(region.slots[position], hook, uuid))
		return std::nullopt;
	return region.slots[position].value.u32;
}

bool Memory::rndUuidRemove(UuidRndHook hook, const ObjUuid& uuid)
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

std::vector<ObjUuid> Memory::rndUuidKeys(UuidRndHook hook) const
{
	auto& region = checkedRnd();
	checkedRndHookIndex(hook, pid);
	const auto [first, last] = rndExactRange(region, hook);
	std::vector<ObjUuid> keys;
	keys.reserve(last - first);
	for (size_t index = first; index < last; ++index)
		keys.push_back(rndUuidSnapshot(region.slots[index].uuid));
	return keys;
}

size_t Memory::rndUuidCount(UuidRndHook hook) const
{
	auto& region = checkedRnd();
	checkedRndHookIndex(hook, pid);
	const auto [first, last] = rndExactRange(region, hook);
	return last - first;
}

void Memory::rndUuidClear(UuidRndHook hook)
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	const auto [first, last] = rndExactRange(region, hook);
	if (last != first)
	{
		const auto exactCount = static_cast<size_t>(region.exactCount);
		auto* slots = const_cast<RndExactSlot*>(region.slots);
		std::memmove(slots + first, slots + last,
			(exactCount - last) * sizeof(RndExactSlot));
		region.exactCount = static_cast<uint32_t>(exactCount - (last - first));
	}
	region.configs[hookIndex].enabled = static_cast<uint8_t>(
		region.configs[hookIndex].defaultKind == RndDefaultKind::Fixed);
}

void Memory::rndUuidSetDefault(UuidRndHook hook, std::optional<uint32_t> bits)
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	auto& config = region.configs[hookIndex];
	config.defaultKind = bits.has_value() ? RndDefaultKind::Fixed : RndDefaultKind::Original;
	config.padding = 0;
	config.defaultValue.u32 = bits.value_or(0);
	config.enabled = static_cast<uint8_t>(bits.has_value() || hasRndExact(region, hook));
}

std::optional<uint32_t> Memory::rndUuidGetDefault(UuidRndHook hook) const
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	const auto& config = region.configs[hookIndex];
	if (config.defaultKind != RndDefaultKind::Fixed)
		return std::nullopt;
	return config.defaultValue.u32;
}

void Memory::rndSet(RndHook hook, std::optional<uint32_t> bits)
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	auto& config = region.configs[hookIndex];
	config.defaultKind = bits.has_value() ? RndDefaultKind::Fixed : RndDefaultKind::Original;
	config.padding = 0;
	config.defaultValue.u32 = bits.value_or(0);
	config.enabled = static_cast<uint8_t>(bits.has_value());
}

std::optional<uint32_t> Memory::rndGet(RndHook hook) const
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	const auto& config = region.configs[hookIndex];
	if (config.defaultKind != RndDefaultKind::Fixed)
		return std::nullopt;
	return config.defaultValue.u32;
}

bool Memory::rndEnabled(UuidRndHook hook) const
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	return region.configs[hookIndex].enabled != 0;
}

bool Memory::rndEnabled(RndHook hook) const
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	return region.configs[hookIndex].enabled != 0;
}

void Memory::rndClear()
{
	auto& region = checkedRnd();
	for (size_t index = 0; index < RND_CONFIG_COUNT; ++index)
		region.configs[index].enabled = 0;
	for (size_t index = 0; index < RND_CONFIG_COUNT; ++index)
		resetRndConfig(region.configs[index]);
	region.exactCount = 0;
}

void Memory::rndClear(UuidRndHook hook)
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	region.configs[hookIndex].enabled = 0;

	const auto [first, last] = rndExactRange(region, hook);
	if (last != first)
	{
		const auto exactCount = static_cast<size_t>(region.exactCount);
		auto* slots = const_cast<RndExactSlot*>(region.slots);
		std::memmove(slots + first, slots + last,
			(exactCount - last) * sizeof(RndExactSlot));
		region.exactCount = static_cast<uint32_t>(exactCount - (last - first));
	}

	resetRndConfig(region.configs[hookIndex]);
}

void Memory::rndClear(RndHook hook)
{
	auto& region = checkedRnd();
	const auto hookIndex = checkedRndHookIndex(hook, pid);
	resetRndConfig(region.configs[hookIndex]);
}

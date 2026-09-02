#include "UuidManager.h"

#include "InsertHook.h"
#include "SharedMemory.h"
#include "rp_dll.h"

namespace
{
    constexpr uint32_t DATA_ARRAY_BLOCK_OFFSET = 0;
    constexpr uint32_t DATA_ARRAY_MAX_USED_COUNT_OFFSET = 4;
    constexpr uint32_t DATA_ARRAY_MAX_SIZE_OFFSET = 8;

    ObjArrayMeta& arrayMeta(ObjType type)
    {
        return SharedMemory::getInstance()->shm().objMeta.arrays[objTypeIndex(type)];
    }

    void addAllocHooks()
    {
        InsertHook::addInsert(reinterpret_cast<void*>(0x41DE0A), [](const HookContext& reg) {
            getUuidManager().onAlloc(ObjType::Zombie, static_cast<uint16_t>(reg.ebx));
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41DEF1), [](const HookContext& reg) {
            getUuidManager().onAlloc(ObjType::Plant, static_cast<uint16_t>(reg.ebx));
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41DFFC), [](const HookContext& reg) {
            getUuidManager().onAlloc(ObjType::Projectile, static_cast<uint16_t>(reg.ebx));
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41E22A), [](const HookContext& reg) {
            getUuidManager().onAlloc(ObjType::GridItem, static_cast<uint16_t>(reg.ebx));
        });
    }

    void addFreeHooks()
    {
        // The originally identified 0x41BB4F/0x41BC23/0x41BCDB/0x41BE49
        // sites are unconditional jumps and cannot host a MinHook trampoline.
        // Hook the immediately preceding mSize update; the index registers are
        // already final here and the UUID is still invalidated before return.
        InsertHook::addInsert(reinterpret_cast<void*>(0x41BB49), [](const HookContext& reg) {
            getUuidManager().onFree(ObjType::Plant, static_cast<uint16_t>(reg.edx));
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41BC18), [](const HookContext& reg) {
            getUuidManager().onFree(ObjType::Zombie, static_cast<uint16_t>(reg.ecx));
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41BCD5), [](const HookContext& reg) {
            getUuidManager().onFree(ObjType::Projectile, static_cast<uint16_t>(reg.ecx));
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41BE43), [](const HookContext& reg) {
            getUuidManager().onFree(ObjType::GridItem, static_cast<uint16_t>(reg.edi));
        });
    }

    void addFreeAllHooks()
    {
        InsertHook::addInsert(reinterpret_cast<void*>(0x41E4D0), [](const HookContext&) {
            getUuidManager().clear(ObjType::Zombie);
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41E590), [](const HookContext&) {
            getUuidManager().clear(ObjType::Plant);
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41E600), [](const HookContext&) {
            getUuidManager().clear(ObjType::Projectile);
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41E7D0), [](const HookContext&) {
            getUuidManager().clear(ObjType::GridItem);
        });
    }

    void addDisposeHooks()
    {
        InsertHook::addInsert(reinterpret_cast<void*>(0x41DD70), [](const HookContext&) {
            getUuidManager().dispose(ObjType::Zombie);
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41DE50), [](const HookContext&) {
            getUuidManager().dispose(ObjType::Plant);
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41DF30), [](const HookContext&) {
            getUuidManager().dispose(ObjType::Projectile);
        });
        InsertHook::addInsert(reinterpret_cast<void*>(0x41E190), [](const HookContext&) {
            getUuidManager().dispose(ObjType::GridItem);
        });
    }
}

ObjArrayMeta& UuidManager::meta(ObjType type) const { return arrayMeta(type); }

uint32_t UuidManager::nextUuidCnt()
{
    ++counter;
    if (counter == 0)
        ++counter;
    return counter;
}

void UuidManager::onAlloc(ObjType type, uint16_t index)
{
    assert(index < OBJ_UUID_SLOT_COUNT);
    meta(type).uuidCnt[index] = nextUuidCnt();
}

void UuidManager::onFree(ObjType type, uint16_t index)
{
    assert(index < OBJ_UUID_SLOT_COUNT);
    meta(type).uuidCnt[index] = 0;
}

void UuidManager::clear(ObjType type)
{
    memset(meta(type).uuidCnt, 0, sizeof(meta(type).uuidCnt));
}

void UuidManager::clearAll()
{
    for (size_t i = 0; i < OBJ_TYPE_COUNT; ++i)
        clear(static_cast<ObjType>(i));
}

void UuidManager::dispose(ObjType type)
{
    auto& target = meta(type);
    memset(target.uuidCnt, 0, sizeof(target.uuidCnt));
    target.blockPtr = 0;
    target.maxSize = 0;
}

void UuidManager::scanExistingObjects()
{
    clearAll();
    for (size_t typeIndex = 0; typeIndex < OBJ_TYPE_COUNT; ++typeIndex)
    {
        const auto type = static_cast<ObjType>(typeIndex);
        auto& target = meta(type);
        if (target.dataArrayPtr == 0 || target.blockPtr == 0)
            continue;

        const auto maxUsedCount = *reinterpret_cast<const uint32_t*>(
            target.dataArrayPtr + DATA_ARRAY_MAX_USED_COUNT_OFFSET);
        const auto count = std::min({maxUsedCount, target.maxSize,
            static_cast<uint32_t>(OBJ_UUID_SLOT_COUNT)});
        const auto itemSize = getObjTypeInfo(type).ITEM_SIZE;
        const auto stride = getObjStride(type);

        for (uint32_t index = 0; index < count; ++index)
        {
            const auto slot = target.blockPtr + stride * index;
            const auto id = *reinterpret_cast<const uint32_t*>(slot + itemSize);
            if ((id >> 16) != 0)
                target.uuidCnt[index] = nextUuidCnt();
        }
    }
}

UuidManager& getUuidManager()
{
    static UuidManager manager;
    return manager;
}

void refreshArrayMeta(uint32_t board)
{
    assert(board != 0);
    for (size_t typeIndex = 0; typeIndex < OBJ_TYPE_COUNT; ++typeIndex)
    {
        const auto type = static_cast<ObjType>(typeIndex);
        auto& target = arrayMeta(type);
        target.dataArrayPtr = board + getObjTypeInfo(type).BOARD_ARRAY_OFFSET;
        target.blockPtr = *reinterpret_cast<const uint32_t*>(target.dataArrayPtr + DATA_ARRAY_BLOCK_OFFSET);
        target.maxSize = *reinterpret_cast<const uint32_t*>(target.dataArrayPtr + DATA_ARRAY_MAX_SIZE_OFFSET);
    }
}

void publishBoard(uint32_t board)
{
    auto& shm = SharedMemory::getInstance()->shm();
    getUuidManager().clearAll();
    refreshArrayMeta(board);
    shm.boardPtr = board;
    shm.isBoardPtrValid = false;
}

void unpublishBoard()
{
    auto& shm = SharedMemory::getInstance()->shm();
    getUuidManager().clearAll();
    memset(&shm.objMeta, 0, sizeof(shm.objMeta));
    shm.boardPtr = 0;
    shm.isBoardPtrValid = false;
}

void initializeObjectUuid()
{
    addAllocHooks();
    addFreeHooks();
    addFreeAllHooks();
    addDisposeHooks();

    InsertHook::addInsert(reinterpret_cast<void*>(0x407DC7), [](const HookContext& reg) {
        publishBoard(reg.ebp);
    });
    InsertHook::addInsert(reinterpret_cast<void*>(0x408690), [](const HookContext&) {
        unpublishBoard();
    });
    InsertHook::addInsert(reinterpret_cast<void*>(0x482078), [](const HookContext& reg) {
        refreshArrayMeta(reg.edi);
        getUuidManager().scanExistingObjects();
    });

    const auto board = readMemory<uint32_t>(0x6A9EC0, 0x768).value_or(0);
    if (board != 0)
    {
        publishBoard(board);
        getUuidManager().scanExistingObjects();
    }
}

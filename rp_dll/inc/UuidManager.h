#pragma once

#include "obj_uuid.h"

class UuidManager
{
    ObjArrayMeta& meta(ObjType type) const;

public:
    uint32_t nextUuidCnt(ObjType type);
    void onAlloc(ObjType type, uint16_t index);
    void onFree(ObjType type, uint16_t index, uint32_t dataArrayPtr);
    void clear(ObjType type);
    void clearAll();
    void dispose(ObjType type, uint32_t dataArrayPtr);
    void scanExistingObjects();
};

UuidManager& getUuidManager();
void refreshArrayMeta(uint32_t board);
void publishBoard(uint32_t board);
void unpublishBoard(uint32_t board);
void initializeObjectUuid();

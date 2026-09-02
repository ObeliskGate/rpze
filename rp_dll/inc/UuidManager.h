#pragma once

#include "obj_uuid.h"

class UuidManager
{
    uint32_t counter = 0;

    ObjArrayMeta& meta(ObjType type) const;

public:
    uint32_t nextUuidCnt();
    void onAlloc(ObjType type, uint16_t index);
    void onFree(ObjType type, uint16_t index);
    void clear(ObjType type);
    void clearAll();
    void dispose(ObjType type);
    void scanExistingObjects();
};

UuidManager& getUuidManager();
void refreshArrayMeta(uint32_t board);
void publishBoard(uint32_t board);
void unpublishBoard();
void initializeObjectUuid();

#pragma once
#include <stdint.h>
#include <stddef.h>
#include "obj_uuid.h"

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容

// Windows 头文件
#include <Windows.h> 

inline constexpr size_t SHARED_MEMORY_SIZE = 0x10000;

enum class PhaseCode : int32_t
{
	CONTINUE = 0, // 让游戏继续执行
	WAIT, // 暂停游戏, 以读写操作
	RUN_CODE, // 执行汇编码
	JUMP_FRAME, // 跳帧
	READ_MEMORY, // 读内存
	WRITE_MEMORY, // 写内存
	READ_MEMORY_PTR
};

enum class RunState : int32_t
{
	RUNNING = 0, // 游戏正在运行中
	OVER // 游戏开始被阻塞
};

enum class ExecuteResult : int32_t
{
	END = 0, // 没在执行
	SUCCESS, // 执行成功
	FAIL // 执行失败
};

enum class HookState : int32_t
{
	NOT_CONNECTED = 0, // 未连接
	CONNECTED, // 已连接
};

enum class HookPosition : int32_t
{
	MAIN_LOOP = 0,
	ZOMBIE_PICK_RANDOM_SPEED,
	CHALLENGE_I_ZOMBIE_SCORE_BRAIN,
	CHALLENGE_I_ZOMBIE_PLACE_PLANTS
};

enum class SyncMethod : int32_t
{
	SPIN = 0,
	MUTEX
};

enum class ShmError: int32_t
{
    NONE = 0,
    CAUGHT_SEH,
    CAUGHT_CPP_EXCEPTION
};

inline constexpr size_t getHookIndex(HookPosition pos) { return static_cast<size_t>(pos); }


#ifdef _MSC_VER
#pragma warning(push)  // 保存警告状态
#pragma warning(disable : 4201)  // 使用了非标准扩展: 无名称的结构/联合
#endif

#pragma pack(push, 1)
struct Shm
{
    static constexpr size_t OFFSETS_LEN = 16;
    static constexpr uint32_t OFFSET_END = UINT32_MAX;
    static constexpr size_t HOOK_LEN = 16;
    static constexpr uint32_t BUFFER_OFFSET = 0x0100;
    static constexpr uint32_t ASM_OFFSET = 0x1000;
    static constexpr uint32_t OBJ_META_OFFSET = 0x2000;
    static constexpr uint32_t BUFFER_SIZE = ASM_OFFSET - BUFFER_OFFSET;
    static constexpr uint32_t ASM_SIZE = OBJ_META_OFFSET - ASM_OFFSET;
    static constexpr uint32_t RESERVED_OFFSET = OBJ_META_OFFSET + sizeof(ObjMeta);
    static constexpr uint32_t RESERVED_SIZE = SHARED_MEMORY_SIZE - RESERVED_OFFSET;

    union {
        struct {
            volatile PhaseCode phaseCode;
            volatile RunState runState;
            volatile uint32_t boardPtr;
            volatile PhaseCode jumpingPhaseCode;
            volatile RunState jumpingRunState;
            volatile uint32_t memoryNum; // size of memory to be read & writed

            volatile uint32_t offsets[OFFSETS_LEN];  // offsets of memory be read & writed

            volatile HookState globalState;
            volatile ExecuteResult executeResult;

            volatile HookState hookStateArr[HOOK_LEN];
            volatile SyncMethod syncMethod;
            volatile SyncMethod jumpingSyncMethod;

            volatile ShmError error;

            volatile bool isBoardPtrValid;
            volatile bool alreadyShared;
        };
        uint8_t __padding_before_buffers[BUFFER_OFFSET];
    };

    volatile char readWriteBuffer[BUFFER_SIZE];
    volatile char asmBuffer[ASM_SIZE];
    ObjMeta objMeta;
    uint8_t reserved[RESERVED_SIZE];

    template <typename T = void>
    volatile T* getReadWriteBuffer() volatile { return reinterpret_cast<volatile T*>(readWriteBuffer); }

    template <typename T = void>
    volatile T* getAsmBuffer() volatile { return reinterpret_cast<volatile T*>(asmBuffer); }

    Shm() = delete;
};
#pragma pack(pop)

#ifdef __MSC_VER
#pragma warning(pop)  // 恢复警告状态
#endif

static_assert(offsetof(Shm, readWriteBuffer) == Shm::BUFFER_OFFSET, "Shm buffer offset error");
static_assert(offsetof(Shm, asmBuffer) == Shm::ASM_OFFSET, "Shm asm buffer offset error");
static_assert(offsetof(Shm, objMeta) == Shm::OBJ_META_OFFSET, "Shm object metadata offset error");
static_assert(Shm::RESERVED_OFFSET == 0x6030, "Shm reserved offset error");
static_assert(sizeof(Shm) == SHARED_MEMORY_SIZE, "Shm size error");

inline std::string toShmName(std::string_view name, std::optional<DWORD> pid = {}) {
    auto p = pid.value_or(GetCurrentProcessId());
    return std::format("__rp_dll_shared_affix_{}_{}", p, name);
}

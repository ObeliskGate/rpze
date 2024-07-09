#pragma once
#include <stdint.h>

#ifndef RP_API
#ifdef RP_DLL
#define RP_API __declspec(dllexport)
#else
#define RP_API __declspec(dllimport)
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t InitArgs;

RP_API uint32_t setEnv(InitArgs* options);

#ifdef __cplusplus
}
#endif
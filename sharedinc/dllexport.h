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

RP_API uint32_t setEnv(uint32_t* options);

#ifdef __cplusplus
}
#endif
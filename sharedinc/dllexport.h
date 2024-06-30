#ifdef RP_DLL
#define RP_API __declspec(dllexport)
#else
#define RP_API __declspec(dllimport)
#endif
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

RP_API uint32_t setEnv(uint32_t* options);

#ifdef __cplusplus
}
#endif
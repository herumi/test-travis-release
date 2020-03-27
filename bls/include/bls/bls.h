#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
typedef size_t mclSize;

int blsVerifyAggregatedHashWithDomain(const void *aggSig, const void *pubVec, const unsigned char hashWithDomain[][40], size_t n);

#ifdef __cplusplus
}
#endif

#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdlib.h>

typedef size_t mclSize;

int blsInit(int curve, int compiledTimeVar);
int blsSecretKeySetByCSPRNG(blsSecretKey *sec);
void blsGetPublicKey(blsPublicKey *pub, const blsSecretKey *sec);
void blsAggregateSignature(blsSignature *aggSig, const blsSignature *sigVec, mclSize n);

int blsSignHashWithDomain(blsSignature *sig, const blsSecretKey *sec, const unsigned char hashWithDomain[40]);
int blsVerifyAggregatedHashWithDomain(const blsSignature *aggSig, const blsPublicKey *pubVec, const unsigned char hashWithDomain[][40], mclSize n);

#ifdef __cplusplus
}
#endif

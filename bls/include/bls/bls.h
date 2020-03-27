#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
typedef size_t mclSize;

#include <stdint.h>
#define MCLBN_FP_UNIT_SIZE 6
#define MCLBN_FR_UNIT_SIZE 4
typedef struct {
	uint64_t d[MCLBN_FP_UNIT_SIZE];
} mclBnFp;

typedef struct {
	mclBnFp d[2];
} mclBnFp2;

typedef struct {
	uint64_t d[MCLBN_FR_UNIT_SIZE];
} mclBnFr;

typedef struct {
	mclBnFp x, y, z;
} mclBnG1;

typedef struct {
	mclBnFp2 x, y, z;
} mclBnG2;

typedef struct {
	mclBnFr v;
} blsSecretKey;

typedef struct {
	mclBnG1 v;
} blsPublicKey;

typedef struct {
	mclBnG2 v;
} blsSignature;

int blsVerifyAggregatedHashWithDomain(const blsSignature *aggSig, const blsPublicKey *pubVec, const unsigned char hashWithDomain[][40], mclSize n);

#ifdef __cplusplus
}
#endif

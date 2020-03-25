#pragma once
#include <stdint.h>
#define MCLBN_FP_UNIT_SIZE 6
#define MCLBN_FR_UNIT_SIZE 4
#define MCL_BLS12_381 5
#define MCLBN_NO_AUTOLINK

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

#define BLS_COMPILER_TIME_VAR_ADJ 200
#define MCLBN_COMPILED_TIME_VAR ((MCLBN_FR_UNIT_SIZE) * 10 + (MCLBN_FP_UNIT_SIZE) + BLS_COMPILER_TIME_VAR_ADJ)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	mclBnFr v;
} blsId;

typedef struct {
	mclBnFr v;
} blsSecretKey;

typedef struct {
#ifdef BLS_SWAP_G
	mclBnG1 v;
#else
	mclBnG2 v;
#endif
} blsPublicKey;

typedef struct {
#ifdef BLS_SWAP_G
	mclBnG2 v;
#else
	mclBnG1 v;
#endif
} blsSignature;

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

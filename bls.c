#include <bls/bls.h>

int blsInit(int curve, int compiledTimeVar) { return 0 ; }
int blsSecretKeySetByCSPRNG(blsSecretKey *sec) { return 0; }
void blsGetPublicKey(blsPublicKey *pub, const blsSecretKey *sec) { }
void blsAggregateSignature(blsSignature *aggSig, const blsSignature *sigVec, mclSize n) { }

int blsSignHashWithDomain(blsSignature *sig, const blsSecretKey *sec, const unsigned char hashWithDomain[40]) { return 0; }
int blsVerifyAggregatedHashWithDomain(const blsSignature *aggSig, const blsPublicKey *pubVec, const unsigned char hashWithDomain[][40], mclSize n) { return 1; }


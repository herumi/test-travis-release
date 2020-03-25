#pragma once
/**
	@file
	@brief C interface of bls.hpp
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#define MCLBN_NO_AUTOLINK
#include <mcl/bn.h>

#ifdef BLS_ETH
	#ifndef BLS_SWAP_G
		#define BLS_SWAP_G
	#endif
	#define BLS_COMPILER_TIME_VAR_ADJ 200
#endif
#ifdef BLS_SWAP_G
	#ifndef BLS_COMPILER_TIME_VAR_ADJ
		#define BLS_COMPILER_TIME_VAR_ADJ 100
	#endif
	/*
		error if BLS_SWAP_G is inconsistently used between library and exe
	*/
	#undef MCLBN_COMPILED_TIME_VAR
	#define MCLBN_COMPILED_TIME_VAR ((MCLBN_FR_UNIT_SIZE) * 10 + (MCLBN_FP_UNIT_SIZE) + BLS_COMPILER_TIME_VAR_ADJ)
#endif

#ifdef _MSC_VER
	#ifdef BLS_DONT_EXPORT
		#define BLS_DLL_API
	#else
		#ifdef BLS_DLL_EXPORT
			#define BLS_DLL_API __declspec(dllexport)
		#else
			#define BLS_DLL_API __declspec(dllimport)
		#endif
	#endif
	#ifndef BLS_NO_AUTOLINK
		#if MCLBN_FP_UNIT_SIZE == 4
			#pragma comment(lib, "bls256.lib")
		#elif (MCLBN_FP_UNIT_SIZE == 6) && (MCLBN_FR_UNIT_SIZE == 4)
			#pragma comment(lib, "bls384_256.lib")
		#elif (MCLBN_FP_UNIT_SIZE == 6) && (MCLBN_FR_UNIT_SIZE == 6)
			#pragma comment(lib, "bls384.lib")
		#endif
	#endif
#elif defined(__EMSCRIPTEN__) && !defined(BLS_DONT_EXPORT)
	#define BLS_DLL_API __attribute__((used))
#elif defined(__wasm__) && !defined(BLS_DONT_EXPORT)
	#define BLS_DLL_API __attribute__((visibility("default")))
#else
	#define BLS_DLL_API
#endif

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

/*
	initialize this library
	call this once before using the other functions
	@param curve [in] enum value defined in mcl/bn.h
	@param compiledTimeVar [in] specify MCLBN_COMPILED_TIME_VAR,
	which macro is used to make sure that the values
	are the same when the library is built and used
	@return 0 if success
	@note blsInit() is not thread safe
*/
BLS_DLL_API int blsInit(int curve, int compiledTimeVar);


BLS_DLL_API int blsSecretKeySetByCSPRNG(blsSecretKey *sec);
BLS_DLL_API void blsGetPublicKey(blsPublicKey *pub, const blsSecretKey *sec);
// aggSig = sum of sigVec[0..n]
BLS_DLL_API void blsAggregateSignature(blsSignature *aggSig, const blsSignature *sigVec, mclSize n);

#ifndef BLS_MINIMUM_API

/*
	sign hashWithDomain by sec
	hashWithDomain[0:32] 32 bytes message
	hashWithDomain[32:40] 8 bytes data
	see https://github.com/ethereum/eth2.0-specs/blob/dev/specs/bls_signature.md#hash_to_g2
	HashWithDomain apis support only for BLS_ETH=1 and BLS12_381
	return 0 if success else -1
*/
BLS_DLL_API int blsSignHashWithDomain(blsSignature *sig, const blsSecretKey *sec, const unsigned char hashWithDomain[40]);
// return 1 if valid

/*
	pubVec is an array of size n
	hashWithDomain is an array of size (40 * n)
*/
BLS_DLL_API int blsVerifyAggregatedHashWithDomain(const blsSignature *aggSig, const blsPublicKey *pubVec, const unsigned char hashWithDomain[][40], mclSize n);

///// to here only for BLS12-381 with BLS_ETH

#endif // BLS_MINIMUM_API

#ifdef __cplusplus
}
#endif

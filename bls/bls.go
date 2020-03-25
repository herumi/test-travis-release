package bls

/*
#cgo CFLAGS:-I${SRCDIR}./include -DBLS_ETH -DBLS_SWAP_G -I./include
#cgo LDFLAGS:-lbls384_256 -lstdc++ -lm
#cgo linux,amd64 LDFLAGS:-L${SRCDIR}/lib/linux/amd64
#cgo linux,arm64 LDFLAGS:-L${SRCDIR}/lib/linux/arm64
#cgo darwin,amd64 LDFLAGS:-L${SRCDIR}/lib/darwin/amd64
#cgo darwin,arm64 LDFLAGS:-L${SRCDIR}/lib/darwin/arm64
#include <bls/bls.h>
*/
import "C"
import (
	"unsafe"
)

// 2
const BLS12_381 = C.MCL_BLS12_381

func Init(curve int) error {
	C.blsInit(C.int(curve), C.MCLBN_COMPILED_TIME_VAR)
	return nil
}

type SecretKey struct {
	v C.blsSecretKey
}

func (sec *SecretKey) SetByCSPRNG() {
	err :=  C.blsSecretKeySetByCSPRNG(&sec.v)
	if err != 0 {
		panic("err blsSecretKeySetByCSPRNG")
	}
}

type PublicKey struct {
	v C.blsPublicKey
}

type PublicKeys []PublicKey

type Sign struct {
	v C.blsSignature
}

func (sec *SecretKey) GetPublicKey() (pub *PublicKey) {
	pub = new(PublicKey)
	C.blsGetPublicKey(&pub.v, &sec.v)
	return pub
}

func (sig *Sign) Aggregate(sigVec []Sign) {
	C.blsAggregateSignature(&sig.v, &sigVec[0].v, C.mclSize(len(sigVec)))
}

func (sec *SecretKey) SignHashWithDomain(hashWithDomain []byte) (sig *Sign) {
	if len(hashWithDomain) != 40 {
		return nil
	}
	sig = new(Sign)
	// #nosec
	err := C.blsSignHashWithDomain(&sig.v, &sec.v, (*C.uchar)(unsafe.Pointer(&hashWithDomain[0])))
	if err == 0 {
		return sig
	}
	return nil
}

func (sig *Sign) VerifyAggregateHashWithDomain(pubVec []PublicKey, hashWithDomains []byte) bool {
	if pubVec == nil {
		return false
	}
	n := len(pubVec)
	if n == 0 || len(hashWithDomains) != n*40 {
		return false
	}
	return C.blsVerifyAggregatedHashWithDomain(&sig.v, &pubVec[0].v, (*[40]C.uchar)(unsafe.Pointer(&hashWithDomains[0])), C.mclSize(n)) == 1
}

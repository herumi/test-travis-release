package bls

/*
#cgo CFLAGS:-I${SRCDIR}/include/
#cgo LDFLAGS:-lbls
#cgo linux,amd64 LDFLAGS:-L${SRCDIR}/lib/linux/amd64
#cgo darwin,amd64 LDFLAGS:-L${SRCDIR}/lib/darwin/amd64
#include <bls/bls.h>
*/
import "C"
import (
	"unsafe"
)

type SecretKey struct {
	v C.blsSecretKey
}

type PublicKey struct {
	v C.blsPublicKey
}

type PublicKeys []PublicKey

type Sign struct {
	v C.blsSignature
}

func (sig *Sign) VerifyAggregateHashWithDomain(pubVec []PublicKey, hashWithDomains []byte) bool {
	n := len(pubVec)
	return C.blsVerifyAggregatedHashWithDomain(&sig.v, &pubVec[0].v, (*[40]C.uchar)(unsafe.Pointer(&hashWithDomains[0])), C.mclSize(n)) == 1
}

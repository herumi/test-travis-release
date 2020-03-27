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

func BlsFunc(hashWithDomains []byte) bool {
	n := 3
	return C.blsFunc(nil, nil, (*[40]C.uchar)(unsafe.Pointer(&hashWithDomains[0])), C.size_t(n)) == 1
}

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

func BlsFunc(buf []byte) {
	n := 3
	C.blsFunc((*[40]C.char)(unsafe.Pointer(&buf[0])), C.size_t(n))
}

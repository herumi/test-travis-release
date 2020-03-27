package bls

/*
#cgo LDFLAGS:-lbls
#cgo linux,amd64 LDFLAGS:-L${SRCDIR}/lib/linux/amd64
#cgo darwin,amd64 LDFLAGS:-L${SRCDIR}/lib/darwin/amd64
void blsFunc(const char buf[][8]);
*/
import "C"
import (
	"unsafe"
)

func BlsFunc(buf []byte) {
	C.blsFunc((*[8]C.char)(unsafe.Pointer(&buf[0])))
}

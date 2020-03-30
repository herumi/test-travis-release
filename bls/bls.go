package bls

/*
#cgo LDFLAGS:-lbls -L${SRCDIR}/lib
void blsFunc(const char buf[][8]);
*/
import "C"
import (
	"unsafe"
)

func BlsFunc(buf []byte) {
	C.blsFunc((*[8]C.char)(unsafe.Pointer(&buf[0])))
}

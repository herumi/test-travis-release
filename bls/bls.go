package bls

/*
#cgo LDFLAGS:-lbls -L ./lib
int blsFunc(const char buf[][8]);

// dirty hack to avoid error on travis-ci with linux
inline int blsFuncWrap(const char *buf)
{
	typedef char type[8];
	return blsFunc((const type*)buf);
}
*/
import "C"
import (
	"unsafe"
)

func BlsFunc(buf []byte) int {
	/*
		The following line runs well on Linux/macOS/Windows mingw, but failts on Travis-ci with linux
		cf. https://travis-ci.org/github/herumi/test-travis-release/builds/668709471
		bls/bls.go:13:118: cannot use _cgo0 (type *[8]_Ctype_char) as type unsafe.Pointer in argument to _Cfunc_blsFunc
	*/
	//v := C.blsFunc((*[8]C.char)(unsafe.Pointer(&buf[0])))
	/*
		Then use blsFuncWrap instead of blsFunc
	*/
	v := C.blsFuncWrap((*C.char)(unsafe.Pointer(&buf[0])))
	return (int)(v)
}

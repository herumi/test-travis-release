package bls

/*
#cgo CFLAGS:-I${SRCDIR}./include -DBLS_ETH -DBLS_SWAP_G
#cgo LDFLAGS:-lbls384_256 -lstdc++ -lm
#cgo ios LDFLAGS:-L${SRCDIR}/lib/ios
#cgo android,arm64 LDFLAGS:-L${SRCDIR}/lib/android/arm64-v8a
#cgo android,arm LDFLAGS:-L${SRCDIR}/lib/android/armeabi-v7a
#cgo android,amd64 LDFLAGS:-L${SRCDIR}/lib/android/x86_64
#cgo linux,amd64 LDFLAGS:-L${SRCDIR}/lib/linux/amd64
#cgo linux,arm64 LDFLAGS:-L${SRCDIR}/lib/linux/arm64
#cgo darwin,amd64 LDFLAGS:-L${SRCDIR}/lib/darwin/amd64
#cgo darwin,arm64 LDFLAGS:-L${SRCDIR}/lib/darwin/arm64
#cgo windows,amd64 LDFLAGS:-L${SRCDIR}/lib/windows/amd64
typedef unsigned int (*ReadRandFunc)(void *, void *, unsigned int);
int wrapReadRandCgo(void *self, void *buf, unsigned int n);
#include <mcl/bn_c384_256.h>
#include <bls/bls.h>
*/
import "C"
import (
	"fmt"
	"io"
	"unsafe"
)

// Init --
// call this function before calling all the other operations
// this function is not thread safe
func Init(curve int) error {
	if curve != C.MCL_BLS12_381 {
		return fmt.Errorf("ERR only BLS12-381")
	}
	err := C.blsInit(C.int(curve), C.MCLBN_COMPILED_TIME_VAR)
	if err != 0 {
		return fmt.Errorf("ERR Init curve=%d", curve)
	}
	return nil
}

// SecretKey --
type SecretKey struct {
	v C.blsSecretKey
}

// SetByCSPRNG --
func (sec *SecretKey) SetByCSPRNG() {
	err := C.blsSecretKeySetByCSPRNG(&sec.v)
	if err != 0 {
		panic("err blsSecretKeySetByCSPRNG")
	}
}

// Add --
func (sec *SecretKey) Add(rhs *SecretKey) {
	C.blsSecretKeyAdd(&sec.v, &rhs.v)
}

// GetMasterSecretKey --
func (sec *SecretKey) GetMasterSecretKey(k int) (msk []SecretKey) {
	msk = make([]SecretKey, k)
	msk[0] = *sec
	for i := 1; i < k; i++ {
		msk[i].SetByCSPRNG()
	}
	return msk
}

// GetMasterPublicKey --
func GetMasterPublicKey(msk []SecretKey) (mpk []PublicKey) {
	n := len(msk)
	mpk = make([]PublicKey, n)
	for i := 0; i < n; i++ {
		mpk[i] = *msk[i].GetPublicKey()
	}
	return mpk
}

// PublicKey --
type PublicKey struct {
	v C.blsPublicKey
}

// PublicKeys ..
type PublicKeys []PublicKey

// IsEqual --
func (pub *PublicKey) IsEqual(rhs *PublicKey) bool {
	if pub == nil || rhs == nil {
		return false
	}
	return C.blsPublicKeyIsEqual(&pub.v, &rhs.v) == 1
}

// Add --
func (pub *PublicKey) Add(rhs *PublicKey) {
	C.blsPublicKeyAdd(&pub.v, &rhs.v)
}

// Sign  --
type Sign struct {
	v C.blsSignature
}

// IsEqual --
func (sig *Sign) IsEqual(rhs *Sign) bool {
	if sig == nil || rhs == nil {
		return false
	}
	return C.blsSignatureIsEqual(&sig.v, &rhs.v) == 1
}

// GetPublicKey --
func (sec *SecretKey) GetPublicKey() (pub *PublicKey) {
	pub = new(PublicKey)
	C.blsGetPublicKey(&pub.v, &sec.v)
	return pub
}

// Sign -- Constant Time version
func (sec *SecretKey) Sign(m string) (sig *Sign) {
	sig = new(Sign)
	buf := []byte(m)
	// #nosec
	C.blsSign(&sig.v, &sec.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	return sig
}

// Add --
func (sig *Sign) Add(rhs *Sign) {
	C.blsSignatureAdd(&sig.v, &rhs.v)
}

// Verify --
func (sig *Sign) Verify(pub *PublicKey, m string) bool {
	if sig == nil || pub == nil {
		return false
	}
	buf := []byte(m)
	// #nosec
	return C.blsVerify(&sig.v, &pub.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf))) == 1
}

func bool2int(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

// VerifySignatureOrder --
func VerifySignatureOrder(doVerify bool) {
	C.blsSignatureVerifyOrder(bool2int(doVerify))
}

// VerifyPublicKeyOrder --
func VerifyPublicKeyOrder(doVerify bool) {
	C.blsPublicKeyVerifyOrder(bool2int(doVerify))
}

// IsValidOrder --
func (pub *PublicKey) IsValidOrder() bool {
	return C.blsPublicKeyIsValidOrder(&pub.v) == 1
}

// IsValidOrder --
func (sig *Sign) IsValidOrder() bool {
	return C.blsSignatureIsValidOrder(&sig.v) == 1
}

// VerifyPop --
func (sig *Sign) VerifyPop(pub *PublicKey) bool {
	if sig == nil || pub == nil {
		return false
	}
	return C.blsVerifyPop(&sig.v, &pub.v) == 1
}

// DHKeyExchange --
func DHKeyExchange(sec *SecretKey, pub *PublicKey) (out PublicKey) {
	C.blsDHKeyExchange(&out.v, &sec.v, &pub.v)
	return out
}

// HashAndMapToSignature --
func HashAndMapToSignature(buf []byte) *Sign {
	sig := new(Sign)
	// #nosec
	err := C.blsHashToSignature(&sig.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err != 0 {
		return nil
	}
	return sig
}

// VerifyPairing --
func VerifyPairing(X *Sign, Y *Sign, pub *PublicKey) bool {
	if X == nil || Y == nil || pub == nil {
		return false
	}
	return C.blsVerifyPairing(&X.v, &Y.v, &pub.v) == 1
}

// SignHash --
func (sec *SecretKey) SignHash(hash []byte) (sig *Sign) {
	sig = new(Sign)
	// #nosec
	err := C.blsSignHash(&sig.v, &sec.v, unsafe.Pointer(&hash[0]), C.mclSize(len(hash)))
	if err == 0 {
		return sig
	}
	return nil
}

// VerifyHash --
func (sig *Sign) VerifyHash(pub *PublicKey, hash []byte) bool {
	if pub == nil {
		return false
	}
	// #nosec
	return C.blsVerifyHash(&sig.v, &pub.v, unsafe.Pointer(&hash[0]), C.mclSize(len(hash))) == 1
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// VerifyAggregateHashes --
func (sig *Sign) VerifyAggregateHashes(pubVec []PublicKey, hash [][]byte) bool {
	if pubVec == nil {
		return false
	}
	n := len(hash)
	if n == 0 {
		return false
	}
	hashByte := len(hash[0])
	h := make([]byte, n*hashByte)
	for i := 0; i < n; i++ {
		hn := len(hash[i])
		copy(h[i*hashByte:(i+1)*hashByte], hash[i][0:min(hn, hashByte)])
	}
	return C.blsVerifyAggregatedHashes(&sig.v, &pubVec[0].v, unsafe.Pointer(&h[0]), C.mclSize(hashByte), C.mclSize(n)) == 1
}

// SignatureVerifyOrder --
// check the correctness of the order of signature in deserialize if true
func SignatureVerifyOrder(doVerify bool) {
	var b = 0
	if doVerify {
		b = 1
	}
	C.blsSignatureVerifyOrder(C.int(b))
}

// SignByte --
func (sec *SecretKey) SignByte(msg []byte) (sig *Sign) {
	sig = new(Sign)
	// #nosec
	C.blsSign(&sig.v, &sec.v, unsafe.Pointer(&msg[0]), C.mclSize(len(msg)))
	return sig
}

// VerifyByte --
func (sig *Sign) VerifyByte(pub *PublicKey, msg []byte) bool {
	if sig == nil || pub == nil {
		return false
	}
	// #nosec
	return C.blsVerify(&sig.v, &pub.v, unsafe.Pointer(&msg[0]), C.mclSize(len(msg))) == 1
}

// Aggregate --
func (sig *Sign) Aggregate(sigVec []Sign) {
	C.blsAggregateSignature(&sig.v, &sigVec[0].v, C.mclSize(len(sigVec)))
}

// FastAggregateVerify --
func (sig *Sign) FastAggregateVerify(pubVec []PublicKey, msg []byte) bool {
	if pubVec == nil {
		return false
	}
	n := len(pubVec)
	return C.blsFastAggregateVerify(&sig.v, &pubVec[0].v, C.mclSize(n), unsafe.Pointer(&msg[0]), C.mclSize(len(msg))) == 1
}

///

var sRandReader io.Reader

func createSlice(buf *C.char, n C.uint) []byte {
	size := int(n)
	return (*[1 << 30]byte)(unsafe.Pointer(buf))[:size:size]
}

// this function can't be put in callback.go
//export wrapReadRandGo
func wrapReadRandGo(buf *C.char, n C.uint) C.uint {
	slice := createSlice(buf, n)
	ret, err := sRandReader.Read(slice)
	if ret == int(n) && err == nil {
		return n
	}
	return 0
}

// SetRandFunc --
func SetRandFunc(randReader io.Reader) {
	sRandReader = randReader
	if randReader != nil {
		C.blsSetRandFunc(nil, C.ReadRandFunc(unsafe.Pointer(C.wrapReadRandCgo)))
	} else {
		// use default random generator
		C.blsSetRandFunc(nil, C.ReadRandFunc(unsafe.Pointer(nil)))
	}
}

// BlsGetGeneratorOfPublicKey -
func BlsGetGeneratorOfPublicKey(pub *PublicKey) {
	C.blsGetGeneratorOfPublicKey(&pub.v)
}

// SerializeUncompressed --
func (pub *PublicKey) SerializeUncompressed() []byte {
	buf := make([]byte, 96)
	// #nosec
	n := C.blsPublicKeySerializeUncompressed(unsafe.Pointer(&buf[0]), C.mclSize(len(buf)), &pub.v)
	if n == 0 {
		panic("err blsPublicKeySerializeUncompressed")
	}
	return buf[:n]
}

// SerializeUncompressed --
func (sig *Sign) SerializeUncompressed() []byte {
	buf := make([]byte, 192)
	// #nosec
	n := C.blsSignatureSerializeUncompressed(unsafe.Pointer(&buf[0]), C.mclSize(len(buf)), &sig.v)
	if n == 0 {
		panic("err blsSignatureSerializeUncompressed")
	}
	return buf[:n]
}

// DeserializeUncompressed --
func (pub *PublicKey) DeserializeUncompressed(buf []byte) error {
	// #nosec
	err := C.blsPublicKeyDeserializeUncompressed(&pub.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err == 0 {
		return fmt.Errorf("err blsPublicKeyDeserializeUncompressed %x", buf)
	}
	return nil
}

// DeserializeUncompressed --
func (sig *Sign) DeserializeUncompressed(buf []byte) error {
	// #nosec
	err := C.blsSignatureDeserializeUncompressed(&sig.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err == 0 {
		return fmt.Errorf("err blsSignatureDeserializeUncompressed %x", buf)
	}
	return nil
}

// SetETHmode --
// 0 ; old version
// 1 ; draft 05
// 2 ; draft 06
func SetETHmode(mode int) error {
	if err := C.blsSetETHmode(C.int(mode)); err != 0 {
		return fmt.Errorf("got non-zero response code: %d", err)
	}
	return nil
}

func AreAllMsgDifferent(msgVec []byte, msgSize int) bool {
	n := len(msgVec) / msgSize
	// How can I use []byte instead of string?
	set := map[string]struct{}{}
	for i := 0; i < n; i++ {
		msg := string(msgVec[i*msgSize : (i+1)*msgSize])
		_, ok := set[msg]
		if ok {
			return false
		}
		set[msg] = struct{}{}
	}
	return true
}

func (sig *Sign) innerAggregateVerify(pubVec []PublicKey, msgVec []byte, checkMessage bool) bool {
	const MSG_SIZE = 32
	n := len(pubVec)
	if n == 0 || len(msgVec) != MSG_SIZE*n {
		return false
	}
	if checkMessage && !AreAllMsgDifferent(msgVec, MSG_SIZE) {
		return false
	}
	return C.blsAggregateVerifyNoCheck(&sig.v, &pubVec[0].v, unsafe.Pointer(&msgVec[0]), MSG_SIZE, C.mclSize(n)) == 1
}

// AggregateVerify --
// len(msgVec) == 32 * len(pubVec)
func (sig *Sign) AggregateVerifyNoCheck(pubVec []PublicKey, msgVec []byte) bool {
	return sig.innerAggregateVerify(pubVec, msgVec, false)
}

// AggregateVerify --
// len(msgVec) == 32 * len(pubVec)
// check all msgs are different each other
func (sig *Sign) AggregateVerify(pubVec []PublicKey, msgVec []byte) bool {
	return sig.innerAggregateVerify(pubVec, msgVec, true)
}

// SignHashWithDomain -- duplicated for mode > 0
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

// VerifyHashWithDomain -- duplicated for mode > 0
func (sig *Sign) VerifyHashWithDomain(pub *PublicKey, hashWithDomain []byte) bool {
	if len(hashWithDomain) != 40 {
		return false
	}
	if pub == nil {
		return false
	}
	// #nosec
	return C.blsVerifyHashWithDomain(&sig.v, &pub.v, (*C.uchar)(unsafe.Pointer(&hashWithDomain[0]))) == 1
}

// VerifyAggregateHashWithDomain -- duplicated for mode > 0
// hashWithDomains is array of 40 * len(pubVec)
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

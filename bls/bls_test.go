package bls

import (
	"testing"
)

func Test(_ *testing.T) {
	const S = 40
	const N = 10
	hds := make([]byte, S*N)
	BlsFunc(hds)
}

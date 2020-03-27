package bls

import (
	"testing"
)

func Test(_ *testing.T) {
	const S = 40
	const N = 10
	buf := make([]byte, S*N)
	BlsFunc(buf)
}

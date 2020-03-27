package bls

import (
	"testing"
)

func Test(t *testing.T) {
	const S = 40
	const N = 10
	hds := make([]byte, S*N)
	if !BlsFunc(hds) {
		t.Fatalf("bad VerifyAggregateHashWithDomain")
	}
}

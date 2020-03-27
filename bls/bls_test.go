package bls

import (
	"testing"
)

func Test(t *testing.T) {
	const S = 40
	const N = 10
	pubs := make([]PublicKey, N)
	hds := make([]byte, S*N)
//	var sig Sign
//	if !sig.VerifyAggregateHashWithDomain(pubs, hds) {
//		t.Fatalf("bad VerifyAggregateHashWithDomain")
//	}
	if !BlsFunc(pubs, hds) {
		t.Fatalf("bad VerifyAggregateHashWithDomain")
	}
}

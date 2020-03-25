package bls

import (
	"testing"
)

func testVerifyHashDomain(t *testing.T) {
	const S = 40
	const N = 10
	secs := make([]SecretKey, N)
	pubs := make([]PublicKey, N)
	sigs := make([]Sign, N)
	hds := make([]byte, S*N)
	for i := 0; i < N; i++ {
		hds[i*S] = byte(i)
		hd := hds[S*i : S*(i+1)]
		secs[i].SetByCSPRNG()
		pubs[i] = *secs[i].GetPublicKey()
		sigs[i] = *secs[i].SignHashWithDomain(hd)
		if !sigs[i].VerifyHashWithDomain(&pubs[i], hd) {
			t.Fatalf("bad VerifyHashWithDomain %v", i)
		}
	}
	var sig Sign
	sig.Aggregate(sigs)
	if !sig.VerifyAggregateHashWithDomain(pubs, hds) {
		t.Fatalf("bad VerifyAggregateHashWithDomain")
	}
	hds[0] = 5
	if sig.VerifyAggregateHashWithDomain(pubs, hds) {
		t.Fatalf("bad VerifyAggregateHashWithDomain 2")
	}
}

func Test(t *testing.T) {
	if Init(BLS12_381) != nil {
		t.Fatalf("Init")
	}
	testVerifyHashDomain(t)
}

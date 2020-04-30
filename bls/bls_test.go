package bls

import (
	"fmt"
	"testing"
)

func Test(_ *testing.T) {
	buf := "01234567X9abcdef"
	fmt.Printf("ret=%c\n", BlsFunc([]byte(buf)))
}

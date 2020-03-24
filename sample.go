package main

/*
#include <stdio.h>
#include <stdlib.h>
void put(const unsigned char s[][40], size_t n)
{
	for (size_t i = 0; i < n; i++) {
		printf("%zd %s\n", i, s[i]);
	}
}
*/
import "C"
import "unsafe"

func callPut(s []byte) {
	C.put((*[40]C.uchar)(unsafe.Pointer(&s[0])), (C.size_t)(len(s)/40))
}

func main() {
	const L = 40
	t := []string{"abcd", "012345", "XYZ", "QQQX"}
	s := make([]byte, L*len(t))
	for i := 0; i < len(t); i++ {
		for j := 0; j < len(t[i]); j++ {
			s[i*L+j] = t[i][j]
		}
	}
	callPut(s)
}

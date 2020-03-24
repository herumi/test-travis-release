package main
/*
#include <stdio.h>
#include <stdlib.h>
void put(const char s[][3], size_t n)
{
	for (size_t i = 0; i < n; i++) {
		printf("%zd %c%c%c\n", i, s[i][0], s[i][1], s[i][2]);
	}
}
*/
import "C"
import "unsafe"

func main() {
	s := ([]byte)("abc012XYZQQQ");
	C.put((*[3]C.char)(unsafe.Pointer(&s[0])), (C.size_t)(len(s) / 3))
}

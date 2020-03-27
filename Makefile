UNAME_S=$(shell uname -s)
ARCH=amd64
ifeq ($(UNAME_S),Linux)
  OS=linux
endif
ifeq ($(UNAME_S),Darwin)
  OS=darwin
endif
TARGET=bls/lib/$(OS)/$(ARCH)/libbls.a

all: $(TARGET)
$(TARGET): bls.o
	mkdir -p bls/lib/$(OS)/$(ARCH)
	ar r $@ $<

bls.o: bls.c bls/include/bls/bls.h
	$(CC) -o $@ $< -O2 -c -I ./bls/include

test: $(TARGET)
	go test -v ./bls

clean:
	rm -rf bls.o $(TARGET)

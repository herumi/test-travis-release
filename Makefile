TARGET=bls/lib/libbls.a

all: $(TARGET)
$(TARGET): bls.o
	mkdir -p bls/lib
	ar r $@ $<

bls.o: bls.c
	$(CC) -o $@ $< -O2 -c

test: $(TARGET)
	go test -v ./bls

clean:
	rm -rf bls.o $(TARGET)

CFLAGS=-Wall -std=c99
all: sha256

sha256: sha256.o

clean:
	rm -f sha256 sha256.o

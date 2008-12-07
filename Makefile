CC=g++
LDFLAGS=-lssl -lcrypto
all: mtpass mtdump
clean:
	rm -f mtpass mtdump core

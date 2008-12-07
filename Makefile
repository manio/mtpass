CC=g++
LDFLAGS=-lssl -lcrypto
all: mtpass
clean:
	rm -f mtpass core

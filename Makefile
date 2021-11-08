SH=/bin/sh
CC=${CROSS_COMPILE}gcc

all: peekpoke

peekpoke: peekpoke.c mapping.c
	$(CC) -Wall -O -o $@ $^

.PHONY: clean

clean:
	rm -f peekpoke

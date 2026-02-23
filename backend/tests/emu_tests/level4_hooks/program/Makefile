CC = gcc
CFLAGS = -O0 -g -fno-stack-protector

all: hooks complex

hooks: hooks.c
	$(CC) $(CFLAGS) -o $@ $<

complex: complex.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f hooks complex
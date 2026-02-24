CC = gcc
CFLAGS = -O0 -g -fno-stack-protector

all: hooks complex stack_overflow sub_hook

hooks: hooks.c
	$(CC) $(CFLAGS) -o $@ $<

complex: complex.c
	$(CC) $(CFLAGS) -o $@ $<

stack_overflow: stack_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

sub_hook: sub_hook.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f hooks complex stack_overflow sub_hook

CC = gcc
CFLAGS = -O0 -g -fno-stack-protector -no-pie

TARGET = hooks

all: $(TARGET)

$(TARGET): hooks.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
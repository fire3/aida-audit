CC = gcc
CFLAGS = -O0 -g -m64 -no-pie
TARGET = control
SRC = control.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
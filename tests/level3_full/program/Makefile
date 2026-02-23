CC = gcc
CFLAGS = -O0 -g -m64
TARGET = full
SRC = full.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
CC = gcc
CFLAGS = -O0 -g -m64
TARGET = add
SRC = add.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
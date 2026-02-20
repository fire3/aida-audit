CC = gcc
CFLAGS = -Wall -Wextra -std=c99
TARGET = microcode_test
SRC = microcode_test.c
STUB = external_func.c
BACKEND_DIR = ..

$(TARGET): $(SRC) $(STUB)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(STUB)

clean:
	rm -f $(TARGET)

.PHONY: clean
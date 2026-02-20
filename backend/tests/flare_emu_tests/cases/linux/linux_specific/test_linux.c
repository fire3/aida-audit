#include <stdio.h>

#define EXPORT __attribute__((visibility("default")))

EXPORT long get_long_size() {
    return sizeof(long);
}

EXPORT long add_longs(long a, long b) {
    return a + b;
}

// Add a function that is definitely not Windows
EXPORT int is_linux() {
    return 1;
}

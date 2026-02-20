#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define EXPORT __attribute__((visibility("default")))

// Vulnerable function: Buffer Overflow
// If input is larger than 16 bytes, it overflows buffer
EXPORT int vuln_strcpy(const char* input) {
    char buffer[16];
    // Intentionally unsafe strcpy
    strcpy(buffer, input);
    return 0;
}

// Function with multiple paths for coverage test
EXPORT int path_coverage(int a, int b) {
    if (a > 10) {
        if (b > 10) {
            return 1; // Path 1
        } else {
            return 2; // Path 2
        }
    } else {
        if (b > 10) {
            return 3; // Path 3
        } else {
            return 4; // Path 4
        }
    }
}

int main() {
    path_coverage(11, 11);
    return 0;
}

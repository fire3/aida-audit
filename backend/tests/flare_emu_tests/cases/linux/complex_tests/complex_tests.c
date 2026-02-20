#include <stdio.h>
//#include <string.h> // Do not include string.h to avoid conflicts or just don't use it
#include <stdlib.h>

#define EXPORT __attribute__((visibility("default")))

// 1. Global variables
int global_counter = 0; // .bss
int global_init = 123;  // .data
char global_buffer[100]; // .bss

EXPORT int get_constant() {
    return 42;
}

EXPORT int get_global_init() {
    return global_init;
}

EXPORT int get_global_counter() {
    return global_counter;
}

EXPORT void increment_global_counter() {
    global_counter++;
}

// Custom string functions to avoid IFUNC/libc issues in emulation without loader
int my_strlen(const char* str) {
    int len = 0;
    while (str[len]) len++;
    return len;
}

int my_strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

EXPORT void set_global_buffer(const char* str) {
    int i = 0;
    for (; i < 99 && str[i]; i++) {
        global_buffer[i] = str[i];
    }
    global_buffer[i] = '\0';
}

EXPORT const char* get_global_buffer() {
    return global_buffer;
}

EXPORT int get_global_buffer_first_char() {
    return (int)global_buffer[0];
}

// 2. Standard library calls (simulated with custom impl)
EXPORT int use_strlen(const char* str) {
    return my_strlen(str);
}

EXPORT int use_strcmp(const char* s1, const char* s2) {
    return my_strcmp(s1, s2);
}

// 3. String operations
EXPORT void reverse_string(char* str) {
    int len = my_strlen(str);
    for (int i = 0; i < len / 2; i++) {
        char temp = str[i];
        str[i] = str[len - 1 - i];
        str[len - 1 - i] = temp;
    }
}

// 4. Data structure operations
typedef struct Point {
    int x;
    int y;
} Point;

EXPORT int process_point(Point* p) {
    if (!p) return -1;
    p->x += 10;
    p->y += 20;
    return p->x + p->y;
}

// 5. Loops
EXPORT int sum_array(int* arr, int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return sum;
}

EXPORT int factorial_loop(int n) {
    int result = 1;
    for (int i = 1; i <= n; i++) {
        result *= i;
    }
    return result;
}

int main() {
    printf("Complex tests binary\n");
    return 0;
}

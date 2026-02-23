#include <stdio.h>
#include <stdint.h>

int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

int mul(int a, int b) {
    return a * b;
}

int div_int(int a, int b) {
    if (b == 0) return 0;
    return a / b;
}

int main() {
    printf("add(3, 5) = %d\n", add(3, 5));
    printf("sub(10, 3) = %d\n", sub(10, 3));
    printf("mul(4, 7) = %d\n", mul(4, 7));
    printf("div_int(20, 4) = %d\n", div_int(20, 4));
    return 0;
}
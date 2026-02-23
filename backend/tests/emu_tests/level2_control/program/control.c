#include <stdio.h>

int max(int a, int b) {
    if (a > b)
        return a;
    return b;
}

int min(int a, int b) {
    if (a < b)
        return a;
    return b;
}

int abs_val(int a) {
    if (a < 0)
        return -a;
    return a;
}

int factorial(int n) {
    if (n <= 1)
        return 1;
    return n * factorial(n - 1);
}

int fibonacci(int n) {
    if (n <= 1)
        return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

int main() {
    printf("max(3, 5) = %d\n", max(3, 5));
    printf("min(3, 5) = %d\n", min(3, 5));
    printf("abs_val(-5) = %d\n", abs_val(-5));
    printf("factorial(5) = %d\n", factorial(5));
    printf("fibonacci(6) = %d\n", fibonacci(6));
    return 0;
}
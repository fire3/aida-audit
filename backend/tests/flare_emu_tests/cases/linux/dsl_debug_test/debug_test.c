#include <stdio.h>
#include <string.h>

int nested_func(int a) {
    return a * 2;
}

int test_func(int a, int b) {
    int c = nested_func(a);
    return c + b;
}

void stack_test() {
    char buffer[100];
    memset(buffer, 0, 100);
}

int main() {
    test_func(10, 20);
    stack_test();
    return 0;
}

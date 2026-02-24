#include <stdio.h>

int sub_func(int a, int b) {
    return a * b;
}

int main() {
    int res = sub_func(10, 20);
    return res;
}

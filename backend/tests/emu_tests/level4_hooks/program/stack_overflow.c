#include <stdio.h>

int recursive_sum(int n) {
    if (n <= 0) return 0;
    int local_array[1024];
    local_array[0] = n;
    return n + recursive_sum(n - 1);
}

int main() {
    int result = recursive_sum(100);
    return result;
}
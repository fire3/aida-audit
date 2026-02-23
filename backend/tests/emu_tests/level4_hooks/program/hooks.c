#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int sum_array(int* arr, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) {
        sum += arr[i];
    }
    return sum;
}

int str_len(const char* s) {
    int len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

char* strdup_test(const char* s) {
    return strdup(s);
}

int atoi_test(const char* s) {
    return atoi(s);
}

void* malloc_test(size_t size) {
    return malloc(size);
}

int printf_test(int x, int y) {
    return printf("%d + %d = %d\n", x, y, x + y);
}

int main() {
    int arr[] = {1, 2, 3, 4, 5};
    int result = sum_array(arr, 5);
    
    const char* s = "hello";
    int len = str_len(s);
    
    char* dup = strdup_test("test");
    free(dup);
    
    int num = atoi_test("12345");
    
    void* p = malloc_test(100);
    free(p);
    
    printf_test(10, 20);
    
    return result + len + num;
}
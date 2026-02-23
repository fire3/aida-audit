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
    return strlen(s);
}

char* strdup_test(const char* s) {
    return strdup(s);
}

int atoi_test(const char* s) {
    return atoi(s);
}

int strcmp_test(const char* a, const char* b) {
    return strcmp(a, b);
}

int memcpy_test(const char* src) {
    char dest[32];
    memcpy(dest, src, strlen(src) + 1);
    return strlen(dest);
}

int memset_test(int val) {
    char buf[16];
    memset(buf, val, sizeof(buf));
    return buf[0];
}

void* malloc_test(size_t size) {
    return malloc(size);
}

int free_test(void* ptr) {
    free(ptr);
    return 0;
}

int main() {
    int arr[] = {1, 2, 3, 4, 5};
    int result = sum_array(arr, 5);
    
    const char* s = "hello";
    int len = strlen(s);
    
    char* dup = strdup_test("test");
    free(dup);
    
    int num = atoi_test("12345");
    
    int cmp = strcmp_test("hello", "world");
    
    int copied = memcpy_test("test_string");
    
    int filled = memset_test(0xAB);
    
    void* p = malloc_test(100);
    free(p);
    
    return result + len + num + cmp + copied + filled + 1;
}
#include <stdio.h>
#include <string.h>

int sum_array(int* arr, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) {
        sum += arr[i];
    }
    return sum;
}

int find_max(int* arr, int len) {
    if (len <= 0) return 0;
    int max_val = arr[0];
    for (int i = 1; i < len; i++) {
        if (arr[i] > max_val)
            max_val = arr[i];
    }
    return max_val;
}

int str_len(const char* s) {
    int len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

int str_cmp(const char* a, const char* b) {
    while (*a && *b) {
        if (*a != *b) break;
        a++;
        b++;
    }
    return *a - *b;
}

void str_copy(char* dest, const char* src) {
    int i = 0;
    while (src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

int main() {
    int arr[] = {1, 2, 3, 4, 5};
    printf("sum_array = %d\n", sum_array(arr, 5));
    printf("find_max = %d\n", find_max(arr, 5));
    
    const char* s = "hello";
    printf("str_len = %zu\n", strlen(s));
    printf("str_cmp(hello, hello) = %d\n", str_cmp("hello", "hello"));
    
    return 0;
}
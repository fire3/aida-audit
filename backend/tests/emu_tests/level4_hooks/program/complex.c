#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    char name[32];
    int age;
    int score;
} Student;

int string_to_number(const char* s) {
    int result = 0;
    int sign = 1;
    
    if (*s == '-') {
        sign = -1;
        s++;
    }
    
    while (*s >= '0' && *s <= '9') {
        result = result * 10 + (*s - '0');
        s++;
    }
    
    return result * sign;
}

int compare_strings(const char* a, const char* b) {
    while (*a && *b) {
        if (*a != *b) {
            return *a - *b;
        }
        a++;
        b++;
    }
    return *a - *b;
}

int find_max_in_array(int* arr, int len) {
    if (len <= 0) return 0;
    
    int max = arr[0];
    for (int i = 1; i < len; i++) {
        if (arr[i] > max) {
            max = arr[i];
        }
    }
    return max;
}

int sum_of_positive(int* arr, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) {
        if (arr[i] > 0) {
            sum += arr[i];
        }
    }
    return sum;
}

int count_matches(const char* str, char c) {
    int count = 0;
    while (*str) {
        if (*str == c) {
            count++;
        }
        str++;
    }
    return count;
}

void reverse_string(char* dest, const char* src, int len) {
    for (int i = 0; i < len; i++) {
        dest[i] = src[len - 1 - i];
    }
    dest[len] = '\0';
}

int process_student(Student* s, const char* name, int age, int score) {
    int name_len = strlen(name);
    if (name_len >= 32) name_len = 31;
    
    for (int i = 0; i < name_len; i++) {
        s->name[i] = name[i];
    }
    s->name[name_len] = '\0';
    
    s->age = age;
    s->score = score;
    
    return name_len + age + score;
}

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

int binary_search(int* arr, int len, int target) {
    int left = 0;
    int right = len - 1;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (arr[mid] == target) {
            return mid;
        }
        if (arr[mid] < target) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return -1;
}

int main() {
    int result = 0;
    
    result += string_to_number("12345");
    result += string_to_number("-987");
    
    result += compare_strings("apple", "banana");
    result += compare_strings("hello", "hello");
    
    int arr1[] = {5, 2, 8, 1, 9, 3};
    result += find_max_in_array(arr1, 6);
    
    int arr2[] = {-5, 2, -8, 1, 9, -3};
    result += sum_of_positive(arr2, 6);
    
    result += count_matches("hello world", 'l');
    
    char reversed[32];
    reverse_string(reversed, "hello", 5);
    result += strlen(reversed);
    
    Student stu;
    result += process_student(&stu, "Alice", 20, 95);
    
    result += factorial(5);
    result += fibonacci(7);
    
    int sorted[] = {1, 3, 5, 7, 9, 11, 13, 15};
    result += binary_search(sorted, 8, 7);
    result += binary_search(sorted, 8, 100);
    
    return result;
}
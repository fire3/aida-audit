
#include <stdio.h>
#include <string.h>

// Simple arithmetic test
// Arguments: a, b
// Returns: a + b
__declspec(dllexport) int test_add(int a, int b) {
    return a + b;
}

// Memory read test
// Arguments: str
// Returns: length of string
__declspec(dllexport) int test_strlen(const char* str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

// Memory write test (XOR encryption)
// Arguments: buf (in/out), len, key
// Returns: void (buf is modified in place)
__declspec(dllexport) void test_xor_crypt(char* buf, int len, char key) {
    for (int i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

// Control flow test (Fibonacci)
// Arguments: n
// Returns: nth fibonacci number
__declspec(dllexport) int test_fib(int n) {
    if (n <= 1) return n;
    return test_fib(n - 1) + test_fib(n - 2);
}

// Stack test
// Arguments: a, b, c, d, e, f (needs stack for >4 args on x64 windows, or >6 on linux)
// Returns: sum
__declspec(dllexport) int test_many_args(int a, int b, int c, int d, int e, int f) {
    return a + b + c + d + e + f;
}

// Complex path test
// Arguments: val
// Returns: based on conditions
__declspec(dllexport) int test_complex_path(int val) {
    int result = 0;
    if (val > 100) {
        result = val * 2;
    } else if (val < 0) {
        result = -val;
    } else {
        for (int i = 0; i < val; i++) {
            result += i;
        }
    }
    return result;
}

int main() {
    // Just to ensure code is referenced and linked properly if compiled as exe
    printf("Add: %d\n", test_add(10, 20));
    return 0;
}

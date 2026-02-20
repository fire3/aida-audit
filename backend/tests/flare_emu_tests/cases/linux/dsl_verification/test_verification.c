#include <stdio.h>
#include <string.h>

#define EXPORT __attribute__((visibility("default")))

// Test 1: Simple return value
EXPORT int test_ret_val() {
    return 42;
}

// Test 2: Local variable modification and check
// We will use a hook to inspect 'local_var' before function returns
EXPORT int test_local_var(int input) {
    int local_var = input * 2;
    // We can't easily rely on line numbers, but we can hook the return instruction
    // or an instruction after calculation.
    // For simplicity, let's call a dummy function to make it easy to hook.
    return local_var;
}

// Test 3: Memory manipulation
EXPORT void test_memory_write(char* buffer) {
    strcpy(buffer, "modified");
}

// Test 4: Register usage (simulation)
// We'll hook this function and modify a register to change return value
EXPORT int test_register_hook() {
    return 0;
}

int main() {
    printf("%d\n", test_ret_val());
    return 0;
}

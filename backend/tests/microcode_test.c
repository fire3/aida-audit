/*
 * IDA Microcode Comprehensive Test Suite
 * Purpose: Generate diverse microcode instructions for testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <float.h>
#include <stdarg.h>

/* Global variables for testing */
int global_int = 42;
unsigned int global_uint = 100;
long global_long = -1000;
char global_char = 'A';
float global_float = 3.14f;
double global_double = 2.718;
void *global_ptr = NULL;
int global_array[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

/* Structure for testing */
struct TestStruct {
    int a;
    long b;
    char c;
    float d;
    int *ptr;
};

struct NestedStruct {
    int x;
    struct TestStruct inner;
    int y;
};

struct TestStruct global_struct = {1, 2, 'X', 1.5f, &global_int};
struct NestedStruct global_nested = {10, {20, 30, 'Y', 2.5f, NULL}, 40};

/* Pointer to function */
typedef int (*func_ptr_t)(int);

/* External function declaration */
extern int external_func(int a, int b);
int callback_func(int x) {
    return x * 2;
}

/* ============================================
 * Test Case 1: Basic Arithmetic Operations
 * ============================================ */
int test_arithmetic(int a, int b) {
    int result;
    
    /* Addition */
    result = a + b;
    result = a + 100;
    result = 200 + b;
    result = a + b + 50;
    
    /* Subtraction */
    result = a - b;
    result = a - 100;
    result = 200 - b;
    
    /* Multiplication */
    result = a * b;
    result = a * 2;
    result = 3 * b;
    
    /* Division */
    result = a / b;
    if (b != 0) result = a / b;
    result = a / 4;
    
    /* Modulo */
    result = a % b;
    result = a % 10;
    
    /* Negation */
    result = -a;
    result = -(-a);
    
    /* Increment/Decrement */
    result = a++;
    result = ++a;
    result = b--;
    result = --b;
    
    return result;
}

/* ============================================
 * Test Case 2: Bitwise Operations
 * ============================================ */
unsigned int test_bitwise(unsigned int x, unsigned int y) {
    unsigned int result;
    
    /* AND */
    result = x & y;
    result = x & 0xFF;
    result = 0xFF & y;
    
    /* OR */
    result = x | y;
    result = x | 0xFF;
    
    /* XOR */
    result = x ^ y;
    result = x ^ 0xFF;
    
    /* NOT */
    result = ~x;
    result = ~0xFFFF;
    
    /* Shift Left */
    result = x << 2;
    result = x << y;
    result = x << 4;
    
    /* Shift Right (logical) */
    result = x >> 2;
    result = x >> y;
    
    /* Shift Right (arithmetic) - signed */
    int neg = -8;
    int arith_shift = neg >> 2;
    
    return result;
}

/* ============================================
 * Test Case 3: Comparison Operations
 * ============================================ */
int test_comparison(int a, int b) {
    int result = 0;
    
    /* Equality */
    if (a == b) result = 1;
    if (a == 100) result = 2;
    if (200 == b) result = 3;
    
    /* Inequality */
    if (a != b) result = 1;
    if (a != 100) result = 2;
    
    /* Greater than */
    if (a > b) result = 1;
    if (a > 100) result = 2;
    if (200 > b) result = 3;
    
    /* Less than */
    if (a < b) result = 1;
    if (a < 100) result = 2;
    if (200 < b) result = 3;
    
    /* Greater than or equal */
    if (a >= b) result = 1;
    if (a >= 100) result = 2;
    
    /* Less than or equal */
    if (a <= b) result = 1;
    if (a <= 100) result = 2;
    
    /* Logical NOT */
    result = !a;
    result = !(a == b);
    
    return result;
}

/* ============================================
 * Test Case 4: Logical Operations
 * ============================================ */
int test_logical(int a, int b) {
    int result;
    
    /* Logical AND */
    result = (a > 0) && (b > 0);
    result = (a == 5) && (b == 10);
    
    /* Logical OR */
    result = (a > 0) || (b > 0);
    result = (a == 0) || (b == 0);
    
    /* Combined */
    result = (a > 0) && (b > 0) || (a < b);
    result = (a || b) && (a && b);
    
    return result;
}

/* ============================================
 * Test Case 5: Conditional Branching
 * ============================================ */
int test_conditional_branching(int x, int y) {
    int result = 0;
    
    /* Simple if */
    if (x > 0) {
        result = 1;
    }
    
    /* If-else */
    if (x > y) {
        result = 1;
    } else {
        result = 2;
    }
    
    /* Else-if chain */
    if (x > 100) {
        result = 1;
    } else if (x > 50) {
        result = 2;
    } else if (x > 0) {
        result = 3;
    } else {
        result = 0;
    }
    
    /* Nested conditions */
    if (x > 0) {
        if (y > 0) {
            result = x + y;
        } else {
            result = x - y;
        }
    }
    
    return result;
}

/* ============================================
 * Test Case 6: Switch Statement
 * ============================================ */
int test_switch(int value) {
    int result = 0;
    
    switch (value) {
        case 0:
            result = 0;
            break;
        case 1:
            result = 1;
            break;
        case 2:
            result = 2;
            break;
        case 3:
            result = 3;
            break;
        case 4:
            result = 4;
            break;
        default:
            result = -1;
    }
    
    /* Switch with fall-through */
    switch (value) {
        case 10:
        case 11:
        case 12:
            result = 100;
            break;
        default:
            result = 0;
    }
    
    return result;
}

/* ============================================
 * Test Case 7: Loops
 * ============================================ */
int test_loops(int n) {
    int sum = 0;
    int i;
    
    /* While loop */
    i = 0;
    while (i < n) {
        sum += i;
        i++;
    }
    
    /* Do-while loop */
    i = 0;
    do {
        sum += i * 2;
        i++;
    } while (i < n);
    
    /* For loop */
    for (i = 0; i < n; i++) {
        sum += i * i;
    }
    
    /* For loop with multiple variables */
    for (i = 0, sum = 0; i < n; i++, sum += i) {
        /* Empty body */
    }
    
    /* Nested loops */
    for (i = 0; i < 3; i++) {
        int j;
        for (j = 0; j < 3; j++) {
            sum += i * j;
        }
    }
    
    /* Break and continue */
    for (i = 0; i < n; i++) {
        if (i == 5) break;
        if (i % 2 == 0) continue;
        sum += i;
    }
    
    return sum;
}

/* ============================================
 * Test Case 8: Function Calls
 * ============================================ */
int test_function_calls(int a, int b) {
    int result;
    
    /* Direct function call */
    result = external_func(a, b);
    
    /* Function call with expressions */
    result = external_func(a + 1, b * 2);
    
    /* Function call with mixed arguments */
    result = external_func(a, 100);
    result = external_func(50, b);
    
    /* Nested function calls */
    result = external_func(external_func(1, 2), external_func(3, 4));
    
    /* Callback function */
    func_ptr_t fp = callback_func;
    result = fp(a);
    
    return result;
}

/* ============================================
 * Test Case 9: Recursive Function
 * ============================================ */
int test_recursion(int n) {
    if (n <= 0) {
        return 0;
    }
    if (n == 1) {
        return 1;
    }
    return n + test_recursion(n - 1);
}

/* ============================================
 * Test Case 10: Pointer Operations
 * ============================================ */
int test_pointers(int *ptr_in) {
    int local = 100;
    int *ptr = &local;
    int **pptr = &ptr;
    int result = 0;
    
    /* Pointer dereference */
    result = *ptr;
    
    /* Pointer assignment */
    ptr = ptr_in;
    
    /* Address-of */
    result = *(&local);
    
    /* Pointer arithmetic */
    int arr[10] = {0};
    int *arr_ptr = arr;
    result = *(arr_ptr + 5);
    result = *(arr_ptr++);
    result = *(++arr_ptr);
    
    /* Double pointer */
    result = **pptr;
    
    /* Pointer comparison */
    if (ptr < &local) result = 1;
    if (ptr == ptr_in) result = 2;
    if (ptr != NULL) result = 3;
    
    /* Offset pointer */
    char *byte_ptr = (char *)ptr_in;
    result = *(int *)(byte_ptr + 4);
    
    return result;
}

/* ============================================
 * Test Case 11: Array Operations
 * ============================================ */
int test_arrays(int index) {
    int arr1[5] = {1, 2, 3, 4, 5};
    int arr2[5];
    int result = 0;
    int i;
    
    /* Array access */
    result = arr1[0];
    result = arr1[4];
    result = arr1[index];
    
    /* Array assignment */
    arr2[0] = arr1[0];
    arr2[1] = arr1[1];
    
    /* Multi-dimensional array */
    int matrix[3][3] = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
    result = matrix[0][0];
    result = matrix[2][2];
    result = matrix[index][index];
    
    /* Array in struct */
    struct {int arr[4];} s = {{10, 20, 30, 40}};
    result = s.arr[0];
    result = s.arr[3];
    
    /* Array length macro usage */
    int arr3[10];
    for (i = 0; i < 10; i++) {
        arr3[i] = i;
    }
    
    /* Pointer to array */
    int (*ptr_to_arr)[5] = &arr1;
    result = (*ptr_to_arr)[2];
    
    return result;
}

/* ============================================
 * Test Case 12: Structure Operations
 * ============================================ */
int test_structures(int val) {
    struct TestStruct s;
    struct TestStruct *s_ptr = &s;
    int result = 0;
    
    /* Structure member access */
    s.a = val;
    s.b = val * 2;
    s.c = 'Z';
    s.d = 1.0f;
    s.ptr = &global_int;
    
    result = s.a + s.b;
    
    /* Pointer to structure */
    s_ptr->a = val;
    s_ptr->b = val * 3;
    
    /* Nested structure */
    struct NestedStruct ns;
    ns.x = 100;
    ns.inner.a = val;
    ns.inner.ptr = &val;
    ns.y = 200;
    
    result = ns.inner.a + ns.y;
    
    /* Structure assignment */
    struct TestStruct s2 = s;
    result = s2.a;
    
    /* Structure array */
    struct TestStruct arr[3];
    arr[0].a = 1;
    arr[1].a = 2;
    arr[2].a = 3;
    result = arr[0].a + arr[1].a + arr[2].a;
    
    /* Bit fields */
    struct {
        unsigned int a: 4;
        unsigned int b: 8;
        unsigned int c: 4;
    } bf = {0xA, 0xFF, 0x5};
    result = bf.a + bf.b + bf.c;
    
    return result;
}

/* ============================================
 * Test Case 13: Stack Operations
 * ============================================ */
int test_stack(int a, int b, int c) {
    int local1 = a;
    int local2 = b;
    int local3 = c;
    int result;
    
    /* All local variables used */
    result = local1 + local2 + local3;
    
    /* Reference to stack variable */
    int *ptr1 = &local1;
    int *ptr2 = &local2;
    
    result = *ptr1 + *ptr2;
    
    /* Stack address in expression */
    result = (int)&local1;
    
    /* Large local array */
    int large[100];
    large[0] = a;
    large[99] = b;
    result = large[0] + large[99];
    
    return result;
}

/* ============================================
 * Test Case 14: Type Casting
 * ============================================ */
int test_type_casting(int a, double d) {
    int result;
    
    /* Integer to double */
    double d_from_int = (double)a;
    
    /* Double to integer */
    int i_from_double = (int)d;
    
    /* Unsigned to signed */
    unsigned int ui = 0xFFFFFFFF;
    int si = (int)ui;
    
    /* Pointer casting */
    int *int_ptr = &a;
    char *char_ptr = (char *)int_ptr;
    void *void_ptr = (void *)int_ptr;
    
    /* Sizeof in expression */
    result = sizeof(int) + sizeof(long) + sizeof(void *);
    
    /* Cast in arithmetic */
    result = (int)(d + 0.5);
    
    return result;
}

/* ============================================
 * Test Case 15: Floating Point Operations
 * ============================================ */
double test_floating_point(float f, double d) {
    double result;
    
    /* Float operations */
    result = f + 1.0f;
    result = f - 2.0f;
    result = f * 3.0f;
    result = f / 4.0f;
    
    /* Double operations */
    result = d + 1.0;
    result = d - 2.0;
    result = d * 3.0;
    result = d / 4.0;
    
    /* Mixed float/double */
    result = f + d;
    result = f * d;
    
    /* Comparison */
    if (f > d) result = f;
    else result = d;
    
    /* Float constants */
    result = 3.14159;
    result = 2.718281828;
    
    /* Negative floats */
    result = -f;
    result = -d;
    
    return result;
}

/* ============================================
 * Test Case 16: String Operations
 * ============================================ */
int test_strings(char *str1, char *str2) {
    char local1[100] = "hello";
    char local2[100];
    char *ptr;
    int result = 0;
    
    /* String literal */
    const char *lit = "test string";
    result = lit[0];
    
    /* String in local array */
    result = local1[0];
    result = local1[4];
    
    /* String assignment */
    strcpy(local2, local1);
    result = local2[0];
    
    /* String comparison */
    if (strcmp(str1, str2) == 0) result = 1;
    if (strcmp(local1, "hello") == 0) result = 2;
    
    /* String length */
    result = strlen(str1);
    result = strlen("constant");
    
    /* String concatenation */
    strcat(local1, " world");
    
    /* Character access */
    result = str1[0];
    result = str1[strlen(str1) - 1];
    
    return result;
}

/* ============================================
 * Test Case 17: Comma Operator
 * ============================================ */
int test_comma(int a, int b) {
    int result;
    
    /* Comma in expression */
    result = (a++, b++, a + b);
    
    /* Comma in for loop */
    for (result = 0, a = 0; a < 5; a++, result += a) {
        /* Empty */
    }
    
    /* Comma as separator */
    result = (a = 1, b = 2, a + b);
    
    return result;
}

/* ============================================
 * Test Case 18: Ternary Operator
 * ============================================ */
int test_ternary(int a, int b) {
    int result;
    
    /* Simple ternary */
    result = (a > b) ? a : b;
    
    /* Nested ternary */
    result = (a > 100) ? 1 : (b > 50) ? 2 : 3;
    
    /* Ternary with assignments */
    int x;
    x = (a > 0) ? a : -a;
    
    /* Ternary in expression */
    result = (a > b) ? a + b : a - b;
    
    return result;
}

/* ============================================
 * Test Case 19: Compound Assignment
 * ============================================ */
int test_compound(int a, int b) {
    int result = 10;
    
    result += a;
    result -= b;
    result *= 2;
    result /= 2;
    result %= 5;
    
    result &= 0xFF;
    result |= 0x0F;
    result ^= 0x0F;
    result <<= 2;
    result >>= 1;
    
    return result;
}

/* ============================================
 * Test Case 20: Goto Statement
 * ============================================ */
int test_goto(int n) {
    int result = 0;
    int i;
    
    if (n <= 0) goto end;
    
    for (i = 0; i < n; i++) {
        result += i;
        if (result > 100) goto overflow;
    }
    
    result *= 2;
    goto end;
    
overflow:
    result = -1;
    
end:
    return result;
}

/* ============================================
 * Test Case 21: Volatile and Const
 * ============================================ */
int test_volatile_const(volatile int v, const int c) {
    int result = 0;
    
    /* Volatile read */
    result = v;
    result = v + 1;
    
    /* Const read */
    result = c;
    result = c * 2;
    
    /* Multiple volatile */
    volatile int v2 = 0;
    result = v + v2;
    
    return result;
}

/* ============================================
 * Test Case 22: Bit Manipulation Macros
 * ============================================ */
#define BIT_MASK(n) (1 << n)
#define GET_BIT(v, n) ((v) >> (n) & 1)
#define SET_BIT(v, n) ((v) | (1 << (n)))
#define CLEAR_BIT(v, n) ((v) & ~(1 << (n)))
#define TOGGLE_BIT(v, n) ((v) ^ (1 << (n)))

int test_macros(int value, int bit) {
    int result;
    
    result = BIT_MASK(bit);
    result = GET_BIT(value, bit);
    result = SET_BIT(value, bit);
    result = CLEAR_BIT(value, bit);
    result = TOGGLE_BIT(value, bit);
    
    return result;
}

/* ============================================
 * Test Case 23: Inline Assembly
 * ============================================ */
int test_inline_asm(int a, int b) {
    int result;
    
    /* Simple asm */
    __asm__ volatile ("mov %1, %%eax\n\t"
                      "add %2, %%eax\n\t"
                      "mov %%eax, %0"
                      : "=r" (result)
                      : "r" (a), "r" (b)
                      : "eax");
    
    /* Another asm */
    __asm__ volatile ("xor %0, %0" : "=r" (result));
    
    return result;
}

/* ============================================
 * Test Case 24: Ellipsis (Variadic)
 * ============================================ */
int test_variadic(int count, ...) {
    int result = 0;
    va_list args;
    int i;
    
    va_start(args, count);
    for (i = 0; i < count; i++) {
        result += va_arg(args, int);
    }
    va_end(args);
    
    return result;
}

/* ============================================
 * Test Case 25: Complex Expressions
 * ============================================ */
int test_complex_expressions(int a, int b, int c) {
    int result;
    
    /* Chained arithmetic */
    result = a + b * c - a / b + c % a;
    
    /* Complex logical */
    result = (a > 0 && b < 100) || (c == 0) || (a + b > c);
    
    /* Mixed pointer and arithmetic */
    int arr[10];
    int *p = arr;
    result = *(p + a) + *(p + b);
    
    /* Address calculations */
    result = (int)&arr[a] - (int)&arr[0];
    
    /* Cast in complex expression */
    result = (int)((double)a * b + (double)c / 2);
    
    return result;
}

/* ============================================
 * Test Case 26: Union Operations
 * ============================================ */
union TestUnion {
    int i;
    float f;
    char c[4];
};

int test_union(union TestUnion *u) {
    int result = 0;
    
    u->i = 42;
    result = u->i;
    
    u->f = 3.14f;
    result = (int)u->f;
    
    u->c[0] = 'A';
    u->c[1] = 'B';
    result = u->c[0] + u->c[1];
    
    return result;
}

/* ============================================
 * Test Case 27: Global and Static Variables
 * ============================================ */
static int static_var = 100;

int test_static_globals(void) {
    int result = 0;
    
    /* Static local variable */
    static int call_count = 0;
    call_count++;
    
    /* Global variable access */
    result = global_int;
    result += global_array[0];
    
    /* Static variable access */
    result += static_var;
    
    /* Pointer to global */
    int *ptr = &global_int;
    result = *ptr;
    
    return result;
}

/* ============================================
 * Test Case 28: Longjmp/Setjmp
 * ============================================ */
#include <setjmp.h>

jmp_buf jump_buffer;

int test_setjmp(int value) {
    int result;
    
    result = setjmp(jump_buffer);
    
    if (result == 0) {
        /* First time */
        if (value > 0) {
            /* Will longjmp later */
        }
    } else {
        /* Returned from longjmp */
        result = value * 2;
    }
    
    return result;
}

void trigger_longjmp(int value) {
    longjmp(jump_buffer, value);
}

/* ============================================
 * Test Case 29: Multi-file compilation test
 * ============================================ */
int helper_function(int x) {
    return x * x + 1;
}

int test_helper_calls(int a, int b) {
    return helper_function(a) + helper_function(b);
}

/* ============================================
 * Test Case 30: Memory Operations
 * ============================================ */
int test_memory_operations(char *buf, int size) {
    int result = 0;
    char local_buf[100];
    int i;
    
    /* memset-like */
    for (i = 0; i < size && i < 100; i++) {
        local_buf[i] = 0;
    }
    
    /* memcpy-like */
    for (i = 0; i < size && i < 100; i++) {
        local_buf[i] = buf[i];
    }
    
    /* memcmp-like */
    for (i = 0; i < size && i < 100; i++) {
        if (local_buf[i] != buf[i]) {
            result = local_buf[i] - buf[i];
            break;
        }
    }
    
    /* Pointer to buffer element */
    char *elem_ptr = &buf[0];
    result = *elem_ptr;
    
    return result;
}

/* ============================================
 * Main entry point
 * ============================================ */
int main(void) {
    int a, b, c, result;
    
    a = 10;
    b = 20;
    c = 30;
    
    /* Call all test functions to ensure compilation */
    result = test_arithmetic(a, b);
    result = test_bitwise((unsigned int)a, (unsigned int)b);
    result = test_comparison(a, b);
    result = test_logical(a, b);
    result = test_conditional_branching(a, b);
    result = test_switch(c);
    result = test_loops(10);
    result = test_function_calls(a, b);
    result = test_recursion(5);
    result = test_pointers(&a);
    result = test_arrays(c % 10);
    result = test_structures(a);
    result = test_stack(a, b, c);
    result = test_type_casting(a, 3.14);
    result = (int)test_floating_point(1.5f, 2.5);
    result = test_strings("hello", "world");
    result = test_comma(a, b);
    result = test_ternary(a, b);
    result = test_compound(a, b);
    result = test_goto(10);
    result = test_volatile_const(a, b);
    result = test_macros(a, 3);
    result = test_inline_asm(a, b);
    result = test_variadic(3, 1, 2, 3);
    result = test_complex_expressions(a, b, c);
    
    union TestUnion u;
    result = test_union(&u);
    
    result = test_static_globals();
    result = test_setjmp(5);
    result = test_helper_calls(a, b);
    char local_buf[100];
    result = test_memory_operations(local_buf, 10);
    
    printf("All tests completed. Result: %d\n", result);
    
    return 0;
}
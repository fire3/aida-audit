# Test new DSL debugging features

# 1. Enable call tracing
option trace_calls = true

# 2. Log message with variable
$start_msg = alloc("Starting debug test")
log "Test initialized: $start_msg"

# 3. Call function and check return value logging
# test_func(10, 20) should return 40
# nested_func(10) -> 20
log "Calling test_func(10, 20)..."
$res = call test_func(10, 20)

# 4. Log the result
log "Result received: $res"

# 5. Assert the result
assert $res == 40

# 6. Check stack integrity on a void function
log "Calling stack_test()..."
call stack_test()
log "Stack test done"

# 7. Check memory allocation and write
$buf = alloc(64)
write mem[$buf] = "test data"
assert mem[$buf] == "test data"
log "Memory check passed"

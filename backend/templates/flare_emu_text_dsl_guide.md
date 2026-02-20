# Flare-Emu Text DSL 规范

为了提供更简洁的测试编写体验，我们设计了一套基于文本的 DSL。该 DSL 旨在替代冗长的 JSON 格式，采用类似脚本语言的语法。

## 基础语法

- **注释**: 以 `#` 开头的行。
- **变量**: 以 `$` 开头，如 `$ptr`, `$result`。
- **数值**: 支持十进制 (`10`) 和十六进制 (`0x1a`)。
- **字符串**: 双引号包围 `"string"`。

## 指令集

### 1. 内存分配 (alloc)
```
$var = alloc(SIZE)
$var = alloc("STRING_CONTENT")
$var = alloc(hex"AABBCC")
```

### 2. 函数调用 (call)
```
# 基本调用
call function_name(arg1, arg2, ...)

# 获取返回值
$res = call function_name(...)

# 带 Hook 的调用
$res = call function_name(...) {
    hook addr_or_name {
        action: write_reg reg.eax = 0
    }
    hook 0x1234 {
        action: skip
    }
}
```

### 3. 写操作 (write)
```
write reg.name = value
write mem[$ptr] = value
write mem[0x1000] = "string"
```

### 4. 模拟执行 (emulate)
```
emulate start_addr, end_addr
# 限制指令数
emulate start, end count=100
```

### 5. 断言 (assert)
```
assert $var == value
assert reg.name == value
assert mem[$ptr] == "expected_content"
assert mem[0x1000] == hex"AABB"
```

### 6. 选项 (option)
```
option coverage = true
option trace = true
```

### 7. 报告 (report)
```
report "filename.json"
# 包含 trace
report "filename.json" include_trace=true
```

## Hook 语法
Hook 定义在 `call` 或 `emulate` 的代码块中。

```
hook <target_addr> {
    action: write_reg reg.<name> = <value>
    action: read_reg reg.<name> -> $var
    action: read_mem mem[<addr>] size=<len> -> $var
    action: skip
    action: stop
}
```

## 示例脚本

```python
# 开启覆盖率
option coverage = true

# 分配内存
$buf = alloc("hello")

# 调用函数
$len = call strlen($buf)

# 验证结果
assert $len == 5

# Hook 示例
$res = call test_add(10, 20) {
    # 修改返回值
    hook test_add {
        action: write_reg reg.eax = 999
    }
}
assert $res == 999
```

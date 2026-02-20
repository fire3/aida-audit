# Flare-Emu Text DSL 指南

本文档详细介绍了 **Flare-Emu Text DSL** 的语法和特性。这套文本 DSL 旨在提供一种简洁、直观的方式来编写二进制仿真场景，支持函数调用、内存操作、变量管理以及结果验证。

## 目录

1. [概述](#概述)
2. [DSL 语法](#dsl-语法)
   - [变量系统](#变量系统)
   - [选项配置 (Option)](#选项配置-option)
   - [内存分配 (Alloc)](#内存分配-alloc)
   - [写入操作 (Write)](#写入操作-write)
   - [函数调用 (Call)](#函数调用-call)
   - [Hook 系统](#hook-系统)
   - [模拟执行 (Emulate)](#模拟执行-emulate)
   - [断言验证 (Assert)](#断言验证-assert)
   - [生成报告 (Report)](#生成报告-report)
   - [日志记录 (Log)](#日志记录-log)
3. [完整示例](#完整示例)

## 概述

Flare-Emu Text DSL 是一种脚本化的声明式语言，用于定义仿真器的执行步骤。它通常作为 `.dsl` 文件编写，并通过测试框架加载执行。

## DSL 语法

### 变量系统

变量以 `$` 开头，用于存储内存地址、函数返回值或计算结果。

*   **定义变量**: `$var = ...`
*   **使用变量**: 在参数或断言中直接使用 `$var`。

### 选项配置 (Option)

开启或关闭全局仿真特性。

```text
option coverage = true   # 开启代码覆盖率收集
option trace = true      # 开启指令执行跟踪
option trace_mem = true  # 开启内存访问跟踪
option trace_calls = true # 开启函数调用跟踪
option stack_check = true # 开启堆栈完整性检查
```

### 内存分配 (Alloc)

在模拟器内存中分配空间，并可初始化内容。

**语法**:
*   `$var = alloc(SIZE)`: 分配指定大小（字节）的内存。
*   `$var = alloc("STRING")`: 分配内存并写入字符串（自动计算大小，包含 null 结尾）。
*   `$var = alloc(hex"AABBCC")`: 分配内存并写入十六进制数据。

**示例**:
```text
$buf = alloc(1024)
$str = alloc("Hello World")
$bytes = alloc(hex"11223344")
```

### 写入操作 (Write)

直接修改寄存器或内存。

**语法**:
*   `write reg.NAME = VALUE`: 修改寄存器。
*   `write mem[ADDR] = VALUE`: 修改内存。

**示例**:
```text
write reg.eax = 0x100
write mem[$buf] = "New Data"
write mem[0x400000] = hex"909090"
```

### 函数调用 (Call)

调用二进制文件中的导出函数或指定地址的函数。

**语法**:
*   `call FUNC_NAME(ARG1, ARG2, ...)`: 调用函数，不保存返回值。
*   `$res = call FUNC_NAME(...)`: 调用函数并将返回值保存到 `$res`。

**参数支持**:
*   整数: `10`, `0x10`
*   字符串: `"hello"` (会自动分配临时内存并传入指针)
*   十六进制字节: `hex"1122"` (自动分配内存并传入指针)
*   变量: `$var` (通常作为指针传递)

**示例**:
```text
call printf("Result: %d\n", 100)
$len = call strlen("test string")
$res = call my_add(10, 20)
```

### Hook 系统

在 `call` 或 `emulate` 语句后可以附加 Hook 代码块，用于在特定地址或函数入口/出口拦截执行。

**语法**:
```text
call FUNC_NAME(...) {
    hook ADDRESS_OR_NAME {
        action: ACTION_TYPE PARAMS...
    }
}
```

**支持的 Action**:
*   `write_reg reg.NAME = VALUE`: 修改寄存器。
*   `read_reg reg.NAME -> $VAR`: 读取寄存器到变量。
*   `read_mem mem[ADDR] size=N -> $VAR`: 读取内存到变量。
*   `skip`: 跳过当前指令。
*   `stop`: 停止模拟。

**示例**:
```text
$res = call test_add(10, 20) {
    # 在 test_add 函数入口处修改 edi 寄存器 (第一个参数)
    hook test_add {
        action: write_reg reg.edi = 100
    }
}
# 此时结果应该是 100 + 20 = 120
assert $res == 120
```

### 模拟执行 (Emulate)

模拟指定范围的指令，比 `call` 更底层的控制。

**语法**:
`emulate START, END, [count=N]`

**示例**:
```text
emulate 0x401000, 0x401050
emulate 0x401000, 0x401050, count=100
```

### 断言验证 (Assert)

验证模拟结果是否符合预期。

**语法**:
*   `assert $VAR == VALUE`: 验证变量值。
*   `assert reg.NAME == VALUE`: 验证寄存器值。
*   `assert mem[ADDR] == "CONTENT"`: 验证内存内容（支持 hex"..."）。

**示例**:
```text
assert $res == 30
assert reg.eax == 0
assert mem[$str] == "Hello World"
assert mem[$buf] == hex"112233"
```

### 生成报告 (Report)

将分析结果（覆盖率、Trace 等）输出到文件。

**语法**:
`report "FILENAME" [include_trace=true]`

**示例**:
```text
report "coverage.json"
report "trace.json" include_trace=true
```

### 日志记录 (Log)

输出日志信息，支持变量插值。

**语法**:
`log "MESSAGE"`

**示例**:
```text
log "Starting emulation..."
log "Result is $res"
```

## 完整示例

**complex.dsl**:
```text
# 开启追踪
option trace = true

# 准备数据
$input = alloc("Sensitive Data")
$output = alloc(128)

# 调用处理函数
# 假设 process(input_ptr, output_ptr)
$ret = call process_data($input, $output) {
    # Hook 监控关键点
    hook 0x401234 {
        action: read_reg reg.eax -> $mid_val
    }
}

# 验证结果
assert $ret == 0
assert mem[$output] == "Encrypted: Sensitive Data"

# 输出报告
report "analysis_result.json" include_trace=true
```

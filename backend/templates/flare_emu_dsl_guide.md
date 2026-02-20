# Flare-Emu DSL 指南

本文档详细介绍了如何使用 Flare-Emu DSL 来驱动二进制仿真测试。这套 DSL 旨在提供一种简单但表达能力强的方式来编写仿真场景，支持函数调用、内存操作、变量管理以及结果验证。

## 目录

1. [概述](#概述)
2. [基本结构](#基本结构)
3. [变量系统](#变量系统)
4. [步骤详解](#步骤详解)
   - [call (函数调用)](#call-函数调用)
   - [alloc (内存分配)](#alloc-内存分配)
   - [write (写入操作)](#write-写入操作)
   - [emulate (模拟执行)](#emulate-模拟执行)
   - [assert (断言验证)](#assert-断言验证)
5. [Hook 系统](#hook-系统)
   - [修改执行流](#修改执行流)
   - [捕获局部状态](#捕获局部状态)
6. [完整示例](#完整示例)

## 概述

Flare-Emu DSL 是基于 JSON 的声明式语言，集成在 `test_config.json` 中。每个测试用例包含一个 `steps` 数组，按顺序执行其中的操作。

DSL 执行器 (`DSLRunner`) 会维护一个上下文环境，允许在步骤之间共享变量（如分配的内存指针、函数返回值等）。

## 基本结构

一个标准的测试用例配置如下：

```json
{
  "name": "test_example",
  "description": "这是一个示例测试",
  "steps": [
    { "type": "alloc", ... },
    { "type": "call", ... },
    { "type": "assert", ... }
  ]
}
```

## 变量系统

DSL 支持简单的变量引用机制。

- **定义变量**：通过 `alloc` 的 `var` 字段或 `call` 的 `return_var` 字段定义变量。
- **使用变量**：在任何支持值的字段中，使用 `$` 前缀引用变量。例如：`"$my_buffer"`。

**示例**：
```json
{
  "type": "alloc",
  "content": "hello",
  "var": "str_ptr" 
}
// 后续使用
{
  "type": "call",
  "args": [{"type": "ptr", "value": "$str_ptr"}]
}
```

## 步骤详解

### call (函数调用)

调用二进制文件中的导出函数或指定地址的函数。

**字段**：
- `type`: 固定为 `"call"`。
- `function`: (String) 函数名或十六进制地址。
- `args`: (Array) 参数列表。
  - 直接值：`10`, `"0x10"`
  - 复杂类型：`{"type": "ptr", "value": "$var"}`
  - 字符串自动分配：`{"type": "string", "value": "hello"}` (会自动分配内存并传入指针)
- `return_var`: (String, 可选) 将返回值存储到指定变量中。
- `convention`: (String, 可选) 调用约定，如 `"ms64"`, `"cdecl"`。默认根据架构自动推断。
- `hooks`: (Array, 可选) 函数执行期间的 Hook 配置。

**示例**：
```json
{
  "type": "call",
  "function": "test_add",
  "args": [10, 20],
  "return_var": "sum"
}
```

### alloc (内存分配)

在模拟器内存中分配空间，并可初始化内容。

**字段**：
- `type`: 固定为 `"alloc"`。
- `size`: (Integer, 可选) 分配大小（字节）。
- `content`: (String/Bytes, 可选) 初始化内容。如果是字符串会自动计算大小。支持 `hex:aabbcc` 格式。
- `var`: (String, 必填) 用于存储分配地址的变量名。

**示例**：
```json
{
  "type": "alloc",
  "content": "hello world",
  "var": "my_str"
}
```

### write (写入操作)

直接修改寄存器或内存。

**字段**：
- `type`: 固定为 `"write"`。
- `registers`: (Object, 可选) 键为寄存器名，值为要写入的数据。
- `memory`: (Array, 可选) 内存写入操作列表。
  - `addr`: 写入地址（支持变量）。
  - `data`: 写入数据（支持字符串或 `hex:` 格式）。

**示例**：
```json
{
  "type": "write",
  "registers": {
    "eax": 100
  },
  "memory": [
    {
      "addr": "$buffer",
      "data": "new data"
    }
  ]
}
```

### emulate (模拟执行)

模拟指定范围的指令，比 `call` 更底层的控制。

**字段**：
- `type`: 固定为 `"emulate"`。
- `start`: (String/Int) 起始地址。
- `end`: (String/Int) 结束地址。
- `count`: (Int, 可选) 最大指令数。
- `registers`: (Object, 可选) 初始寄存器状态。
- `stack`: (Array, 可选) 初始栈内容。

### assert (断言验证)

验证模拟结果是否符合预期。

**字段**：
- `type`: 固定为 `"assert"`。
- `checks`: (Array) 检查列表。每个检查包含：
  - `type`: `"register"`, `"variable"`, 或 `"memory"`。
  - `name` / `register`: 要检查的变量或寄存器名。
  - `addr`: (仅 memory) 内存地址。
  - `value` / `content`: 预期值。
    - 对于寄存器/变量：整数值。
    - 对于内存：字符串或 `hex:` 格式。

**示例**：
```json
{
  "type": "assert",
  "checks": [
    {
      "type": "variable",
      "name": "sum",
      "value": 30
    },
    {
      "type": "memory",
      "addr": "$buffer",
      "content": "expected data"
    }
  ]
}
```

## Hook 系统

在 `call` 或 `emulate` 步骤中，可以定义 `hooks` 来干预执行流程或捕获中间状态。

**Hook 字段**：
- `addr`: (String/Int) 触发 Hook 的地址（函数名或偏移）。
- `action`: (String) 触发时的动作。

### 修改执行流

- `"skip"`: 跳过当前指令。
- `"write_reg"`: 修改寄存器值。需配合 `register` 和 `value` 字段。
- `"stop"`: 停止模拟。

**示例：修改寄存器**
```json
"hooks": [
  {
    "action": "write_reg",
    "register": "eax", 
    "value": 999,
    "addr": "test_add" 
  }
]
```

### 捕获局部状态

由于 `assert` 步骤在函数执行结束后才运行，无法直接检查函数内部的局部变量。为了验证局部变量或中间状态，可以使用 Hook 将寄存器或内存值读取到 DSL 变量中，然后在后续 `assert` 步骤中验证。

- `"read_reg"`: 读取寄存器值并存储到变量。需配合 `register` 和 `var` 字段。
- `"read_mem"`: 读取内存值并存储到变量。需配合 `addr_read` (支持寄存器名), `size`, 和 `var` 字段。

**示例：捕获输入参数（寄存器）**
```json
"hooks": [
  {
    "addr": "test_func",
    "action": "read_reg",
    "register": "rdi",  // Linux x64 第一个参数
    "var": "captured_arg"
  }
]
// 后续断言
{
  "type": "assert",
  "checks": [
    {"type": "variable", "name": "captured_arg", "value": 5}
  ]
}
```

**示例：捕获栈变量（内存）**
```json
"hooks": [
  {
    "addr": "0x1234", // 假设是某条指令地址
    "action": "read_mem",
    "addr_read": "rsp", // 读取栈顶
    "size": 4,
    "var": "stack_val"
  }
]
```

## 完整示例

```json
{
  "name": "test_complex_scenario",
  "description": "演示分配内存、调用函数、捕获中间状态和验证结果",
  "steps": [
    {
      "type": "alloc",
      "content": "Initial Data",
      "var": "data_ptr"
    },
    {
      "type": "call",
      "function": "process_data",
      "args": [
        {"type": "ptr", "value": "$data_ptr"},
        12  // length
      ],
      "hooks": [
          {
              "addr": "process_data",
              "action": "read_reg",
              "register": "rsi", // 捕获长度参数
              "var": "len_arg"
          }
      ],
      "return_var": "result_code"
    },
    {
      "type": "assert",
      "checks": [
        {
          "type": "variable",
          "name": "result_code",
          "value": 0
        },
        {
          "type": "variable",
          "name": "len_arg",
          "value": 12
        },
        {
          "type": "memory",
          "addr": "$data_ptr",
          "content": "Processed"
        }
      ]
    }
  ]
}
```

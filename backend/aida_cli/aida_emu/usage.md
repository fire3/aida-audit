# aida_emu 使用指南

## 简介

aida_emu 是一个基于 Unicorn 的 CPU 模拟器后端，用于在 Python 环境中模拟执行二进制代码。它与 AIDA 工具链紧密集成，可以直接加载 AIDA 导出的分析数据库，对函数进行模拟执行和调试。

### 主要功能

- **多架构支持**：x86_64、x86_32、ARM、ARM64、MIPS、SPARC 等
- **数据库集成**：直接加载 AIDA 导出的 SQLite 数据库
- **调用约定检测**：自动识别函数调用约定（cdecl、stdcall、sysv_amd64 等）
- **灵活的 Hook 机制**：支持代码执行、内存访问、系统中断钩子
- **内存管理**：内置栈和堆分配，支持任意内存读写

## 前置要求

### 依赖库

```bash
pip install unicorn
```

### 数据库文件

使用 AIDA 工具将二进制文件导出为数据库格式（`.db` 文件）。导出后的数据库包含：

- 元数据（架构、处理器类型、字节序等）
- 代码段信息（起始地址、权限、内容）
- 函数信息（函数名、地址范围、基本块）
- 指令和操作数数据

## 快速开始

以下示例展示最基本的方法：从二进制文件直接加载并调用一个函数。

```python
from aida_emu import AidaEmulator

# 1. 从二进制文件加载模拟器（自动导出并加载）
emu = AidaEmulator.from_binary("./program")

# 2. 设置栈和堆
emu.setup_stack()
emu.setup_heap()

# 3. 查找函数地址（假设二进制中存在名为 "add" 的函数）
func_va = None
for func in emu.db.load_functions():
    if func["name"] == "add":
        func_va = func["va"]
        break

# 4. 调用函数并获取返回值
result = emu.call(func_va, 3, 5)
print(f"Result: {result}")  # 输出: Result: 8

# 5. 关闭模拟器
emu.close()
```

### 从数据库加载

如果不使用自动导出，也可以先使用 AIDA 工具导出数据库，再加载：

```python
# 从预导出的数据库加载
emu = AidaEmulator.from_database("program.db")

# 或指定架构
emu = AidaEmulator.from_database("program.db", arch="x86_64")
```

## 基础使用

### 从二进制文件加载

```python
# 从二进制文件直接加载（自动调用 IDA 导出数据库）
emu = AidaEmulator.from_binary("./program")

# 保留导出的数据库文件
emu = AidaEmulator.from_binary("./program", keep_db=True)
# 数据库保存在同目录下: ./program.db

# 指定输出目录
emu = AidaEmulator.from_binary("./program", output_dir="/tmp/my_output")
```

**注意**: 需要 IDA Pro

### 从数据库加载

```python
# 从预导出的数据库加载
emu = AidaEmulator.from_database("program.db")
# 内部自动完成：
#   1. 读取数据库元数据（架构、处理器类型等）
#   2. 加载所有代码段到内存
#   3. 初始化寄存器

# 手动指定架构
emu = AidaEmulator.from_database("program.db", arch="x86_64")
```

支持的架构字符串：`x86_64`、`x86_32`、`arm`、`arm64`、`mips`、`mipsel`、`sparc`、`sparc64`

### 设置栈和堆

```python
# 使用默认地址
emu.setup_stack()      # 默认 1MB 栈空间
emu.setup_heap()       # 默认 1MB 堆空间

# 自定义地址和大小
emu.setup_stack(stack_va=0x7fff0000, stack_size=0x200000)
emu.setup_heap(heap_va=0x600000, heap_size=0x200000)
```

### 查找函数

```python
# 通过地址查找函数信息
func = emu.get_function(0x401000)  # 返回 dict，包含 va, name, start_va, end_va 等字段

# 遍历所有函数查找目标函数
all_functions = emu.db.load_functions()
for func in all_functions:
    if func["name"] == "main":
        func_va = func["va"]
        break
```

### 调用函数

`call()` 方法会自动检测调用约定并设置参数，直接使用即可：

```python
# 直接调用（自动检测调用约定并设置参数）
result = emu.call(function_va, arg1, arg2, arg3)

# 如需手动检测调用约定（可选）
emu.detect_convention(function_va)
result = emu.call(function_va, arg1, arg2)
```

### 传递指针参数

当函数需要指针参数时（如数组、结构体），使用 `alloc()` 方法分配内存并自动写入数据：

```python
# 方法一：使用 alloc() 便捷分配内存
arr = [1, 2, 3, 4, 5]
arr_ptr = emu.alloc(len(arr) * 4)  # 分配 20 字节
for i, val in enumerate(arr):
    emu.mem.write_u32(arr_ptr + i * 4, val)

result = emu.call(func_va, arr_ptr, len(arr))

# 方法二：使用 alloc() 同时分配并写入数据
str_data = b"hello\x00"
str_ptr = emu.alloc(len(str_data), str_data)  # 分配并写入
result = emu.call(func_va, str_ptr)
```

### 分配临时内存

`alloc()` 方法在堆上分配内存，自动跟踪分配位置：

```python
# 分配指定大小的内存，返回起始地址
ptr = emu.alloc(size=0x1000)

# 分配内存并写入数据
ptr = emu.alloc(size=16, data=b"\x01\x02\x03\x04")

# 连续分配会自动接在上次分配位置之后
ptr1 = emu.alloc(16)   # 返回 0x600000
ptr2 = emu.alloc(16)   # 返回 0x600010
```

### 获取返回值

```python
result = emu.call(func_va, 10, 20)

# 或者手动获取
ret_value = emu.regs.get_ret_value(signed=False)  # 无符号
ret_value = emu.regs.get_ret_value(signed=True)   # 有符号
```

## 内存操作

### 读取内存

```python
# 读取原始字节
data = emu.read_memory(address, size)

# 读取特定大小的值
value64 = emu.read_ptr(address, size=8)   # 8 字节
value32 = emu.read_ptr(address, size=4)   # 4 字节
value16 = emu.read_ptr(address, size=2)   # 2 字节
value8  = emu.read_ptr(address, size=1)   # 1 字节

# 读取栈上数据
sp = emu.get_sp()
stack_value = emu.get_stack_value(offset=0, size=8)  # 相对于 SP 的偏移
```

### 写入内存

```python
# 写入原始字节
emu.write_memory(address, b"\x00\x01\x02\x03")

# 写入无符号值
emu.mem.write_u64(address, 0x12345678)   # 8 字节
emu.mem.write_u32(address, 0x12345678)   # 4 字节
emu.mem.write_u16(address, 0x1234)       # 2 字节
emu.mem.write_u8(address, 0x12)          # 1 字节

# 写入有符号值
emu.mem.write_s32(address, -100)         # 4 字节有符号
emu.mem.write_s16(address, -50)          # 2 字节有符号
emu.mem.write_s8(address, -10)           # 1 字节有符号

# 使用统一接口
emu.write_ptr(address, 0x12345678, size=4)

# 写入栈上数据
emu.set_stack_value(offset=8, value=0xdeadbeef, size=8)
```

### 内存映射

> 注意：`from_database()` 会自动加载数据库中的所有段到内存，一般无需手动映射。

```python
# 手动映射新内存区域
emu.mem.map(
    name="my_region",
    va=0x10000,
    size=0x1000,
    read=True,
    write=True,
    execute=False,
    content=b"\x00" * 0x1000
)

# 分配栈（由 setup_stack 自动调用）
emu.mem.allocate_stack(stack_va, stack_size)

# 分配堆（由 setup_heap 自动调用）
emu.mem.allocate_heap(heap_va, heap_size)
```

## Hook 机制

### 代码执行 Hook

在每条指令执行时触发回调：

```python
def code_callback(emu, address, size, user_data):
    print(f"Executing at 0x{address:016x}, size={size}")
    # 可以读取寄存器、内存等
    pc = emu.get_pc()
    return True  # 返回 False 停止执行

emu.hook_code(code_callback, user_data={"step": 1})
emu.run(start=0x401000, end=0x401100)
```

### 基本块 Hook

在每个基本块开始时触发：

```python
def block_callback(emu, address, size, user_data):
    print(f"Basic block at 0x{address:016x}, size={size}")
    return True

emu.hook_block(block_callback)
emu.run(start=0x401000)
```

### 内存访问 Hook

监控内存读写操作：

```python
def mem_callback(emu, access, address, size, value, user_data):
    access_type = {
        1: "READ",
        2: "WRITE", 
        4: "FETCH"
    }.get(access, "UNKNOWN")
    print(f"{access_type} at 0x{address:016x}, size={size}, value=0x{value:x}")
    return True

# 监控所有内存访问
emu.hook_memory(mem_callback, mem_type="all")

# 仅监控写入
emu.hook_memory(mem_callback, mem_type="write")

# 仅监控未映射内存访问
emu.hook_memory(mem_callback, mem_type="unmapped")
```

### 中断 Hook

处理软中断或系统调用：

```python
def int_callback(emu, intno, user_data):
    print(f"Interrupt 0x{intno:x}")
    if intno == 0x80:  # Linux syscall
        # 处理系统调用
        pass
    return True

emu.hook_interrupt(int_callback)
```

## 调用约定

### 自动检测

模拟器可以自动分析函数 prologue 和 epilogue，检测调用约定：

```python
# 自动检测并应用调用约定
emu.detect_convention(function_va)
convention = emu.get_convention()
print(f"Detected: {convention.name}")
```

### 常用调用约定

| 架构 | 约定名称 | 参数寄存器 |
|------|----------|-----------|
| x86_64 | sysv_amd64 | rdi, rsi, rdx, rcx, r8, r9 |
| x86_64 | ms_x64 | rcx, rdx, r8, r9 |
| x86_32 | cdecl | 全部通过栈传递 |
| x86_32 | stdcall | 全部通过栈传递（被调用方清理栈） |
| x86_32 | fastcall | ecx, edx + 栈 |
| ARM | aapcs | r0, r1, r2, r3 |
| ARM64 | aapcs64 | x0-x7 |

### 手动设置参数

```python
# 设置单个参数
emu.set_arg(0, 10)   # 第一个参数
emu.set_arg(1, 20)   # 第二个参数

# 批量设置参数
emu.set_args(10, 20, 30)
```

## 完整示例

以下是一个完整的端到端示例，演示如何使用 aida_emu 模拟执行一个函数：

```python
import sys
from aida_emu import AidaEmulator

def main():
    # 1. 加载数据库
    db_path = "example.db"
    emu = AidaEmulator.from_database(db_path)
    
    # 2. 设置执行环境
    emu.setup_stack()
    emu.setup_heap()
    
    # 3. 查找目标函数
    func_va = None
    for func in emu.db.load_functions():
        if func["name"] == "calculate":
            func_va = func["va"]
            break
    
    if not func_va:
        print("Function 'calculate' not found")
        return
    
    print(f"Found function 'calculate' at 0x{func_va:016x}")
    
    # 4. 添加代码 Hook 用于追踪执行
    instruction_count = [0]
    
    def code_hook(emu, address, size, user_data):
        instruction_count[0] += 1
        if instruction_count[0] % 100 == 0:
            print(f"Executed {instruction_count[0]} instructions")
        return True
    
    emu.hook_code(code_hook)
    
    # 5. 调用函数
    print(f"Calling calculate(10, 20, 30)...")
    result = emu.call(func_va, 10, 20, 30)
    
    # 6. 输出结果
    print(f"Result: {result}")
    
    # 7. 检查执行状态
    print(f"Total instructions executed: {instruction_count[0]}")
    
    # 8. 清理资源
    emu.close()

if __name__ == "__main__":
    main()
```

## 最佳实践

### 1. 使用上下文管理器

推荐使用 `with` 语句确保资源正确释放：

```python
with AidaEmulator.from_database("program.db") as emu:
    emu.setup_stack()
    emu.setup_heap()
    result = emu.call(func_va, arg1, arg2)
    # 退出时自动调用 emu.close()
```

### 2. 合理设置超时和指令数限制

对于复杂函数，设置执行限制防止无限循环：

```python
emu.run(start=func_va, timeout=5000, count=1000000)
# timeout: 毫秒
# count: 最大指令数
```

### 3. 处理未映射内存访问

使用 `hook_memory` 监控未映射内存访问，实现自定义内存分配：

```python
def handle_unmapped(emu, access, address, size, value, user_data):
    print(f"Unmapped access at 0x{address:016x}")
    # 可在此处动态映射内存
    return True

emu.hook_memory(handle_unmapped, mem_type="unmapped")
```

### 4. 调试技巧

使用 Hook 打印执行信息：

```python
def debug_hook(emu, address, size, user_data):
    pc = emu.get_pc()
    sp = emu.get_sp()
    print(f"PC: 0x{pc:016x}, SP: 0x{sp:016x}")
    
    # 获取当前指令
    insns = emu.get_instructions(pc, pc + 16)
    if insns:
        insn = insns[0]
        ops = ", ".join(op["text"] for op in insn["operands"])
        print(f"  Instruction: {insn['mnemonic']} {ops}")
    return True

emu.hook_code(debug_hook)
```

## 常见问题

### Q: 如何处理模拟执行中的崩溃？

A: 使用 `try-except` 捕获 `EmulationError`，并通过 Hook 追踪崩溃位置：

```python
try:
    emu.run(start=func_va)
except EmulationError as e:
    print(f"Emulation error: {e}")
    print(f"Crashed at: 0x{emu.get_pc():016x}")
```

### Q: 如何模拟带有外部库调用的函数？

A: 使用 Hook 拦截调用并模拟返回值：

```python
def hook_call(emu, address, size, user_data):
    # 检查是否为外部调用地址
    if address in external_calls:
        # 设置返回值
        emu.regs.set_ret_value(0)
        # 跳过实际调用
        emu.set_pc(emu.get_pc() + size)
    return True

emu.hook_code(hook_call)
```

### Q: 如何查看当前寄存器状态？

```python
# 获取所有通用寄存器
regs = emu.regs.get_all_gprs()
for name, value in regs.items():
    print(f"{name}: 0x{value:016x}")

# 获取特定寄存器
rax = emu.get_reg("rax")
rsp = emu.get_sp()
pc = emu.get_pc()
```

## 相关文档

- [Unicorn 官方文档](https://unicorn-engine.org/)
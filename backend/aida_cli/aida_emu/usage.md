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

# 3. 查找函数地址
func = emu.db.find_function("add")
if not func:
    print("Function 'add' not found")
    emu.close()
    return

# 4. 调用函数并获取返回值
result = emu.call(func["va"], 3, 5)
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

# 通过函数名查找（精确匹配）
func = emu.db.find_function("main")

# 通过函数名查找（模糊匹配）
funcs = emu.db.find_functions("str_")  # 查找所有以 str_ 开头的函数
```

### 调用函数

`call(func_va, *args)` 方法会自动检测调用约定并设置参数。

**从仿真角度看，参数就是寄存器值**。参数会按照调用约定写入对应寄存器：

```python
# 调用约定：x86_64 SysV ABI
# arg1 -> rdi, arg2 -> rsi, arg3 -> rdx, arg4 -> rcx, arg5 -> r8, arg6 -> r9
result = emu.call(func_va, 10, 20, 30)

# 调用约定：x86_32 cdecl
# 所有参数通过栈传递
result = emu.call(func_va, 10, 20, 30)

# 调用约定：ARM64 AAPCS64
# arg1 -> x0, arg2 -> x1, arg3 -> x2, ...
result = emu.call(func_va, 10, 20, 30)
```

如果需要手动控制寄存器：

```python
# 手动设置调用约定
emu.detect_convention(func_va)

# 手动设置寄存器值
emu.set_arg(0, 10)   # 设置第一个参数寄存器
emu.set_arg(1, 20)   # 设置第二个参数寄存器

# 或直接设置寄存器
emu.set_reg("rdi", 10)
emu.set_reg("rsi", 20)

# 调用函数
emu.set_pc(func_va)
emu.run()
result = emu.regs.get_ret_value()
```

### 传递指针参数

当函数需要指针参数时（如数组、结构体），指针本质上就是一个地址值（整数）。需要先分配内存写入数据，再将该地址作为参数传递：

```python
# 1. 分配内存并写入数据
arr = [1, 2, 3, 4, 5]
arr_ptr = emu.alloc(len(arr) * 4)  # 分配 20 字节
for i, val in enumerate(arr):
    emu.mem.write_u32(arr_ptr + i * 4, val)

# 2. 传递指针地址作为参数值（整数）
# 对应 SysV ABI: rdi = arr_ptr, rsi = 5
result = emu.call(func_va, arr_ptr, len(arr))

# 传递字符串同理
str_data = b"hello\x00"
str_ptr = emu.alloc(len(str_data), str_data)
result = emu.call(func_va, str_ptr)  # rdi = str_ptr
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

返回值同样来自寄存器。按照调用约定：

- **x86_64**: 返回值在 `rax`（或 `rax:rdx` 用于 128 位）
- **x86_32**: 返回值在 `eax`
- **ARM64**: 返回值在 `x0`
- **ARM**: 返回值在 `r0`

```python
result = emu.call(func_va, 10, 20)

# 或者手动读取返回值寄存器
ret_value = emu.regs.get_ret_value()          # 有符号
ret_value = emu.regs.get_ret_value(signed=False)  # 无符号
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

### Libc Hook

模拟 libc 函数调用，避免执行真实的外部库函数：

```python
# 1. 启用 libc hook 功能
emu.enable_libc_hooks()

# 2. 注册 libc 函数地址（从数据库查询或手动指定）
strlen_addr = 0x7ffff7e5a000  # 从 binary 中查找的实际地址
emu.hook_libc("strlen", strlen_addr)

strcmp_addr = 0x7ffff7e5b000
emu.hook_libc("strcmp", strcmp_addr)

malloc_addr = 0x7ffff7e60000
emu.hook_libc("malloc", malloc_addr)

# 3. 调用函数时会自动拦截并模拟
str_ptr = emu.alloc(16, b"hello\x00")
result = emu.call(target_func_va, str_ptr)  # 如果 target_func 调用 strlen，会被模拟
```

**内置支持的 libc 函数**：strlen, strcmp, strncmp, strcpy, strncpy, memcpy, memset, atoi, atol, malloc, free

**自定义 libc 函数模拟**：

```python
def my_strlen(emu):
    addr = emu.regs.get_arg(0)
    s = ""
    while True:
        b = emu.mem.read_u8(addr)
        if b == 0:
            break
        s += chr(b)
        addr += 1
    return len(s)

emu.libc.register("my_strlen", my_strlen)
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

参数就是寄存器值，可以直接操作寄存器：

```python
# 方式一：使用 set_arg（根据调用约定写入对应寄存器）
emu.set_arg(0, 10)   # 第一个参数 -> rdi/x0
emu.set_arg(1, 20)   # 第二个参数 -> rsi/x1

# 方式二：直接设置寄存器
emu.set_reg("rdi", 10)
emu.set_reg("rsi", 20)

# 批量设置
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
    func = emu.db.find_function("calculate")
    if not func:
        print("Function 'calculate' not found")
        return
    
    print(f"Found function 'calculate' at 0x{func['va']:016x}")
    
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
    result = emu.call(func["va"], 10, 20, 30)
    
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

### Q: Hook 返回值 True 和 False 有什么区别？

Hook 回调的返回值控制 Unicorn 的执行流程：

- **返回 `True`**: 继续执行，不改变执行流程
- **返回 `False`**: 停止执行（unicorn 会终止 emu_start）

注意：当在 hook 中调用 `emu.set_pc()` 跳过某些指令后，必须返回 `True` 让 Unicorn 继续从新地址执行，否则会直接停止。

```python
def my_call_hook(emu, address, size, user_data):
    # 拦截并模拟函数调用
    result = emulate_libc_function(emu)
    emu.regs.set_ret_value(result)  # 设置返回值
    
    # 跳过 call 指令，继续执行
    emu.set_pc(address + size)
    return True  # 必须返回 True 继续执行
```

### Q: 32位有符号返回值如何正确获取？

当函数返回 32 位有符号整数（如 C 语言的 `int`）时，直接读取 64 位寄存器会得到零扩展的值。正确做法是使用 `signed=True`：

```python
result = emu.regs.get_ret_value(signed=True)

# 如果返回 -1，get_ret_value(signed=False) 会得到 0xFFFFFFFF
# get_ret_value(signed=True) 会正确得到 -1
```

### Q: 动态链接程序中的 libc 函数调用如何处理？

动态链接的程序通过 PLT (Procedure Linkage Table) 调用 libc 函数。模拟时需要：

1. 找到 PLT 中目标函数的地址
2. 使用 libc hook 拦截并模拟

```python
# 从数据库查找 PLT 函数
for func in emu.db.load_functions():
    if "strlen@plt" in func.get("name", ""):
        emu.hook_libc("strlen", func["va"])
        break
```

### Q: Hook 中读取的寄存器值不正确？

在代码 hook 中读取寄存器时，需要注意 hook 触发的时机：

- Hook 在每条指令**执行前**触发
- 此时寄存器状态是**执行该指令之前**的状态
- 对于 `call` 指令，参数已在寄存器中

```python
def call_hook(emu, address, size, user_data):
    # 读取当前指令地址的参数（在 call 执行前，参数已在寄存器）
    arg0 = emu.regs.get_arg(0)
    arg1 = emu.regs.get_arg(1)
    print(f"Calling with args: {arg0}, {arg1}")
    return True
```

### Q: 写入负数到内存时 OverflowError？

`write_u32` 等方法只支持无符号整数。写入有符号负数需要转换：

```python
# 错误方式
emu.mem.write_u32(address, -5)  # OverflowError

# 正确方式：转换为字节
emu.mem.write(address, (-5).to_bytes(4, 'little', signed=True))

# 或使用 bytes() 包装 bytearray
data = emu.mem.read(src, n)
emu.mem.write(dest, bytes(data))  # 转换 bytearray 为 bytes
```

### Q: 如何在 Hook 中获取累积的数据？

使用可变容器（如 list 或 dict）存储 hook 捕获的数据：

```python
executed_addrs = []

def code_hook(emu, address, size, user_data):
    executed_addrs.append(address)
    return True

emu.hook_code(code_hook)
emu.call(func_va, arg1, arg2)

# hook 执行后，executed_addrs 中包含了所有执行过的地址
print(f"Executed {len(executed_addrs)} instructions")
```

### Q: 如何测试整个程序（main 函数）？

测试 main 函数时，需要考虑它通常接受 `argc` 和 `argv` 参数：

```python
func = emu.db.find_function("main")
assert func is not None

# main 函数签名: int main(int argc, char** argv)
result = emu.call(func["va"], 1, 0)  # argc=1, argv=NULL

# main 返回值通常是程序退出码
# 注意：有些架构下返回值会被截断
exit_code = result & 0xFF  # 取低 8 位
```

### Q: 运行复杂函数时遇到无限循环怎么办？

设置执行限制防止卡死：

```python
# 方式1：设置指令数上限
try:
    emu.run(start=func_va, count=100000)  # 最多执行 10 万条指令
except EmulationError:
    print("Execution limit exceeded")

# 方式2：设置超时
try:
    emu.run(start=func_va, timeout=5000)  # 5 秒超时
except EmulationError:
    print("Timeout")

# 方式3：在 hook 中检测循环并终止
loop_count = {}
def detect_loop(emu, address, size, user_data):
    loop_count[address] = loop_count.get(address, 0) + 1
    if loop_count[address] > 10000:  # 同一地址执行超过 10000 次
        print(f"Infinite loop detected at 0x{address:x}")
        return False  # 停止执行
    return True

emu.hook_code(detect_loop)
```

### Q: 栈空间不足导致崩溃？

复杂函数可能需要更大的栈空间：

```python
# 分配更大的栈
emu.setup_stack(stack_size=0x400000)  # 4MB 栈
```

### Q: 如何检测栈溢出？

栈溢出发生在函数使用超过分配的栈空间时，通常发生在深度递归或大数组分配的场景中。模拟器可以通过以下方式检测：

**方式1：监控未映射内存访问**

当栈指针超出栈区域时，后续的内存访问会触发未映射错误：

```python
unmapped_accesses = []

def detect_stack_overflow(emu, access, address, size, value, user_data):
    # 检查地址是否在栈区域附近
    sp = emu.get_sp()
    stack_base = 0x7fff0000  # 栈底地址
    
    if address < stack_base and address > stack_base - 0x1000000:
        print(f"Potential stack overflow at 0x{address:x}")
        unmapped_accesses.append(address)
    return True

emu.hook_memory(detect_stack_overflow, mem_type="unmapped")

try:
    result = emu.call(func_va, 100)  # 深度递归
except EmulationError as e:
    print(f"Stack overflow detected: {e}")

print(f"Total unmapped accesses: {len(unmapped_accesses)}")
```

**方式2：监控栈指针变化**

通过代码 hook 监控栈指针，检测异常下降：

```python
sp_values = []

def monitor_stack(emu, address, size, user_data):
    sp = emu.get_sp()
    sp_values.append(sp)
    
    # 检测栈指针是否低于某个阈值
    stack_limit = 0x7ffe0000  # 栈空间下限
    if sp < stack_limit:
        print(f"Stack pointer 0x{sp:x} below limit 0x{stack_limit:x}")
        return False  # 停止执行
    return True

emu.hook_code(monitor_stack)
emu.call(func_va, 50)

if sp_values:
    min_sp = min(sp_values)
    max_sp = max(sp_values)
    print(f"Stack grew from 0x{max_sp:x} to 0x{min_sp:x}")
    print(f"Total stack usage: 0x{max_sp - min_sp:x} bytes")
```

**方式3：结合异常处理和栈大小限制**

设置合理的栈大小，让 Unicorn 自动捕获溢出：

```python
# 使用较小的栈空间来快速触发溢出
emu.setup_stack(stack_size=0x1000)  # 4KB 栈

try:
    result = emu.call(recursive_func_va, 100)
    print(f"Result: {result}")
except EmulationError as e:
    print(f"Execution error (possibly stack overflow): {e}")
    print(f"PC: 0x{emu.get_pc():x}")
```

**实际测试示例：递归函数**

对于一个递归函数，每次递归分配局部数组：

```c
int recursive_func(int n) {
    int local_array[1024];  // 每次递归 4KB
    if (n <= 0) return 0;
    return n + recursive_func(n - 1);
}
```

当使用 1MB 栈空间时，可以安全执行约 256 次递归。使用 4KB 栈空间时，约 1 次递归就会触发栈溢出。

```python
# 大栈空间 - 可以完成
emu.setup_stack(stack_size=0x100000)  # 1MB
result = emu.call(func_va, 100)  # 成功

# 小栈空间 - 触发未映射访问
emu.setup_stack(stack_size=0x1000)  # 4KB
result = emu.call(func_va, 100)  # 触发 EmulationError
```

**最佳实践**

1. **预估栈需求**：分析函数调用深度和局部变量大小
2. **设置合理栈大小**：通常 1MB-4MB 足够大多数函数
3. **监控异常**：使用 `hook_memory(..., mem_type="unmapped")` 捕获溢出
4. **调试时使用小栈**：快速发现潜在的栈溢出问题

## 相关文档

- [Unicorn 官方文档](https://unicorn-engine.org/)
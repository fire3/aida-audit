# Microcode Analyzer 指令解析问题分析报告

## 概述

本报告基于 `backend/tests/insn` 文件中的 Microcode analyzer 分析结果，识别并分类了指令解析不到位的问题，每个问题都附带具体的代码证据。

---

## 问题 1：元数据字段普遍缺失

### 问题描述
多个重要的元数据字段未进行解析，导致分析结果缺少关键信息。

### 证据

#### 1.1 `category` 字段全为空

所有指令的 `category` 字段均为空字符串：

```python
InsnInfo(
  block_id=1,
  insn_idx=0,
  ea='0x1008',
  opcode='op_4',
  category='',  # 应标记如 'memory', 'arithmetic', 'branch', 'call'
  ...
)
```

#### 1.2 `flags_read` 和 `flags_write` 全为 None

```python
InsnInfo(
  ...
  flags_read=None,   # 未分析读取的标志位
  flags_write=None,  # 未分析写入的标志位
  ...
)
```

#### 1.3 `op_size` 全为 None

操作数大小信息（如 `.1`、`.4`、`.8`）在 `text` 中有体现，但 `op_size` 字段全为 None：

```python
InsnInfo(
  ...
  op_size=None,  # 应识别操作数宽度
  text='mov    #0.8, result.8',  # .8 表示8字节宽度
  ...
)
```

#### 1.4 `signed` 全为 None

条件跳转指令缺少有符号/无符号标记：

```python
InsnInfo(
  ...
  signed=None,  # jle 应标记为 signed=True
  text='jle    edi0.4{1}, #0x64.4, @3',
  ...
)
```

---

## 问题 2：条件跳转识别错误

### 问题描述
条件跳转指令的 `is_conditional` 标记错误，且 `jump_kind` 和 `jump_targets` 信息缺失。

### 证据

#### 2.1 `jz` 指令被标记为非条件跳转

```python
InsnInfo(
  ...
  opcode='op_44',
  text='jz     &($__gmon_start__{1}).8, #0.8, @3',
  is_conditional=False,  # ❌ 错误：jz 是条件跳转
  jump_kind='',          # 应为 'cond_jump' 或具体类型
  jump_targets=[],       # 应包含目标块 @3
  ...
)
```

#### 2.2 `jnz` 指令被标记为非条件跳转

```python
InsnInfo(
  ...
  opcode='op_43',
  text='jnz    $__TMC_END__.1, #0.1, @5',
  is_conditional=False,  # ❌ 错误：jnz 是条件跳转
  jump_targets=[],
  ...
)
```

#### 2.3 `jle` 指令被标记为非条件跳转

```python
InsnInfo(
  ...
  opcode='op_52',
  text='jle    edi0.4{1}, #0x64.4, @3',
  is_conditional=False,  # ❌ 错误：jle 是条件跳转
  jump_targets=[],
  ...
)
```

#### 2.4 多个条件跳转的 jump_targets 均为空

```python
# jnz
InsnInfo(
  text='jnz    edi0.4{1}, #0.4, @3',
  jump_targets=[],  # ❌ 应包含目标地址
  ...
)

# jz
InsnInfo(
  text='jz     esi0.4{2}, #0.4, @6',
  jump_targets=[],  # ❌ 应包含目标地址
  ...
)
```

---

## 问题 3：操作数依赖未追踪

### 问题描述
指令的源操作数读取和目标操作数写入信息未在 `reads` 和 `writes` 字段中体现。

### 证据

#### 3.1 内存读取操作缺少 reads 记录

```python
InsnInfo(
  ...
  text='mov    &($__gmon_start__{1}).8, result.8',  # 从内存读取
  reads=[],  # ❌ 应记录读取的内存位置
  writes=[],  # ❌ 应记录 result.8 的写入
  ...
)
```

#### 3.2 立即数移动缺少 writes 记录

```python
InsnInfo(
  ...
  text='mov    #0.8, result.8',  # 立即数写入 result
  reads=[],   # 正确，暂无读取
  writes=[],  # ❌ 应记录 result.8
  ...
)
```

#### 3.3 寄存器间移动缺少操作数追踪

```python
InsnInfo(
  ...
  text='mov    rax0.8{2}, _FFFFFFFFFFFFFFF8.8{2}',
  reads=[],   # ❌ 应记录 rax0.8 的读取
  writes=[],  # ❌ 应记录 _FFFFFFFFFFFFFFF8.8 的写入
  ...
)
```

#### 3.4 算术运算缺少 operands 追踪

```python
InsnInfo(
  ...
  opcode='op_12',
  text='add    edi0.4{1}, esi0.4{2}, var4.4',  # 两源一目的
  reads=[],   # ❌ 应记录 edi0.4 和 esi0.4
  writes=[],  # ❌ 应记录 var4.4
  ...
)
```

#### 3.5 比较操作缺少 operands 追踪

```python
InsnInfo(
  ...
  opcode='op_9',
  text='xdu    (edi0.4{1} != esi0.4{2}){3}, result.8',  # 比较操作
  reads=[],   # ❌ 应记录操作数
  writes=[],  # ❌ 应记录结果
  ...
)
```

---

## 问题 4：函数调用信息不完整

### 问题描述
函数调用（CallInfo）的多个字段解析不完整。

### 证据

#### 4.1 `callee_ea` 全为 None

```python
CallInfo(
  kind='op_56',
  callee_name='_gmon_start__',
  callee_ea=None,  # ❌ 应解析实际地址
  target=ExpressionAttr(expr='$__gmon_start__'),
  ...
)
```

#### 4.2 `call_conv` 全为 None

```python
CallInfo(
  callee_name='$strcpy',
  target=ExpressionAttr(expr='$strcpy'),
  args=[...],
  call_conv=None,  # ❌ 应识别调用约定 (cdecl/fastcall/thiscall)
  ...
)
```

#### 4.3 `ret_width` 全为 None

```python
CallInfo(
  callee_name='$printf',
  ret=LocalVarAttr(lvar_idx=1),
  ret_width=None,  # ❌ 应记录返回值宽度 (如 .4 表示4字节)
  ...
)
```

#### 4.4 参数信息不完整

部分函数参数类型信息解析不完整：

```python
CallInfo(
  callee_name='$__cxa_finalize',
  target=ExpressionAttr(expr='$__cxa_finalize'),
  args=[
    ExpressionAttr(expr='"void *" $__dso_handle.8{1}')  # ❌ 应解析为具体类型
  ],
  ...
)
```

---

## 问题 5：goto 指令解析缺失

### 问题描述
无条件跳转指令的 `jump_targets` 未解析。

### 证据

```python
# goto @7
InsnInfo(
  opcode='op_55',
  text='goto   @7',
  jump_targets=[],  # ❌ 应包含目标块 ID 7
  ...
)

# goto @8
InsnInfo(
  opcode='op_55',
  text='goto   @8',
  jump_targets=[],  # ❌ 应包含目标块 ID 8
  ...
)

# goto @12
InsnInfo(
  opcode='op_55',
  text='goto   @12',
  jump_targets=[],  # ❌ 应包含目标块 ID 12
  ...
)
```

---

## 问题 6：重复块 ID 和指令索引混乱

### 问题描述
分析结果中存在块 ID 和指令索引重复的问题，可能导致控制流分析错误。

### 证据

```python
# 块 ID 1 多次出现，insn_idx 均为 0
InsnInfo(block_id=1, insn_idx=0, ea='0x1008', ...)     # 第一次
InsnInfo(block_id=1, insn_idx=0, ea='0x1039', ...)     # ❌ 重复
InsnInfo(block_id=1, insn_idx=0, ea='0x1049', ...)     # ❌ 重复
InsnInfo(block_id=1, insn_idx=0, ea='0x1059', ...)     # ❌ 重复
...
```

---

## 统计摘要

| 问题类型 | 出现次数 | 影响程度 |
|---------|---------|---------|
| category 字段缺失 | 100% 指令 | 高 |
| flags_read/flags_write 缺失 | 100% 指令 | 高 |
| op_size 缺失 | 100% 指令 | 中 |
| signed 缺失 | 100% 条件跳转 | 高 |
| is_conditional 错误标记 | 所有条件跳转 | 高 |
| jump_targets 缺失 | 所有跳转指令 | 高 |
| reads/writes 空数组 | 100% 指令 | 高 |
| callee_ea 全为 None | 所有函数调用 | 高 |
| call_conv 全为 None | 所有函数调用 | 中 |
| ret_width 全为 None | 所有函数调用 | 中 |

---

## 建议修复优先级

1. **P0（紧急）**: 修复 `is_conditional` 错误标记和 `jump_targets` 解析
2. **P0（紧急）**: 修复 `reads`/`writes` 数组填充
3. **P1（高）**: 补充 `category` 分类
4. **P1（高）**: 补充 `flags_read`/`flags_write` 分析
5. **P1（高）**: 修复 `callee_ea` 解析
6. **P2（中）**: 补充 `op_size` 和 `signed` 字段
7. **P2（中）**: 补充 `call_conv` 和 `ret_width` 信息
8. **P3（低）**: 修复块 ID 和指令索引重复问题
# 4. 规范化操作数（Normalized Operand）规范（V1）

本章定义 Extractor 输出给 Builder 的唯一“值表示”。其目标是跨 IDA 版本稳定、可 hash、可持久化，并能在离线侧直接映射为 `Var/Expr/Mem/Const/String` 节点。

## 4.1 统一字段

Normalized Operand 必须是一个 JSON 对象，包含：

- `kind`：枚举，见 4.2
- `bits`：位宽（int）
- `repr`：人类可读串，仅用于报告与调试（不得参与等价判断）
- `v`：kind 对应的结构化字段（对象，字段按 kind 决定）

示例：

```json
{
  "kind": "reg",
  "bits": 64,
  "repr": "rax",
  "v": { "reg": "rax" }
}
```

## 4.2 `kind` 枚举（V1）

V1 固定支持以下 `kind`：

- `reg`：寄存器
- `stack`：栈槽（相对基准的偏移）
- `global`：全局地址
- `const`：常量
- `string`：字符串字面量（以地址引用的形式）
- `mem`：内存访问（地址表达式 + region + 访问位宽）
- `expr`：其它无法归类的表达式/临时值（保底）
- `unknown`：无法解析

## 4.3 各 kind 的 `v` 字段

### 4.3.1 `reg`

```json
{
  "kind": "reg",
  "bits": 64,
  "repr": "rax",
  "v": { "reg": "rax" }
}
```

约束：

- `reg` 统一使用架构下的规范名称（例如 x86_64 的 `rax/rbx/...`，arm64 的 `x0/x1/...`）。

### 4.3.2 `stack`

```json
{
  "kind": "stack",
  "bits": 64,
  "repr": "[rbp-0x20]",
  "v": { "base": "fp", "off": -32 }
}
```

约束：

- `base` 必须是 `fp` 或 `sp`（V1 固定选择一种基准；默认 `fp`）。
- `off` 必须为十进制整数（bytes）。

### 4.3.3 `global`

```json
{
  "kind": "global",
  "bits": 64,
  "repr": "0x140012340",
  "v": { "ea": "0x140012340", "rva": "0x12340" }
}
```

约束：

- `ea` 必填。
- `rva` 必填（`ea - imagebase`），用于跨 imagebase 变化的对齐。

### 4.3.4 `const`

```json
{
  "kind": "const",
  "bits": 32,
  "repr": "0x10",
  "v": { "value": "0x10" }
}
```

约束：

- `value` 必须为十六进制字符串，统一 `0x` 前缀，小写。

### 4.3.5 `string`

```json
{
  "kind": "string",
  "bits": 64,
  "repr": "\"%s\"",
  "v": { "ea": "0x140200000" }
}
```

约束：

- `ea` 必填，指向 `strings.jsonl` 中的同地址记录（或至少能回到二进制地址）。

### 4.3.6 `mem`

`mem` 表示一次具体的 load/store 位置。地址表达式以结构化方式表达，避免依赖 `repr`。

```json
{
  "kind": "mem",
  "bits": 64,
  "repr": "[rbp-0x20]",
  "v": {
    "region": "stack|heap|global|unknown",
    "addr": {
      "base": { "kind": "reg", "bits": 64, "repr": "rbp", "v": { "reg": "rbp" } },
      "index": null,
      "scale": 1,
      "disp": -32
    }
  }
}
```

约束：

- `region` 必填（V1 允许 `unknown`）。
- `addr.base/index` 是递归的 Normalized Operand（允许为 `reg/stack/global/expr/unknown`）。
- `scale` 必须为正整数；`disp` 为十进制整数（bytes）。

### 4.3.7 `expr` / `unknown`

对无法稳定建模的值，V1 统一落到 `expr` 或 `unknown`，并尽量保留结构化信息：

```json
{
  "kind": "expr",
  "bits": 64,
  "repr": "add(x0, 8)",
  "v": { "op": "add", "args": [ {"kind":"reg", "...":"..."}, {"kind":"const", "...":"..."} ] }
}
```

## 4.4 Canonical 化与稳定 hash

离线侧进行 intern/复用需要稳定 hash。V1 采用：

- 对 operand 做 canonical JSON：
  - key 排序
  - 删除 `repr`
  - 数值字段保持统一格式（`value/ea/rva` 为 hex string，`off/disp` 为十进制 int）
- 对 canonical JSON 做 SHA-256，取全量 hex 或前缀作为 `expr_hash`（由实现选择，但必须一致）。


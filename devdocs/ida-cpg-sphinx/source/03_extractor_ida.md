# 3. IDA/Hex-Rays 抽取器（Extractor）设计

## 3.1 运行环境与前置条件

- 必须运行在 IDA Pro 的 Python 环境内，并且具备 Hex-Rays 许可（MicroCode 依赖反编译器）。
- 对 IDA/Hex-Rays API 差异必须通过兼容层隔离：导出格式不随 IDA 小版本变化。
- 对无法反编译的函数：V1 直接跳过，并在 `functions.jsonl` 中记录 `status="failed"` 与错误信息。

## 3.2 导出包目录结构（固定）

Extractor 输出一个目录（V1 不压缩，便于调试与增量）：

- `meta.json`
- `functions.jsonl`
- `imports.jsonl`（可选，存在则离线侧加载）
- `exports.jsonl`（可选）
- `globals.jsonl`（推荐，包含全局变量与常量数据）
- `strings.jsonl`（可选，被 globals.jsonl 覆盖，但可作为纯文本列表存在）

文件编码：

- JSON 必须为 UTF-8。
- 所有地址字段使用十六进制字符串（例如 `"0x401234"`），避免跨语言 64 位整数歧义。

## 3.3 `meta.json`（Program 元信息）

`meta.json` 必须包含：

```json
{
  "binary_id": "sha256:<hex>",
  "input_path": "<extractor 运行时看到的路径，仅用于追踪>",
  "arch": "x86_64|x86|arm64|arm|mips|...",
  "endian": "little|big",
  "bitness": 32,
  "imagebase": "0x140000000",
  "ida": {
    "version": "9.2",
    "hexrays": true
  },
  "extractor": {
    "version": "v1",
    "time_utc": "2026-02-08T00:00:00Z"
  }
}
```

约束：

- `binary_id` 必须稳定：对输入文件内容做 SHA-256 后编码成 `sha256:<hex>`。

## 3.4 MicroCode 生成策略
本章采用 **`MMAT_LVARS`** 作为默认 maturity，并以“递归解析（Recursive Parse）”替代“线性扫描（Linear Scan）”作为 CPG 构建的核心思路。

建议在每个函数上：
- `gen_microcode(func_ea)` 获取 `mba`
- 将 maturity 推进到 `MMAT_LVARS`
- 遍历 `mba` 的 block 与“顶层” microcode 指令（`minsn_t`）

选择 `MMAT_LVARS` 的理由（与 `MMAT_LOCOPT` 相比）：
- 变量已映射为更稳定的局部变量/栈槽表示（LVARS），跨指令追踪更接近源级语义。
- 大量“寄存器搬运/参数准备”被折叠为表达式树，降低噪声并减少无意义的中间 `Expr`。
- 更贴近 Hex-Rays 伪代码的求值结构，便于在 CPG 中表达“值如何被构造/传递”。

代价与应对：
- `MMAT_LVARS` 会出现“折叠指令（folded insn）”，例如 `mov call $fopen(...) => ..., r0_1` 或 `call $sprintf(..., f2i((x*y)))`。这会让“仅按指令线性枚举操作数”的策略失效：`call`、算术、类型转换等都可能嵌套在同一条顶层指令内部。
- 因此，Extractor 必须把 **每一条顶层 microcode 指令视为一棵子树的根节点**，对其内部的 `mop_t` / `minsn_t` 递归遍历，派生出稳定的 `reads/writes` 以及（可选但强烈建议）`calls`。

### 3.4.1 折叠指令：以“子树”作为基本单位

在 `MMAT_LVARS` 输出中：
- 顶层指令：`mba` 中按 block 链表顺序出现的 `minsn_t`，它们仍然决定 CFG 与“语句级”的顺序。
- 子树节点：
  - `minsn_t`：算子节点（例如 `mov/jz/goto/call/f2i/...`）
  - `mop_t`：操作数节点；当 `mop` 的 kind 为“嵌入指令”（常见表现为打印时出现 `mov call ...`、`f2f call ...`、`f2i((...))` 等）时，`mop` 内部携带一个 `minsn_t`，它本身就是一棵子树。

Extractor 的遍历边界必须是：**只把顶层 `minsn_t` 作为“语句（Instr）”导出**；而顶层指令内部出现的嵌套 `minsn_t`，统一当作表达式子树进行递归解析（并在需要时额外导出 call 信息）。

### 3.4.2 递归解析：从子树派生 Normalized Operand

目标：对任意顶层指令 `root`，构建一个可 hash 的“表达式表示”，并从中派生出稳定的 `reads/writes`。

推荐的实现形态：
- `parse_minsn(root_minsn) -> expr_operand`：把 `minsn_t` 规范化为 `kind="expr"` 的 Normalized Operand，其中 `v.op` 是 opcode，`v.args` 递归包含其子操作数。
- `parse_mop(mop) -> operand`：
  - 若为寄存器/常量/全局/栈槽/字符串引用：直接落到 `reg/const/global/stack/string`。
    - **注意**：对于 Global，需区分“读取值”与“取地址”。MicroCode 中通常通过 `mop_t` 的引用类型或上下文指令（如 `lea`）区分。Extractor 必须在 operand 中标记 `access_mode="read|addr"`，或通过操作数结构区分（例如 `global` vs `obj_addr`）。
  - 若为内存：落到 `mem`，并对 `mem.v.addr` 递归构建结构化地址表达式（见第 4 章）
  - 若为嵌入指令：递归调用 `parse_minsn(mop.insn)`
  - 其它无法稳定建模的形态：落到 `expr` 或 `unknown`，并尽量保留结构化字段

为了让“同一导出包可重复构建得到同样的 Expr/Mem ID”，递归解析必须满足：
- 只依赖 microcode 可见信息（不要把 Python 对象地址、遍历顺序号写入 operand）
- 在 `expr` 中固定参数顺序：与 microcode 的语义顺序一致（通常等同于打印顺序）
- 对字段做 canonical 化时删除 `repr`（见 4.4）

### 3.4.3 从子树派生 USE/DEF 与 calls（处理嵌套 call）

对每条顶层指令 `root`：
- 先递归解析得到 `root_expr = parse_minsn(root)`，它是该指令“折叠后”的语义树根。
- 然后在同一趟递归遍历中派生：
  - `writes`：指令在语义上写入的 carrier（寄存器/栈槽/内存/全局）。以顶层指令的“写目标”作为主来源，并对 store 类 opcode 视情况把 `mem` 作为写目标。
  - `reads`：指令在语义上读取的叶子值（寄存器/栈槽/全局/常量/字符串/内存地址表达式等）。原则是“所有出现在 RHS/条件/地址表达式/调用参数中的值都是 USE”。
  - `calls`（建议导出）：子树中出现的每一个 `call` 节点（不要求它是顶层 opcode）。这解决了 `MMAT_LVARS` 下 `call` 被折叠进 `mov/f2f/...` 后，线性扫描无法发现调用点的问题。

`calls` 的抽取规则：
- 当递归遍历遇到 `op == call/icall/...` 的 `minsn_t`：
  - 记录一个 call 事件（包含 `kind`、callee/target、args、ret）
  - 继续递归遍历其参数表达式（参数仍然贡献到顶层指令的 `reads`）
- 多个 call 在同一条顶层指令内出现时，按“求值顺序”排序写入 `calls` 数组（推荐使用后序遍历并按遍历序 append，以获得稳定顺序）。

### 3.4.4 示例：对 `MMAT_LVARS` microcode 做递归解析并导出

以用户提供的片段为例（省略 block 头）：

```text
1. 6  mov  call $fopen(... ) => "FILE *" .4, r0_1.4
1. 7  mov  r0_1.4, r4_1.4
1. 8  jz   r0_1.4, #0.4, @4
...
2. 7  call $sprintf(..., f2i.4((r0_2a.4 *f #(100.0).4))) => int .0
```

对 `1.6 mov call $fopen(...) => ..., r0_1.4`：
- 顶层 `minsn_t`（root）是 `mov`，但其 RHS 是一个“嵌入指令”的 `call` 子树。
- 递归解析时：
  - `writes`：`r0_1.4`（root 的写目标）
  - `calls[0]`：记录 `fopen` 的调用点，`args` 为两个字符串/全局引用，`ret` 绑定到 `r0_1.4`
  - `reads`：应至少包含 `calls[0]` 中的 `callee/args`（这样 Builder 即便不读取 `calls` 也能做保守的 USE/DEF）

对 `1.8 jz r0_1.4, #0.4, @4`：
- root 是条件跳转，子树通常不含嵌套指令，但仍沿用相同规则：
  - `writes`：空
  - `reads`：`r0_1.4` 与常量 `0`（条件表达式的叶子）
  - `calls`：空

对 `2.7 call $sprintf(..., f2i.4((r0_2a.4 *f #(100.0).4))) => int .0`：
- root 是 call，但参数中包含 `f2i` 与 `*f` 的嵌套子树。
- 递归解析时：
  - `calls[0]`：`sprintf`，其 `args` 中第 N 个参数是一个 `expr(op="f2i", args=[expr(op="mul_f", args=[r0_2a, 100.0])])`
  - `reads`：应包含 `r0_2a.4` 与常量 `100.0`（以及其它参数的叶子）
  - `writes`：若返回值被落到可追踪 carrier（寄存器/临时/变量），则导出；否则允许省略（例如返回值 `.0` 被丢弃的场景）

## 3.5 `functions.jsonl`（函数级导出契约）

`functions.jsonl` 每行一个函数记录。每条记录必须包含下列字段：

```json
{
  "func_ea": "0x401000",
  "name": "sub_401000",
  "type_str": "int __cdecl sub_401000(int a1)",
  "status": "ok|failed|skipped",
  "error": null,
  "microcode": {
    "maturity": "MMAT_LVARS",
    "blocks": [
      {
        "block_id": 0,
        "start_ea": "0x401000",
        "end_ea": "0x401020"
      }
    ],
    "cfg_edges": [
      {
        "src_block_id": 0,
        "dst_block_id": 1,
        "branch": "fallthrough|true|false|switch|exception|unknown"
      }
    ],
    "insns": [
      {
        "block_id": 0,
        "insn_idx": 0,
        "ea": "0x401004",
        "opcode": "m_mov",
        "text": "mov    call $fopen(...) => \"FILE *\" .4, r0_1.4",
        "reads": [
          {"role": "callee", "index": 0, "op": {"kind": "global", "...": "..."}},
          {"role": "arg", "index": 0, "op": {"kind": "global", "...": "..."}},
          {"role": "arg", "index": 1, "op": {"kind": "global", "...": "..."}}
        ],
        "writes": [
          {"role": "dst", "index": 0, "op": {"kind": "reg", "...": "..."}}
        ],
        "calls": [
          {
            "index": 0,
            "kind": "direct|indirect|unknown",
            "callee_name": "fopen",
            "callee_ea": null,
            "target": null,
            "args": [
              {"kind": "global", "...": "..."},
              {"kind": "global", "...": "..."}
            ],
            "ret": {"kind": "reg", "...": "..."}
          }
        ]
      }
    ]
  },
}
```

## 3.6 `globals.jsonl`（全局数据与常量）

为了支持跨函数的常量传播与污点分析，Extractor 必须导出全局数据段的信息。这包括全局变量、静态变量、字符串常量以及其他 `.rodata/.data` 段内容。

`globals.jsonl` 每行一条记录：

```json
{
  "ea": "0x403000",
  "name": "aNoMoreSpace",
  "demangled_name": null,
  "type": "char[]",
  "size": 15,
  "storage": "static|extern|public",
  "is_const": true,
  "content": {
    "type": "string|bytes|int|ptr|struct",
    "value": "No more space!",
    "encoding": "utf-8"
  },
  "refs": ["0x401000", "0x401020"]
}
```

字段说明：
- `ea`：数据的起始地址。
- `name`：符号名（IDA 中的 name）。
- `is_const`：是否位于只读段（如 `.rodata`）。
- `content`：
  - 若为字符串，提供解码后的文本。
  - 若为指针（如全局对象指针初始化），提供目标地址。
  - 若为简单标量（int），提供数值。
- `refs`：可选，列出引用该全局变量的指令地址或函数地址（Data XREF），辅助快速构建引用关系。

对于字符串常量，建议优先在此文件中导出，而非仅依赖 `strings.jsonl`。
  "decompilation": {
    "pseudocode": null,
    "ea_to_line": null
  }
}
```

约束：

- `reads` / `writes` 是 V1 的关键契约：Builder 仅基于它们生成 `USE/DEF`，不在离线侧做 opcode 语义推断。
- `text` 用于报告与调试，不参与等价判断。
- `calls` 字段用于承载折叠后的调用点：当 `MMAT_LVARS` 下 `call` 不再是顶层 opcode 时，Extractor 仍必须在 `calls` 中导出它们；其内容与 `reads/writes` 保持一致。
- `reads/writes[].role` 建议至少支持以下集合（实现可扩展，但必须在 Builder 中同步校验）：
  - `dst`：写目标
  - `src`：普通 RHS
  - `cond`：分支条件
  - `addr`：内存地址表达式（用于 `mem.v.addr` 或指针参数）
  - `callee`：调用目标（direct 时为 `global`，indirect 时可为 `expr`）
  - `arg`：调用参数（`index` 对应参数序号）

## 3.6 `imports.jsonl` / `exports.jsonl` / `strings.jsonl`

这三类文件为可选，但一旦存在必须满足以下最小字段：

- `imports.jsonl`：
  - `name`（符号名）
  - `ea`（若可得）
  - `module`（若可得）
- `exports.jsonl`：
  - `name`
  - `ea`
- `strings.jsonl`：
  - `ea`
  - `value`（UTF-8 字符串；无法解码则使用 `base64:<...>`）

## 3.7 失败与降级策略（V1）

- 若 `decompile(func_ea)` 失败：
  - 记录 `status="failed"`，`error` 写入异常摘要；
  - `microcode` 为 `null`。
- V1 不回退到反汇编级 CPG（避免数据契约膨胀）；回退作为 V2 选项引入。

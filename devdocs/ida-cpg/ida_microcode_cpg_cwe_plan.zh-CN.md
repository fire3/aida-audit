# 基于 IDA MicroCode 的二进制 CPG 构建与 CWE 扫描器设计方案（存档）

本文件为早期草案存档。可执行的 V1 设计已迁移到 Sphinx 文档工程：

- 源文档入口：[index.md](file:///Users/fire3/SRC/aida-mcp/devdocs/ida-cpg-sphinx/source/index.md)
- 生成 HTML：

```bash
python -m sphinx -b html devdocs/ida-cpg-sphinx/source devdocs/ida-cpg-sphinx/_build/html
```

## 摘要
本文给出一套从 **IDA Pro + Hex-Rays** 的 **MicroCode**（中间表示）出发，抽取控制流/数据流并落地为 **CPG（Code Property Graph）** 的实现方案，并基于该图设计若干面向真实漏洞场景的 **CWE 扫描器**。方案强调：
- 尽量复用 IDA/Hex-Rays 产物（函数边界、调用关系、类型信息、MicroCode CFG）。
- 使用轻量级 Python 图引擎（以 `networkx` 或 `igraph` 为主）实现属性图与查询。
- 将“抽取（IDA 内）”与“分析（IDA 外）”拆分，降低对 IDA 运行时的耦合与性能瓶颈。

## 1. 目标与非目标

### 1.1 目标
- **MicroCode 抽取**：对每个函数生成 MicroCode，并抽取：
  - MicroCode 基本块图（mblock CFG）
  - 指令序列（minsn）
  - 表达式/变量/内存访问（mop / lvars / stkvars / gvars）
  - 关键元信息（地址、反编译伪代码行号映射、调用目标、常量、类型）
- **CPG 落地**：构建单程序/单二进制的属性图，至少包含：
  - CFG（控制流）
  - DFG/PDG 子集（def-use、简单依赖）
  - Call Graph（跨过程调用）
  - “表达式树”或“指令操作数图”（类 AST）
- **CWE 扫描器**：以 CPG 查询 + 数据流/污点传播为核心，覆盖若干高价值场景，并输出可定位的证据链（地址、函数、路径、关键边/点）。
- **可扩展**：规则可配置（sources/sinks/sanitizers、API 模型、结构体布局、ABI 约束），并可逐步加强跨过程分析。

### 1.2 非目标（第一阶段不做或弱化）
- 不追求完整语义等价的源级 AST（对二进制不现实）。
- 不做“全局精确”的跨过程指针分析/别名分析；第一阶段采用保守近似 + 规则补丁。
- 不实现重型图数据库（Neo4j/JanusGraph 等）；先用轻量库与本地持久化满足迭代。

## 2. 总体架构

### 2.1 两阶段流水线
1) **IDA 内抽取（Extractor）**
- 输入：已完成分析的 IDB / i64（建议开启类型恢复、库识别）。
- 输出：结构化数据包（建议 JSONL + 二进制块/压缩），包含每个函数的 microcode 与辅助信息。

2) **IDA 外构建与分析（Builder/Analyzer）**
- 输入：Extractor 的输出数据包。
- 输出：
  - CPG（内存图 + 可选持久化）
  - 扫描结果（findings.jsonl / sarif）

这样做的好处：IDA 只负责“昂贵且绑定授权/GUI”的抽取；图构建与扫描在纯 Python 环境可并行、可 CI。

### 2.2 模块划分
- `extractor_ida/`（在 IDA 运行）
  - 函数遍历、MicroCode 生成、基础信息抽取、序列化导出
- `cpg/`（离线）
  - 图数据结构与 schema
  - MicroCode→CPG 规范化转换
  - CFG/DFG/CG 组装
  - 查询与遍历 API（类似 Joern 的最小可用子集）
- `analysis/`
  - 数据流：def-use、简单 reaching definitions、局部污点
  - 跨过程：调用解析、函数摘要（summary）与污点摘要
- `scanners/`
  - CWE 规则与执行器
  - 报告生成与去重、置信度打分

## 3. IDA/Hex-Rays MicroCode 抽取设计

### 3.1 依赖与前置条件
- 需要 **Hex-Rays Decompiler** 授权（MicroCode 属于反编译器能力范围）。
- 固定 IDA 版本区间（9.2+），并将 MicroCode API 差异封装在兼容层里。
- 对于无法反编译的函数：
  - 允许回退到反汇编级（insn/operand）构建弱 CPG，或直接跳过（可配置）。

### 3.2 抽取对象与最小字段
对每个函数 `f` 抽取：
- 基础信息
  - `func_ea` / `name` / `size`
  - `segment` / `module`（如果是多文件装载）
  - `calling_convention`（可选）
  - `type_signature`（尽可能：返回值、参数）
- 反编译相关
  - 伪代码（可选保存，主要用于报告展示）
  - 伪代码行与地址映射（用于定位证据）
- MicroCode 相关
  - `maturity`（microcode maturity level）
  - 基本块集合（mblock id → 起止地址/范围）
  - CFG 边（block → block，边类型：顺序/条件真/条件假/异常等，尽可能）
  - 每块指令序列（minsn 列表）
  - 每条指令：
    - opcode
    - `ea`（尽量绑定到原始地址）
    - 左值/右值操作数（mop：寄存器、栈变量、全局、内存、常量、调用返回等）
    - 对调用指令，抽取可能的 callee（直接/间接）与参数 mop 列表

### 3.3 MicroCode 生成策略
建议在每个函数上：
- `decompile(func_ea)` 获取 cfunc
- 从 cfunc 获取 microcode（mba），并选择固定 maturity（例如较稳定且信息足够的成熟度）
- 遍历 `mba` 的 block 与 insn
- 尽可能提取 `minsn.ea` 与 `mop` 的来源信息

关键点：
- MicroCode 是 SSA-like 还是非 SSA：不同 maturity/阶段会影响 def-use 获取方式；方案应“先能跑”，不强依赖 SSA。
- 间接调用：优先结合 IDA 的 xrefs、类型签名、vtable 识别结果、以及 microcode 中的 callee mop 形态做保守解析。

### 3.4 序列化与导出格式
建议输出一个目录包（zip/tar.zst）：
- `meta.json`：二进制信息（hash、arch、endian、imagebase、ida version、compiler hints）
- `functions.jsonl`：每行一个函数的结构化记录（便于流式处理）
- `strings.jsonl`：字符串表（ea、内容、引用点，可选）
- `imports.jsonl` / `exports.jsonl`：导入导出符号（用于 API 建模）

字段体量较大时：
- `functions.jsonl` 中对每个函数的 `microcode` 字段可做二进制压缩（例如 msgpack + zstd，再 base64）；
- 或者拆分成 `functions/<func_ea>.json` 单文件，利于增量更新与缓存。

## 4. CPG Schema 设计（轻量属性图）

### 4.1 属性图抽象
CPG 统一建模为：
- 顶点集合 `V`：节点带属性（字典）
- 边集合 `E`：有向边带类型与属性

在 Python 里可选：
- `networkx.MultiDiGraph`：实现简单，节点/边属性直观，适合原型与中小规模。
- `igraph`：更高性能，适合大图（需自己管理属性列与边类型编码）。

建议第一阶段用 `networkx`，当规模上来再提供 `igraph` 后端。

### 4.2 节点类型（Node Kinds）
最小可用集合（可以按需扩展）：
- `Program`：二进制整体
- `Function`：函数
- `Block`：MicroCode 基本块
- `Instr`：MicroCode 指令（minsn）
- `Expr`：操作数/表达式节点（mop，或“规范化后的 operand”）
- `Var`：变量（local/stack/reg/global）
- `Mem`：内存访问抽象（base+offset+size+region）
- `CallSite`：调用点（与 `Instr` 可一一对应，也可抽象出来）
- `Const`：常量
- `String`：字符串字面量（来自二进制数据段）
- `Type`：类型节点（可选，支持逐步增强）

推荐在每个节点上统一放这些公共属性：
- `id`（全局唯一字符串或 int）
- `kind`
- `ea`（若可定位到地址）
- `func_ea`（所属函数）
- `name`（可选）
- `size_bits` / `type_str`（可选）

### 4.3 边类型（Edge Kinds）
CPG 常见边的二进制适配版本：
- 控制流
  - `CFG_NEXT`：Block→Block 或 Instr→Instr
  - `CFG_COND_TRUE` / `CFG_COND_FALSE`
- 语法/结构（类 AST）
  - `HAS_INSTR`：Function→Instr 或 Block→Instr
  - `HAS_OPERAND`：Instr→Expr（按序号/角色：dst/src1/src2）
  - `HAS_CHILD`：Expr→Expr（表达式树）
- 数据流
  - `DEF`：Instr→Var/Expr（写入）
  - `USE`：Instr→Var/Expr（读取）
  - `REACHING_DEF`：DEF 点→USE 点（后续分析阶段生成）
- 调用
  - `CALLS`：CallSite→Function（直接解析）
  - `CALL_TARGET`：CallSite→Expr（间接调用时的目标表达式）
  - `ARG`：CallSite→Expr（参数，带 index）
  - `RET`：CallSite→Var/Expr（返回值绑定）
- 指向/内存
  - `ADDR_OF` / `DEREF`
  - `POINTS_TO`（可选：近似别名/指向关系）

### 4.4 “规范化操作数”表示（关键）
MicroCode 的 `mop` 形态复杂且版本相关。建议在抽取阶段就做一层“规范化”，把 `mop` 转成稳定的 JSON 结构：
- `kind`: reg / stkvar / lvar / gvar / mem / const / helper / callret / phi / unknown
- `repr`: 可读串（便于调试与报告）
- `bits`: 位宽
- 若是 `mem`：
  - `base`: 子 operand（可能是 reg/var）
  - `index`: 子 operand（可选）
  - `scale`: int（可选）
  - `disp`: int（可选）
  - `segment`: 可选
  - `region`: stack/heap/global/unknown（启发式推断）

这一层稳定后，CPG 的 `Expr/Var/Mem` 节点就能跨版本保持一致。

### 4.5 标识符与命名空间（实验落地必备）
为了让图可持久化、可增量更新、可跨工具关联，建议统一一套稳定的 ID 方案。

#### 4.5.1 全局命名空间
- `binary_id`：建议 `sha256`（或 `md5`）标识当前二进制输入，所有节点/边都带该字段（或通过 Program 节点关联）。
- `imagebase`：用于把 `ea` 转换为 RVA（便于跨重定位比较）。
- `func_ea`：函数粒度的主键（在同一 `binary_id` 内唯一）。

#### 4.5.2 NodeId 建议编码（可读且可 debug）
第一阶段建议用字符串 ID（后续可映射为 int）：
- `P:<binary_id>`：Program
- `M:<module_name>`：Module（可选）
- `F:<func_ea_hex>`：Function
- `B:<func_ea_hex>:<block_id>`：Block（block_id 取 microcode mblock 序号）
- `I:<func_ea_hex>:<block_id>:<insn_idx>`：Instr（insn_idx 为 block 内序号）
- `C:<func_ea_hex>:<callsite_ea_hex>`：CallSite（优先用 `ea`，无 `ea` 用 `I:*` 绑定）
- `V:<func_ea_hex>:<var_key>`：Var（var_key 由 var kind + stable key 组成）
- `E:<func_ea_hex>:<expr_hash>`：Expr（expr_hash 为规范化 operand 的 stable hash）
- `K:<bits>:<value_hash>`：Const（按位宽与值归一）
- `S:<string_ea_hex>`：String
- `T:<type_hash>`：Type

原则：
- **同一语义实体尽量复用同一个节点**（例如同一个局部变量、同一个字符串常量）。
- **Instr/Block 节点必须一一对应 microcode 结构**，避免后续 CFG/DFG 对齐困难。

### 4.6 节点设计（细化字段）
下面给出推荐的节点字段（`props` 指可扩展字典）。

#### 4.6.1 Program
用途：把一个图绑定到“一个二进制输入 + 一次 IDA 抽取”。
- 必填属性：
  - `kind="Program"`, `binary_id`, `arch`, `endian`, `imagebase`
- 推荐属性：
  - `ida_version`, `compiler`, `os_abi`, `bitness`, `extract_time`, `extractor_version`

#### 4.6.2 Function
用途：跨过程分析与报告定位的第一入口。
- 必填属性：
  - `kind="Function"`, `func_ea`, `name`
- 推荐属性：
  - `rva`, `size`, `is_thunk`, `is_external`, `segment`
  - `type_str`（若有），`calling_convention`（若可得）
  - `hash`（对 microcode/指令序列做稳定 hash，支持增量）

#### 4.6.3 Block
用途：CFG 的基本单元、支配关系与路径分析的载体。
- 必填属性：
  - `kind="Block"`, `func_ea`, `block_id`
- 推荐属性：
  - `start_ea`, `end_ea`（若可得），`succ_count`, `pred_count`
  - `block_flags`（条件块/异常边等信息，尽可能从 microcode 侧恢复）

#### 4.6.4 Instr
用途：数据流的最小事件节点（def/use/内存读写/调用）。
- 必填属性：
  - `kind="Instr"`, `func_ea`, `block_id`, `insn_idx`, `opcode`
- 推荐属性：
  - `ea`（强烈建议），`rva`
  - `maturity`（microcode stage）
  - `text`（规范化指令展示串，用于报告，不要求可逆）

#### 4.6.5 CallSite
用途：把“调用事件”从 Instr 中抽象出来，便于统一处理参数、目标与返回值。
- 必填属性：
  - `kind="CallSite"`, `func_ea`
- 推荐属性：
  - `ea`（若有），`callee_name`（若能解析），`call_kind`（direct/indirect/syscall/vcall）
  - `convention`（若能推断）

CallSite 与 Instr 的关系建议用边表达：
- `CALLSITE_OF`：CallSite→Instr（或 Instr→CallSite 二选一，但保持一致）

#### 4.6.6 Var（强烈建议做成“位置 + 名称”的组合）
用途：污点/def-use 的 carrier；在二进制里“变量”往往是“某个位置”。
建议把 Var 分为几类，并统一一个 `var_kind` 字段：
- `var_kind="reg"`：寄存器（如 `rax`）
- `var_kind="stack"`：栈槽（如 `[rbp-0x20]`）
- `var_kind="local"`：Hex-Rays lvar（若可得，映射到 stack/reg 也行）
- `var_kind="global"`：全局地址（如 `0x140012340`）
- 必填属性：
  - `kind="Var"`, `func_ea`（对 global 可空或设为 0），`var_kind`, `repr`
- 推荐属性：
  - `bits`, `type_str`
  - `reg`（当 var_kind=reg）
  - `stack_off`（当 var_kind=stack，统一用“相对 SP 或 FP”的一套 offset）
  - `g_ea`（当 var_kind=global）

#### 4.6.7 Expr（规范化 operand/表达式）
用途：把“某个具体用法的表达式”节点化，便于表达式级数据流（例如 `p+4`）。
- 必填属性：
  - `kind="Expr"`, `func_ea`, `expr_kind`, `repr`
- 推荐属性：
  - `bits`, `hash`, `props`（保存规范化 operand JSON）

说明：
- `Var` 用于“可被多次引用的符号实体/位置”；
- `Expr` 用于“某条指令中的一个值表达式”；
- 实验阶段可以先把所有 operand 都当 Expr，再在归一阶段把部分 Expr 归并到 Var（例如纯寄存器/纯栈槽）。

#### 4.6.8 Mem（可选但对 CWE 很有价值）
用途：把内存访问建模成可查询实体，尤其是越界/空指针/UAF 这类场景。
- 必填属性：
  - `kind="Mem"`, `func_ea`, `repr`
- 推荐属性：
  - `bits`, `region`（stack/heap/global/unknown）
  - `addr_expr_hash`（地址表达式的 hash，指向对应 Expr）
  - `disp`, `scale` 等（来自规范化 operand）

常见两种策略：
- 策略 A：不单独建 Mem 节点，直接用 Expr（mem kind）表示内存访问。
- 策略 B：Mem 独立成节点，Expr 只表示“地址计算”，Mem 表示“在该地址上的 load/store 位置”。
对后续做 UAF/越界写，策略 B 更清晰。

#### 4.6.9 Const/String/Type
- Const：
  - `kind="Const"`, `bits`, `value`（建议同时保存 `value_u` 与 `value_s` 或保存 `raw` + 解释）
- String：
  - `kind="String"`, `ea`, `value`（UTF-8/bytes 的表示需要约定）
- Type（第一阶段可弱化）：
  - `kind="Type"`, `type_str`, `size_bits`，以及可选的 `type_kind`（ptr/int/struct/array/func）

### 4.7 边设计（细化语义与字段）
建议所有边都带：
- `kind`：边类型（字符串或 int code）
- `binary_id`（若不通过 Program 关联）
- 可选：`func_ea`（若边在函数内）

#### 4.7.1 结构与归属边
- `HAS_BLOCK`：Function→Block（`index` 为拓扑或 block_id）
- `HAS_INSTR`：Block→Instr（`index=insn_idx`）
- `HAS_OPERAND`：Instr→Expr/Var/Const/String/Mem（字段：`role` + `index`）
  - `role` 建议枚举：`dst`, `src`, `cond`, `addr`, `value`, `callee`, `arg`, `ret`
- `HAS_CHILD`：Expr→Expr（表达式树，字段：`index`）

#### 4.7.2 控制流边
推荐 Block 级为主，Instr 级为辅：
- `CFG_BB`：Block→Block（字段：`branch`）
  - `branch` 枚举：`fallthrough`, `true`, `false`, `switch`, `exception`, `unknown`
- `CFG_INS`：Instr→Instr（可选，用于细粒度路径与切片）

#### 4.7.3 数据流边
基础边（抽取/构建阶段即可生成）：
- `DEF`：Instr→Var/Expr/Mem（字段：`role`，例如 `dst`/`mem_write`）
- `USE`：Instr→Var/Expr/Mem/Const/String（字段：`role`）

派生边（分析阶段生成）：
- `REACHING_DEF`：Instr(def)→Instr(use)（字段：`var_key` 或 `expr_hash`）
- `TAINT`：SourceNode→SinkNode（字段：`rule_id`, `path_hash`，可选）

约定：
- `DEF/USE` 的落点尽量指向 `Var/Mem` 而不是“临时 Expr”，否则变量级切片会很碎。
- 若短期内无法建立 Var（例如寄存器重命名困难），可先落到 Expr，后续再加归并层。

#### 4.7.4 调用边
建议统一通过 CallSite 承载调用：
- `CALLSITE_OF`：CallSite→Instr
- `ARG`：CallSite→Expr/Var/Const/String（字段：`index`, `passing`）
  - `passing`：`reg`/`stack`/`unknown`（可选）
- `CALLS`：CallSite→Function（直接调用能解析时）
- `CALL_TARGET`：CallSite→Expr（间接调用目标表达式）
- `RET`：CallSite→Var/Expr（返回值绑定，字段：`ret_index`，多数为 0）

外部函数建议也建成 Function 节点，但标记 `is_external=true`：
- 好处：sink/source 模型统一走 CALLS→Function 的查询。
- 若不想把 externals 放进 CFG/函数集合，也可单独用 `ExternalFunction` 节点；但会增加规则复杂度。

### 4.8 规范化操作数（Normalized Operand）建议 Schema（可直接用于 JSON）
目标：把 Hex-Rays `mop_t` 变成稳定、可 hash、可持久化的结构，且能在离线侧重建 Expr/Var/Mem 节点。

建议结构（示意）：
```json
{
  "kind": "mem",
  "bits": 64,
  "repr": "[rbp-0x20]",
  "mem": {
    "region": "stack",
    "base": {"kind": "reg", "bits": 64, "repr": "rbp", "reg": "rbp"},
    "index": null,
    "scale": 1,
    "disp": -32,
    "segment": null
  }
}
```

各 kind 推荐字段：
- `reg`：
  - `reg`：架构无关的寄存器名（例如 `rax`、`x0`），并统一大小写
- `stack`（若直接导出栈槽）：
  - `stack_off`：统一基准（建议 FP 相对或 SP 相对二选一）
- `global`：
  - `g_ea`：绝对地址（并同时保存 `rva` 以抗 imagebase 变化）
- `const`：
  - `value`：建议保存 0x 前缀十六进制字符串以避免 Python 大整数/符号位歧义
- `mem`：
  - `base/index/scale/disp`：地址计算要素
  - `region`：启发式推断（stack/heap/global/unknown）

稳定 hash 建议：
- 对 operand JSON 做 canonical json（排序 key、去掉 `repr` 这类非语义字段）后 hash。
- `repr` 保留给报告与调试，但不参与等价判断。

### 4.9 “位置（Location）”与内存区域模型（为 UAF/越界/空指针做准备）
二进制分析中，很多规则并不关心“变量名”，而关心“这个写发生在什么位置”。建议引入一个统一概念：
- `Location`：可以是 reg、stack slot、global addr、heap object + offset、unknown

落地方案（两种选一）：
- 方案 A：用 `Var`/`Mem` 节点承载 Location（推荐第一阶段）
- 方案 B：显式引入 `Location` 节点，并让 Var/Mem/Expr 指向 Location

若采用方案 A，至少保证：
- `Var(var_kind=stack, stack_off=...)` 是稳定的
- `Var(var_kind=global, g_ea=...)` 是稳定的
- `Mem(region=heap, ...)` 可先标 unknown，再通过 malloc/free 模型增强

### 4.10 类型系统（Type）在 Schema 中的最小落点
类型对误报率影响很大，但第一阶段不宜做得过重。建议按“可用即上”的方式：
- 节点上直接挂 `type_str`（来自 IDA/Hex-Rays 的打印串）
- 若要结构化：
  - 建 `Type` 节点并用 `HAS_TYPE` 边连接：Var/Expr/Mem→Type
  - `Type` 节点只需要 `type_kind`（ptr/int/struct/array/func/unknown）与 `size_bits`

结构体字段（非常有助于规则编写）建议增量引入：
- `Field` 节点：`struct_name`, `field_off`, `field_name`, `field_type`
- `FIELD_AT` 边：Mem/Expr→Field（当识别出 `base + off` 对应字段时）

### 4.11 图不变式（Invariants）与最小索引建议
为了保证实验可复现、规则可移植，建议约定以下不变式：
- 每个 Function 必有 0..n 个 Block；每个 Block 必有 0..n 个 Instr。
- Block CFG（`CFG_BB`）在同一 Function 内闭合，不跨函数。
- 每条 Instr 的 `ea` 若存在，应能映射回一个地址范围（用于定位）。
- CallSite 必须能回链到某个 Instr（`CALLSITE_OF`），否则证据难以呈现。

离线侧建议建立最小索引（无论用内存字典还是 SQLite）：
- `by_kind[kind] -> node_ids`
- `by_func[func_ea] -> {blocks, instrs, callsites}`
- `by_ea[ea] -> node_ids`（Instr/CallSite/String）
- `calls_by_callee[name] -> callsite_ids`（导入符号名）

### 4.12 示例：把一条 memcpy 调用编码为图（便于对照实现）
假设在 `0x401234` 有 `memcpy(dst, src, n)`：
- 节点：
  - `I:401000:3:12`（opcode=call, ea=0x401234）
  - `C:401000:401234`（call_kind=direct, callee_name=memcpy）
  - `F:...memcpy`（is_external=true）
  - `V:401000:stack:-0x20`（dst）
  - `V:401000:stack:-0x80`（src）
  - `E:401000:<hash(n)>`（n 的表达式）
- 边：
  - `CALLSITE_OF(C→I)`
  - `ARG(C→dst, index=0)`
  - `ARG(C→src, index=1)`
  - `ARG(C→n, index=2)`
  - `CALLS(C→F_memcpy)`
  - `USE(I→dst/src/n)`（可选：也可把 USE 放到 CallSite，统一由扫描器处理）

## 5. MicroCode → CPG 的构建流程

### 5.1 输入契约（Extractor → Builder）
为保证离线侧可重建第 4 章的 schema，建议对每个函数记录至少包含：
- `binary_id`、`imagebase`、`arch` 等 Program 级元信息（可放 `meta.json`）
- `func_ea`、`name`、`type_str` 等 Function 元信息
- microcode 结构：
  - `maturity`
  - blocks：`block_id`, `start_ea/end_ea`（可选但强烈建议）
  - cfg_edges：`src_block_id`, `dst_block_id`, `branch`
  - insns：按 block 切分，每条包含 `opcode`, `ea`（建议），以及 operand 列表（必须是“规范化 operand JSON”，见 4.8）
- callsite 信息：
  - 对 call 指令：callee 解析结果（direct/indirect/unknown），以及参数 operand 列表（已规范化）

### 5.2 全局初始化（Program / 外部符号）
1) 创建 `Program` 节点 `P:<binary_id>` 并填充元信息字段（见 4.6.1）。
2) 载入 `imports/exports/strings`（若有），用于：
   - 构建外部 `Function(is_external=true)` 节点（建议做，统一 CALLS 模型）
   - 构建 `String` 节点与引用索引（便于 format/path/command 等规则）
3) 初始化最小索引（见 4.11）：
   - `by_kind`、`by_func`、`by_ea`、`calls_by_callee`

### 5.3 函数级构建（强制按第 4 章 ID 与不变式）
对每个函数 `f(func_ea)`，按如下顺序构建，保证“先节点后边”“先归属后语义”。

#### 5.3.1 创建 Function / Block / Instr（结构骨架）
- 创建 `Function` 节点 `F:<func_ea_hex>`，填充 `func_ea/name/type_str/hash/...`（见 4.6.2）。
- 对每个 microcode block：
  - 创建 `Block` 节点 `B:<func_ea_hex>:<block_id>`（见 4.6.3）
  - 建 `HAS_BLOCK(Function→Block)`
- 对每个 block 内指令：
  - 创建 `Instr` 节点 `I:<func_ea_hex>:<block_id>:<insn_idx>`（见 4.6.4）
  - 建 `HAS_INSTR(Block→Instr, index=insn_idx)`
- 创建 Block CFG：
  - 建 `CFG_BB(Block→Block, branch=...)`（见 4.7.2）
- 可选：建立 `CFG_INS(Instr→Instr)`（仅当你需要指令级路径/切片时再做）

此阶段完成后，至少满足 4.11 的结构不变式：Function→Block→Instr 与 Block CFG 闭合。

#### 5.3.2 规范化 operand → Expr/Var/Mem/Const/String（实体化与复用）
目标：把“指令中的 operand JSON”映射到稳定节点，并尽可能复用（intern）。

建议实现一个统一的映射函数 `intern_operand(func_ea, operand_json) -> node_id`，其行为：
- `reg/stack/global/local`：
  - 生成/复用 `Var` 节点 `V:<func_ea_hex>:<var_key>`（见 4.6.6）
  - `var_key` 建议由 `var_kind + stable key` 组成（例如 `reg:rax`、`stack:-0x20`、`global:0x140012340`）
- `const`：
  - 生成/复用 `Const` 节点 `K:<bits>:<value_hash>`（见 4.6.9）
- `string`（若 operand 能解析到 string ea）：
  - 复用 `S:<string_ea_hex>`
- `mem`：
  - 两阶段策略：
    - 先为地址表达式建 `Expr`（hash 基于 canonical operand JSON，见 4.8）
    - 再按策略 A/B 决定是否创建 `Mem` 节点（见 4.6.8）
  - 若创建 Mem，建议 Mem 的稳定 key 至少包含：`region + addr_expr_hash + bits`
- 其它（helper/callret/phi/unknown）：
  - 先落为 `Expr` 节点（保留 `expr_kind/repr/bits/props`），避免丢信息

#### 5.3.3 指令结构边（HAS_OPERAND / HAS_CHILD）
对每条 `Instr`：
- 把指令的 dst/src/cond/addr/value/callee/args 等 operand 全部通过 `intern_operand` 变成节点
- 建 `HAS_OPERAND(Instr→*, role=..., index=...)`
- 若 operand JSON 带子表达式（例如 mem 的 base/index），按需建 `HAS_CHILD(Expr→Expr)`

建议约束：
- `HAS_OPERAND` 的 `role` 与 `index` 必须稳定，否则规则与缓存难以复用。

#### 5.3.4 DEF/USE 边生成（先局部正确，再逐步增强）
在第 4.7.3 的约束下生成 `DEF/USE`：
- `DEF` 优先落点：
  - 赋值/运算：落到 `Var`（如 reg/stack/local），其次才是 Expr
  - 内存写：落到 `Mem`（若建 Mem），否则落到 mem-kind Expr
- `USE` 落点：
  - 所有读取的 `Var/Mem/Expr/Const/String`

opcode 到读写角色映射建议分层：
- 第一层：只覆盖你要做的 CWE 规则最常见 opcode（call、assign、load/store、cmp/branch）
- 第二层：补全算术、位运算、类型转换、phi 等（并可按 maturity 版本化）

块间数据流不要在构建期硬连：
- 先把 `DEF/USE` 边做“事件事实”，把 reaching defs / taint 作为分析期派生边（`REACHING_DEF`/`TAINT`）。

#### 5.3.5 CallSite 构建（统一调用语义）
当 `Instr` 为调用语义（direct/indirect/vcall/syscall）：
- 创建 `CallSite` 节点 `C:<func_ea_hex>:<callsite_ea_hex>`（无 `ea` 时用 `C:<instr_id>` 替代）
- 建 `CALLSITE_OF(CallSite→Instr)`
- 对参数：
  - 建 `ARG(CallSite→node, index=i, passing=...)`
- 对目标：
  - direct：建/复用 callee `Function(is_external=...)`，并建 `CALLS(CallSite→Function)`
  - indirect：建 `CALL_TARGET(CallSite→Expr)`，并把“可能的 callee 集”放在 CallSite props（可选）
- 对返回值：
  - 若能识别返回值落点（某 reg/var），建 `RET(CallSite→Var/Expr)`

### 5.4 图后处理（索引、持久化、增量）
构建完所有函数后：
- 补全/刷新索引（见 4.11），并做一致性校验（见 5.5）
- 可选持久化：
  - `nodes/edges` 表或 Parquet 输出（见 7.2）
- 增量构建建议：
  - 以 `Function.hash`（microcode/insn 序列 hash）判断该函数子图是否需要重建
  - 重建时按 `by_func[func_ea]` 先删后建（避免 dangling edges）

### 5.5 DEF/USE 判定策略
MicroCode opcode 的写/读语义需要一个映射表（可版本化配置）：
- 赋值类：`x = y`：dst 为 DEF，src 为 USE
- 二元运算：`x = y op z`：x DEF，y/z USE
- 比较/条件：USE
- 内存写：`*(addr) = v`：addr USE，v USE，Mem DEF（也可表示为 “写内存”事件）
- 内存读：`x = *(addr)`：addr USE，x DEF
- 调用：callee/args USE；返回值 DEF（若可绑定到某 var）

第一阶段可以做到：
- **块内**精确（按顺序串联）
- **块间**保守（先不连 REACHING_DEF，或用简单的 reaching defs 分析生成）

### 5.6 构建期一致性校验（建议强制）
为了保证扫描器与证据链稳定，建议在构建完成后做最小校验：
- 结构校验：每个 CallSite 必有 `CALLSITE_OF`；每个 Instr 必属于某 Block；每个 Block 必属于某 Function
- CFG 校验：`CFG_BB` 不跨函数；所有 block_id 在节点集合中存在
- 地址校验：若 Instr/CallSite 有 `ea`，则 `by_ea[ea]` 可反查到该节点
- 角色校验：`HAS_OPERAND.role/index` 必在预定义集合里，且 index 连续/稳定（按抽取数据）

### 5.7 地址与伪代码定位（输出证据链）
扫描器输出必须能回到 IDA 视图（见 4.6.4/4.6.5）：
- 每个 `Instr`/`CallSite` 节点尽量保存 `ea`（或可逆的定位信息）
- 每个 finding 至少包含：
  - `func_ea`
  - `sink_ea`（或 callsite_ea）
  - `path`：Instr/CallSite 的 `ea` 列表（可截断）
  - `evidence`：关键节点/边 id 列表（source→…→sink 链）
  - `decomp_line`：若 extractor 提供 `ea→伪代码行` 映射则附带

## 6. 分析能力分层（从易到难）

### 6.1 Level 0：图查询 + 模式匹配
适合：
- 危险 API 直接调用（strcpy/memcpy/sprintf/system 等）
- 缺少检查的 API 调用（如 `recv` 后未检查返回值就使用长度）
- 简单逻辑缺陷（如 `if (len > buf_size)` 的比较方向错误可做启发式）

实现方式：
- 基于 CallSite/ARG 的结构化查询
- 结合常量、字符串参数、导入符号名做规则匹配

### 6.2 Level 1：函数内污点传播（intra-procedural taint）
适合：
- 由输入到危险函数参数的传播（同一函数内）
- 由长度字段到 memcpy/memmove 的 size 参数传播

核心：
- 将 `Var/Mem` 作为 taint carrier
- 以 `DEF/USE` + 指令语义作为传播规则
- 遇到调用：使用函数摘要（见 6.4）或保守截断

### 6.3 Level 2：跨基本块数据流（reaching defs + path feasibility 近似）
适合：
- 需要穿过 if/loop 的传播
- 判断某检查是否支配（dominate）sink

核心：
- 构建 CFG 后做：
  - dominator（支配关系）用于“检查覆盖”判定
  - reaching definitions 用于建立 REACHING_DEF 边
- 可用近似的路径约束：只识别最常见的比较/范围检查模式，不做 SMT。

### 6.4 Level 3：跨过程污点（inter-procedural summaries）
对二进制来说，精确跨过程很难，但可用“函数摘要”逐步增强：
- 对每个函数计算摘要：
  - 哪些参数/全局/内存区域会影响返回值
  - 哪些参数会被写（out-params）
  - 是否调用了敏感 sink（用于报警）
- 在 callsite 传播时使用摘要替代内联展开，避免爆炸。

## 7. 轻量图引擎与持久化方案

### 7.1 运行时图引擎（内存）
- 原型：`networkx.MultiDiGraph`
  - 节点 id：`"F:401000"`、`"I:401234:17"` 这类可读编码，或整数自增
  - 边属性：`{"kind": "DEF", "index": 0}`
- 大规模：`igraph.Graph(directed=True)` + 边类型用 int 编码

### 7.2 持久化（可选但很实用）
轻量且可控的组合：
- **SQLite** 存 node/edge 表（适合离线检索与增量）
- 或者 **Parquet**（列式存储，适合批处理与向量化过滤）

推荐的最小表：
- `nodes(id PRIMARY KEY, kind, func_ea, ea, name, props_json)`
- `edges(src, dst, kind, props_json)`

这样扫描器既可以：
- 直接走内存图遍历（快，适合单次扫描）
- 也可以先用 SQL 过滤候选（例如所有调用 memcpy 的 callsites），再加载子图做深入分析（省内存）

## 8. CWE 扫描器设计（场景优先）

### 8.1 规则框架（统一抽象）
每个扫描器建议统一为：
- `metadata`：CWE、名称、严重性、置信度策略
- `matcher`：候选 sink/source 的图查询（缩小搜索空间）
- `analysis`：对每个候选做数据流/控制流验证
- `report`：输出证据（路径、关键节点、参数、常量、字符串）

并提供共享的“模型库”：
- **Sources**：网络输入、文件读取、环境变量、IPC、argv、注册表等
- **Sinks**：危险 API、危险指令模式（间接跳转写控制流等）
- **Sanitizers/Checks**：长度检查、白名单校验、格式化限制等

### 8.2 优先实现的扫描器清单（建议）
下面给出一组适合二进制落地、性价比高的 CWE 场景与检测思路（均可先做 Level 0/1，再逐步加强到 Level 2/3）。

#### CWE-121 / CWE-122：栈/堆缓冲区溢出（危险拷贝）
目标：
- `strcpy/strcat/sprintf/gets` 等无界函数调用
- `memcpy/memmove/strncpy/snprintf` 等“有界但长度可控”调用

检测：
- Level 0：
  - 直接命中无界 API：立刻出报告（高置信）
  - 对 memcpy 类：若 size 参数为非常量且来自 source（用户输入/网络）则报警（中置信）
- Level 1/2：
  - 污点从 source→size/len 参数传播
  - 检查是否存在支配 sink 的范围校验（`len <= buf_size`）

证据：
- callsite 地址、callee 名称
- 参数表达式 repr
- 从 source 到 size 的 def-use 链

#### CWE-134：格式化字符串漏洞
目标：
- `printf/fprintf/sprintf/syslog` 等格式化输出

检测：
- Level 0：
  - 若 format 参数不是常量字符串（或来自外部输入）则报警
- Level 1：
  - 污点传播：source→format 参数
- 进一步：
  - 区分 `%n` 高危（如果能解析格式串常量）

#### CWE-190 / CWE-680：整数溢出导致分配/拷贝错误
目标：
- `malloc/calloc/realloc/new` 的 size
- `memcpy/memmove` 的 size

检测（启发式可先做）：
- 若 size 来自 `a * b`、`a + k` 等计算且 a/b 可控（taint），并且缺少溢出检查（例如乘法后比较、或使用安全乘法 helper），则报警
- 若分配 size 与后续拷贝 size 不一致（拷贝更大），报警

#### CWE-787：越界写（数组索引/指针算术）
目标：
- 对内存写 `*(base + idx*scale + disp) = v` 的 idx

检测：
- 识别 idx 来自 taint，且写发生前缺少范围检查（基于 dominator + 常见比较模式）
- 结合 region：stack/heap/global，优先 stack/heap

#### CWE-476：空指针解引用
目标：
- `*(p)` 或 `p->field` 形式的内存读写

检测：
- 若 p 可能为 0（来自返回值、未初始化、条件赋值），且解引用前不存在 `p != 0` 之类支配检查，则报警

#### CWE-401 / CWE-415 / CWE-416：内存泄漏 / double free / use-after-free（规则化版本）
目标：
- `malloc/new` 与 `free/delete` 的配对

检测（第一阶段可做简化）：
- 函数内：
  - malloc 后存在某路径返回未释放（泄漏）
  - free 后同一路径再次 free（double free）
  - free 后继续使用该指针进行 mem 访问或作为参数传入（UAF）
- 跨过程：
  - 通过函数摘要标记“释放了参数 p”“返回了分配对象”等

#### CWE-22：路径穿越（文件路径注入）
目标：
- `open/fopen/CreateFile` 等路径参数

检测：
- source→path 参数污点传播
- 查找 sanitizers：去除 `../`、白名单目录拼接、realpath 规范化后校验前缀等（可先做弱匹配）

#### CWE-78：命令注入
目标：
- `system/popen/exec*` 以及 `CreateProcess` 的命令行构造

检测：
- source→cmd 参数污点传播
- 识别常见拼接模式（`sprintf/strcat` 构造命令串）
- 缺少白名单/固定参数约束则报警

### 8.3 漏洞去重与置信度
同一问题可能被多次命中（不同路径/不同 callsite）：
- 去重 key：`(cwe, func_ea, sink_ea, arg_index, normalized_arg_repr_hash)`
- 置信度：
  - 高：无界 API 或 format 非常量且可控、明确 source→sink 链且无检查
  - 中：有污点链但存在不确定间接调用/别名
  - 低：仅模式匹配、缺少数据流证据

## 9. API 模型与“语义补丁”

### 9.1 API/函数模型（必需）
为了让 def-use/污点跨调用更靠谱，需要为常见库函数建立模型：
- 纯函数：`strlen`（ret depends on arg0）
- 复制：`memcpy(dst, src, n)`（dst mem depends on src/n）
- 格式化：`sprintf(dst, fmt, ...)`（dst depends on fmt/args）
- 分配：`malloc(n)`（ret is heap ptr, depends on n）
- 释放：`free(p)`（p becomes freed）
- 输入：`recv(fd, buf, n)`（buf becomes tainted, ret is length）

模型表达方式建议 JSON/YAML：
- `name_patterns`：符号名/导入名/签名匹配
- `effects`：taint/def/use/alloc/free/returns
- `sanitizer`：是否清洗、清洗条件

### 9.2 结构体与字段偏移
二进制里常见 `p + 0x10` 这种字段访问。若能得到类型信息可增强：
- 将 `Mem(base=p, disp=0x10)` 归一成 `FieldAccess(p, off=0x10, type=...)`
- 这对识别状态机字段、长度字段与数据指针字段很关键（尤其 CWE-787/190）。

## 10. 可验证性与工程化

### 10.1 评测数据
建议分三类：
- 合成样本：小程序手工构造（单个 CWE 场景），便于回归
- 开源真实项目：不同编译选项（O0/O2、clang/gcc、x86_64/arm64）
- CTF 样本/已公开漏洞：用于验证规则有效性

### 10.2 输出格式
建议支持：
- `findings.jsonl`：便于管道处理
- `SARIF`：便于导入安全平台

每条 finding 的最小字段：
- `cwe`, `title`, `severity`, `confidence`
- `binary_hash`, `func_ea`, `sink_ea`
- `callee`（若是 call sink）
- `evidence`（节点/边 id 列表或 ea 列表）
- `message`（人类可读）

### 10.3 性能策略
- 抽取阶段：
  - 函数级缓存（按 func hash 判断是否需要重抽）
  - 跳过库函数/巨函数（可配置阈值）
- 分析阶段：
  - 先候选过滤后深分析
  - 子图加载（围绕候选 sink 的 k-hop 邻域）

## 11. 实施里程碑（建议拆解）

### M1：抽取与最小 CPG
- 在 IDA 内导出函数 microcode CFG + 指令 + 操作数规范化
- 离线构建 Function/Block/Instr/Expr/Var 节点与 CFG/HAS_OPERAND/DEF/USE 边

### M2：查询与 Level 0 扫描器
- 实现基本图查询 API（按 kind/属性过滤、邻接遍历）
- 上线无界拷贝、格式串、命令执行等 Level 0 规则

### M3：Level 1/2 数据流
- 实现函数内污点传播 + dominator/reaching defs
- 强化 memcpy/分配/索引类规则的真实性验证

### M4：跨过程摘要与规则扩展
- 建立函数摘要与常见库模型
- 扩展到 UAF/double free、路径穿越、整数溢出等

## 12. 风险与对策
- MicroCode API 兼容性：做版本适配层 + 抽取结果的“规范化 JSON”隔离变化。
- 间接调用与别名：保守处理 + API 模型 + 逐步增强（vtable 识别、类型引导）。
- 误报/漏报权衡：用“候选→深分析→证据链”的流程控制误报；对不确定点降置信度而不是强行断言。

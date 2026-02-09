# 5. CPG Schema（V1）

V1 CPG 是一个轻量属性图：节点与边均携带 `kind` 与属性字典。默认实现使用 `networkx.MultiDiGraph`。

## 5.1 Node Kinds（节点类型）

V1 固定节点集合：

- `Program`
- `Function`
- `Block`
- `Instr`
- `CallSite`
- `Var`
- `Global`（新增：区分全局变量/常量）
- `Mem`
- `Expr`
- `Const`
- `String`

公共字段（所有节点都必须具备）：

- `id`：全局唯一字符串
- `kind`：上述枚举之一
- `binary_id`：来自 `meta.json`

可定位字段（若可得必须填）：

- `ea`：十六进制字符串
- `func_ea`：所属函数地址（十六进制字符串；`Program` 例外）

## 5.2 Edge Kinds（边类型）

V1 固定边集合：

结构归属：

- `HAS_FUNCTION`：Program → Function
- `HAS_BLOCK`：Function → Block
- `HAS_INSTR`：Block → Instr（必须带 `index=insn_idx`）
- `CALLSITE_OF`：CallSite → Instr

控制流：

- `CFG_BB`：Block → Block（必须带 `branch`）

调用：

- `ARG`：CallSite → (Expr/Var/Mem/Const/String)（必须带 `index`）
- `CALLS`：CallSite → Function（direct 能解析时）
- `CALL_TARGET`：CallSite → Expr（indirect/unknown）
- `RET`：CallSite → (Var/Expr/Mem)（必须带 `index`，V1 固定为 0）

数据流（事实边，由 Builder 直接生成）：

- `DEF`：Instr → (Var/Mem/Expr/Global)（必须带 `role`）
- `USE`：Instr → (Var/Mem/Expr/Const/String/Global)（必须带 `role`，可选 `access_mode`）
  - `access_mode`：`"read"` (默认，读取值) | `"addr"` (取地址/LEA)
- `POINTS_TO`：Global/Var → (String/Global/Const/Mem)（表示静态初始化指向或变量指向的内存区域）

数据流（派生边，由分析阶段生成）：

- `REACHING_DEF`：Instr(def) → Instr(use)（必须带 `var_id` 或 `mem_id` 或 `expr_id`）

## 5.3 ID 规则（V1 固定）

V1 采用可读字符串 ID。所有 ID 必须仅依赖导出包内容，且在同一导出包上可重复构建得到相同 ID。

- Program：`P:<binary_id>`
- Function：`F:<func_ea>`
- Block：`B:<func_ea>:<block_id>`
- Instr：`I:<func_ea>:<block_id>:<insn_idx>`
- CallSite：`C:<func_ea>:<ea>`（若 call 指令缺失 `ea`，使用 `C:<instr_id>`）

实体 intern（复用）：

- Global：`G:<binary_id>:<ea>`
- Var：`V:<func_ea>:<var_key>`
  - `var_key`：
    - reg：`reg:<regname>`
    - stack：`stack:<base>:<off>`
- Const：`K:<bits>:<value>`
- String：`S:<ea>`
- Expr：`E:<func_ea>:<expr_hash>`
- Mem：`M:<func_ea>:<region>:<addr_hash>:<bits>`
  - `addr_hash` 为 `mem.v.addr` 的 canonical hash

## 5.4 节点字段（V1 最小字段）

### 5.4.1 Program

- `id`, `kind="Program"`, `binary_id`
- `arch`, `endian`, `bitness`, `imagebase`
- `ida_version`, `extractor_version`（若可得）

### 5.4.2 Function

- `id`, `kind="Function"`, `binary_id`
- `func_ea`, `name`
- `type_str`（若可得）

### 5.4.3 Block

- `id`, `kind="Block"`, `binary_id`
- `func_ea`, `block_id`
- `start_ea/end_ea`（若可得）

### 5.4.4 Instr

- `id`, `kind="Instr"`, `binary_id`
- `func_ea`, `block_id`, `insn_idx`
- `ea`（若导出包提供必须填）
- `opcode`, `text`

### 5.4.5 CallSite

- `id`, `kind="CallSite"`, `binary_id`
- `func_ea`, `ea`（若可得）
- `call_kind`：`direct|indirect|unknown`
- `callee_name`（若可得）

### 5.4.6 Var / Mem / Expr / Const / String / Global

这些节点用于数据流 carrier 与规则查询。为了支持指针污点分析，所有 carrier 节点（Var/Mem/Expr/Global）必须携带类型信息。

公共类型字段（Var/Mem/Expr/Global）：
- `type_full`: 完整类型字符串（如 `char *`, `struct A **`）
- `ptr_level`: 指针层级（int，0表示非指针）
- `base_type`: 基础类型（去除指针后的类型）

- Global：
  - `name`: 符号名
  - `is_const`: boolean
  - `value`: (可选) 初始值
- Var：
  - `var_kind`：`reg|stack`（注意：global 独立为 Global 节点）
  - `bits`
  - 位置字段：`reg` 或 `{base, off}` 或 `{ea, rva}`
- Mem：
  - `region`
  - `bits`
  - `addr_hash`
  - `addr`（保存 canonical 后的结构化对象，便于报告）
- Expr：
  - `bits`
  - `expr_hash`
  - `expr`（canonical 后的结构化对象）
- Const：
  - `bits`, `value`
- String：
  - `ea`, `value`（若 strings.jsonl 可提供）

## 5.5 图不变式（Builder 必须强制校验）

- 每个 Function 必须被 Program 通过 `HAS_FUNCTION` 关联。
- 每个 Block 必须且只能属于一个 Function（`HAS_BLOCK`）。
- 每个 Instr 必须且只能属于一个 Block（`HAS_INSTR`）。
- `CFG_BB` 必须在同一 Function 内闭合，且 `branch` 属于枚举集合。
- 每个 CallSite 必须且只能通过 `CALLSITE_OF` 回链到一个 Instr。
- 所有 `ea` 字段必须是以 `0x` 开头的小写十六进制字符串。


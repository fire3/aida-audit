# 6. CPG 构建器（Builder）设计

Builder 在纯 Python 环境运行，输入导出包目录，输出内存 CPG 与最小索引。Builder 仅做确定性组装：不推断复杂语义，不做重型分析。

## 6.1 构建顺序（固定）

1) 载入 `meta.json`，创建 Program 节点。
2) 载入 `imports/exports/strings`（若存在），建立外部 Function 与 String 节点的索引。
3) 流式读取 `functions.jsonl`：
   - 对 `status!="ok"` 的记录：仅创建 Function 节点并标记状态（V1 不建 CFG/DFG）。
   - 对 `status="ok"` 的记录：按 6.2~6.5 构建完整函数子图。
4) 构建完成后执行一致性校验（6.6），失败即中止（不输出不可信结果）。

## 6.2 Program / Function / Block / Instr（结构骨架）

对每个 `status="ok"` 的函数：

- 创建 Function 节点 `F:<func_ea>`，并建 `HAS_FUNCTION(P→F)`。
- 对每个 block：
  - 创建 Block 节点 `B:<func_ea>:<block_id>`；
  - 建 `HAS_BLOCK(F→B)`。
- 对每个 insn：
  - 创建 Instr 节点 `I:<func_ea>:<block_id>:<insn_idx>`；
  - 建 `HAS_INSTR(B→I, index=insn_idx)`。
- 对每条 cfg edge：
  - 建 `CFG_BB(B_src→B_dst, branch=...)`。

## 6.3 Operand intern（实体化与复用）

Builder 必须实现两类 intern：

- `intern_value_operand(func_ea, op) -> node_id`：用于 `Var/Const/String/Expr`
- `intern_mem_operand(func_ea, op) -> node_id`：用于 `Mem`

映射规则（以第 4 章 operand 为输入）：

- `reg/stack/global` → `Var`
- `const` → `Const`
- `string` → `String`
- `expr/unknown` → `Expr`
- `mem` → `Mem`（并同时对 `mem.v.addr` 建立一个 `Expr` 节点用于地址表达式复用）

复用规则（必须）：

- 同一函数内，同一个 `Var/Mem/Expr` 的 ID 必须稳定且复用；禁止为同一语义实体重复建节点。
- `Const/String` 为全局复用（跨函数复用），ID 不包含 `func_ea`。

## 6.4 DEF/USE 边生成（只依赖 reads/writes）

对每个 Instr：

- 对 `reads` 中每个条目：
  - `node = intern_* (op)`
  - 建 `USE(Instr→node, role=<role>, index=<index>)`
- 对 `writes` 中每个条目：
  - `node = intern_* (op)`
  - 建 `DEF(Instr→node, role=<role>, index=<index>)`

约束：

- `reads/writes` 为空允许存在；但 call 语义指令必须至少有 `callee/arg` 的 reads。
- `role` 必须来自一组固定枚举（由实现常量定义）；未知 role 视为导出包不符合契约。

## 6.5 指针与内存建模 (Points-To)

为了支持指针分析与别名追踪，Builder 需要显式建模变量与内存的关系：

1.  **栈变量建模**：
    - 对每个识别到的栈变量节点 `V:<func_ea>:stack:<base>:<off>`，必须创建一个对应的内存节点 `M:<func_ea>:stack:<base>:<off>`。
    - 建立 `POINTS_TO` 边：`Var -> Mem`。
    - 意义：表示该变量（指针/引用）指向该栈内存区域。

2.  **全局变量建模**（可选）：
    - 若全局变量指向已知静态数据，建立 `Global -> Global/String/Const` 的 `POINTS_TO` 边。

## 6.6 CallSite 构建（只依赖导出包 call 字段）

当 insn 含 `call` 字段：

- 创建 CallSite 节点 `C:<func_ea>:<ea>` 并建 `CALLSITE_OF(C→I)`。
- 对 `call.args`：
  - `node = intern_* (arg_op)`
  - 建 `ARG(C→node, index=i)`
- 对目标：
  - `kind=direct` 且 `callee_name` 存在：创建/复用外部 Function 节点 `FEXT:<callee_name>`（实现可选用 `F:ext:<name>`，但必须稳定），并建 `CALLS(C→FEXT)`。
  - `kind=indirect|unknown`：对目标表达式建 `Expr` 节点，并建 `CALL_TARGET(C→Expr)`（若导出包未提供目标表达式则省略该边）。
- 对返回值：
  - 若 `call.ret` 非空：建 `RET(C→node, index=0)`。

## 6.7 一致性校验（V1 强制）

构建完成后必须校验：

- 结构：
  - `HAS_FUNCTION/HAS_BLOCK/HAS_INSTR` 的闭包关系完整
  - 每个 `HAS_INSTR` 的 `index` 连续且从 0 递增（在同一 Block 内）
- CFG：
  - `CFG_BB` 不跨函数
  - edge 的 `branch` 属于枚举集合
- CallSite：
  - 每个 CallSite 必有且仅有一条 `CALLSITE_OF`
  - 每个 `ARG/RET` 的 `index` 为非负整数
- 地址：
  - 所有 `ea/func_ea/start_ea/end_ea` 符合 `0x[0-9a-f]+`

## 6.8 最小索引（V1 必备）

Builder 必须维护以下索引（内存结构即可）：

- `by_kind[kind] -> set(node_id)`
- `by_func[func_ea] -> {function_id, block_ids, instr_ids, callsite_ids}`
- `by_ea[ea] -> set(node_id)`（Instr/CallSite/String）
- `calls_by_callee[name] -> set(callsite_id)`（仅 direct 且有 callee_name 的 CallSite）


# 7. 分析层（V1）

分析层在已构建的 CPG 上运行，产出可解释的证据链。V1 聚焦三类能力：支配关系、reaching definitions、函数内污点传播。

## 7.1 Block CFG 支配关系（Dominator）

输入：函数内 `Block` 与 `CFG_BB` 边。

输出：

- `dom[block] -> set(block)`：支配集合
- `idom[block] -> block`：直接支配者（可选）

用途（V1 必用）：

- 判定“检查是否覆盖 sink”：若某检查块 `B_chk` 支配 sink 所在块 `B_sink`，则该检查对所有路径有效（在 V1 近似为“存在检查”）。

## 7.2 Reaching Definitions（V1 版本）

V1 reaching defs 以 `Var` 与 `Mem` 为 carrier：

- `Var`：`Var.id` 作为 key
- `Mem`：`Mem.id` 作为 key（不做别名合并）

定义点：

- `DEF(Instr→Var/Mem)` 的 Instr 视为对该 key 的定义。

使用点：

- `USE(Instr→Var/Mem)` 的 Instr 视为对该 key 的使用。

输出（两种等价方式，V1 选其一实现即可）：

- 方式 A：在图上新增 `REACHING_DEF(Instr_def→Instr_use, key=...)` 边
- 方式 B：构建外部索引 `reaching_defs[(use_instr_id, key)] -> set(def_instr_id)`（不改图）

约束：

- 以 Block CFG 为边界做数据流分析；指令顺序仅在 block 内处理。
- 不做路径可行性剪枝；任何 CFG 可达即视为可能到达。

## 7.3 函数内污点传播（Intra-procedural Taint）

### 7.3.1 Carrier

V1 污点 carrier 是：

- `Var.id`
- `Mem.id`

`Expr` 不作为默认 carrier（避免临时值碎片化）；当导出包将不稳定值落为 `Expr` 时，规则必须显式选择是否追踪该 Expr。

### 7.3.2 传播规则（V1 固定）

V1 使用“def-use 驱动”的传播，结合图上指针分析（见 7.4）：

- **指令级传播**：若 `Instr` 对 `dst` 有 DEF，对 `src` 有 USE，则 `taint(src)` ⇒ `taint(dst)`。
- **指针传播**：通过 `POINTS_TO` 边自动处理别名（详见 7.4）。
- **Call 传播**：
  - 使用 API 模型（第 9 章）来决定：
    - 哪些参数 taint 会影响返回值
    - 哪些参数 taint 会写入到哪些内存位置（例如 `memcpy(dst, src, n)` 使 `dst_mem` tainted）
  - 若无模型：V1 默认保守截断（不跨 call 传播），但保留 “call 发生点” 作为证据节点。

### 7.3.3 Source / Sink / Sanitizer 的落点

规则框架必须以节点定位：

- Source：一个 `CallSite` 或一个 `Instr`（例如读取输入到缓冲区的写入点）
- Sink：一个 `CallSite`（危险 API）或一个 `Instr`（危险内存写）
- Sanitizer：一个 `Instr/CallSite`，并要求其所在 Block 支配 sink（7.1）

### 7.3.4 输出证据

对每条污点命中必须输出：

- `path_ea`：一条可解释的路径（允许截断）
- `evidence_nodes`：
  - source 节点
  - 若干关键 def/use 指令
  - sink 节点

## 7.4 指针与别名分析（图驱动）

为了避免复杂的定制规则，TaintEngine 应利用 `POINTS_TO` 边进行图驱动的别名解析：

1.  **Var → Mem (Write)**:
    - 当污点到达 `Var` 节点，且该节点有 `POINTS_TO` 边指向 `Mem` 节点时：
    - 污点传播至 `Mem` 节点。
    - 语义：通过指针写入内存（`*p = tainted`）。

2.  **Mem → Var (Read/Alias)**:
    - 当污点到达 `Mem` 节点时，反向查找所有指向该 `Mem` 的 `Var` 节点（入边为 `POINTS_TO`）。
    - 污点传播至这些 `Var` 节点。
    - 语义：从被污染的内存读取，或通过别名指针访问（`tainted_val = *p` 或 `alias_p` 指向同一内存）。

3.  **隐式定义 (Implicit Defs)**:
    - 结合 Call 模型，若函数调用修改了通过指针传入的内存（如 `recv(..., buf, ...)`），应视为对该内存的隐式定义。
    - 引擎应自动检查参数的 `POINTS_TO` 关系，将污点应用到对应的 `Mem` 节点。

## 7.5 调试接口设计

为了便于排查污点丢失或过度传播问题，TaintEngine 必须提供默认调试接口：

1.  **Trace Log**:
    - 支持详细级别（verbose）日志，打印每一步传播的源节点、目标节点、传播原因（DEF-USE, POINTS-TO, CALL）。
    
2.  **Subgraph Dump**:
    - 支持将涉及污点传播的子图（包含相关节点和路径）导出为 JSON 或 DOT 格式。
    - 方便可视化查看路径断裂点。

3.  **Interactive Debug Hooks**:
    - 提供 `debug_trace(node_id)` 接口，允许开发者查询特定节点的污点状态和来源。

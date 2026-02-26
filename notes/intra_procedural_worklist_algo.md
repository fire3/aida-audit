# 过程内污点传播算法：基于 IDA MicroCode 的工作列表设计

本文档详细描述了基于 IDA MicroCode (Hex-Rays Decompiler IR) 的过程内（Intra-procedural）污点传播算法。该算法采用工作列表（Worklist）不动点迭代方法，在 MicroCode 基本块（mblock_t）级别的控制流图（CFG）上计算污点数据流。

## 1. 核心概念与 IDA MicroCode 映射

本算法直接运行在 IDA 的 MicroCode 层级（通常是 `MMAT_LOCOPT` 或 `MMAT_CALLS` 成熟度），利用其 SSA 特性（部分）和清晰的数据流语义。

### 1.1 输入 (Inputs)

1.  **Microcode Block Array (`mba_t *mba`)**:
    *   目标函数的 MicroCode 表示。
    *   包含控制流图（CFG）：由 `mblock_t` 节点和其前驱 (`pred`) / 后继 (`succ`) 边组成。
2.  **污点源/汇聚点规则 (Source/Sink Rules)**:
    *   **Source**: 定义哪些函数调用或内存读取引入污点（例如 `recv`, `read`）。
    *   **Sink**: 定义哪些操作不能接受污点数据（例如 `system`, `strcpy` 的参数）。

### 1.2 状态定义 (State Definition)

对于 CFG 中的每个基本块 $B$ (`mblock_t`)，维护两个状态集合：

*   **$In(B)$**: 进入该基本块时的程序状态。
*   **$Out(B)$**: 离开该基本块时的程序状态。

程序状态 $S$ 定义为：

1.  **污点集合 (TaintSet)**:
    *   包含当前被污染的 MicroCode 操作数（`mop_t`）。
    *   **键值表示 (Key Representation)**: 使用 `_mop_key` 唯一标识操作数：
        *   **寄存器 (`mop_r`)**: `reg:{index}` (e.g., `reg:0` for RAX)
        *   **栈变量 (`mop_S`)**: `stack:{offset}`
        *   **局部变量 (`mop_l`)**: `lvar:{index}` (Lvars 在优化后 MicroCode 中常见)
        *   **全局变量 (`mop_v`)**: `global:{ea}`
    *   **值**: 污点标签（Label）及来源信息（Evidence）。

2.  **别名集合 (AliasSet / Points-to Map)**:
    *   用于处理间接内存访问（`m_ldx`, `m_stx`）。
    *   映射：`Pointer Key -> {Target Keys}`。
    *   例如：`reg:1` -> `{stack:0x10, global:0x4000}`。

### 1.3 输出 (Outputs)

1.  **污点发现 (Findings)**:
    *   当污点传播到 Sink 时生成的报告。
    *   包含：`Source Info` (EA, Function), `Sink Info` (EA, Function), `Taint Path` (指令链)。
2.  **基本块摘要 (Block Summaries)** (可选):
    *   每个基本块最终的 $Out$ 状态，可用于后续的过程间分析（Inter-procedural Analysis）。

## 2. 传递函数 (Transfer Function)

传递函数 $f_B$ 模拟基本块内指令序列 (`mblock_t::head` 到 `mblock_t::tail`) 的执行。
MicroCode 指令 (`minsn_t`) 通过操作码 (`mcode_t`) 定义行为。

我们定义指令级传递函数 $S_{out} = f_{inst}(S_{in}, \text{minsn})$。

### 2.1 数据移动 (`m_mov`)
指令：`mov d, l` (Destination `d` = Left `l`)

*   **TaintSet 更新**:
    *   `if is_tainted(l): taint(d)`
    *   `else: untaint(d)` (Strong Update, 假设 `d` 被完全覆盖)
*   **AliasSet 更新**:
    *   `PT(d) = PT(l)` (指针传播)

### 2.2 算术运算 (`m_add`, `m_sub`, `m_and`, etc.)
指令：`add d, l, r`

*   **TaintSet 更新**:
    *   `if is_tainted(l) OR is_tainted(r): taint(d)`
    *   `else: untaint(d)`
*   **AliasSet 更新**:
    *   通常算术运算会破坏指针指向（除了 `ptr + offset`）。
    *   如果 `l` 是指针且 `r` 是常数：`PT(d) = Shift(PT(l), r)`（简化处理可保留 `PT(l)` 或标记为 `Unknown`）。

### 2.3 内存读取 (`m_ldx`)
指令：`ldx d, l, r` (Load `d = *(l + r)`)，通常 `r` 为 0 或偏移。

*   **Alias 解析**:
    *   计算地址 `addr = l + r`。
    *   查找 `PT(addr)` 获取可能指向的目标集合 $O = \{o_1, o_2...\}$。
*   **TaintSet 更新**:
    *   `if Any(is_tainted(o) for o in O): taint(d)`
    *   若无法解析别名，则根据策略决定是否保守地标记为 `Tainted` (Over-taint) 或忽略 (Under-taint)。

### 2.4 内存写入 (`m_stx`)
指令：`stx d, l, r` (Store `*(d + l) = r`)

*   **Alias 解析**:
    *   计算地址 `addr = d + l`。
    *   获取目标集合 $O = PT(addr)$。
*   **TaintSet 更新**:
    *   `if is_tainted(r)`: 将 $O$ 中所有对象标记为污点 (May-Taint)。
    *   `else`: 如果 $O$ 仅包含唯一对象 (Must-Alias)，可执行 Strong Update (Untaint)；否则执行 Weak Update (保留原状态)。

### 2.5 函数调用 (`m_call`)
指令：`call d, l, args` (Call `l` with `args`, result in `d`)

*   **Source 检查**:
    *   如果 `l` (Callee) 匹配 Source 规则（如 `read`）：
        *   标记指定输出（`d` 或 `args` 指针指向的内存）为污点。
*   **Sink 检查**:
    *   如果 `l` (Callee) 匹配 Sink 规则（如 `system`）：
        *   检查 `args` 中对应的参数是否被污染。
        *   若污染，记录 Finding。
*   **Sanitizer 检查**:
    *   如果匹配净化规则，清除输出的污点。
*   **默认传播**:
    *   如果未知函数：
        *   保守策略：假设返回值依赖于所有参数。`if Any(is_tainted(a) for a in args): taint(d)`。
        *   指针参数：假设可能会修改指向的内容（Side-effects），根据策略处理。

## 3. 算法流程 (Worklist Algorithm)

### 3.1 初始化
1.  **Worklist**: `Q = [mba.get_mblock(0)]` (Entry Block)。
2.  **状态**: 所有块 $Out[B] = \emptyset$。
3.  **Entry State**: $In[Entry] = \text{GlobalTaints} \cup \text{ArgTaints}$。

### 3.2 迭代
```python
while Q is not empty:
    B = Q.pop() // 取出一个 mblock_t
    
    // 1. 合并前驱状态 (Meet Operator)
    // In[B] = Union(Out[P] for P in B.pred)
    Current_In = State()
    for P_idx in B.pred:
        Current_In.merge(Out[P_idx])
        
    // 2. 块内传递 (Transfer)
    Current_Out = Current_In.clone()
    inst = B.head
    while inst:
        Current_Out = apply_transfer(Current_Out, inst)
        inst = inst.next
        
    // 3. 检查收敛 (Check Convergence)
    if not Current_Out.equals(Out[B.serial]):
        Out[B.serial] = Current_Out
        // 状态改变，激活后继
        for S_idx in B.succ:
            if S_idx not in Q:
                Q.push(mba.get_mblock(S_idx))
```

## 4. 针对 IDA MicroCode 的特殊处理

1.  **Maturity Level**:
    *   建议在 `MMAT_LOCOPT` (Local Optimization) 或更高层级运行。
    *   此时 `m_mov` 较多，逻辑清晰，且大部分栈变量已转化为 `mop_l` (Local Vars) 或 `mop_S` (Stack)，便于追踪。
2.  **Sub-instructions (`mop_d`)**:
    *   MicroCode 操作数可能包含嵌套指令（如 `add(mul(a, b), c)`）。
    *   传递函数必须递归处理 `mop_d`，先计算子表达式的污点状态，再计算外层。
3.  **Phi 节点**:
    *   如果 MicroCode 处于 SSA 形式，无需显式处理 Phi 节点，直接通过 `mop_l` 的版本号或定义-使用链（Def-Use Chains）自然处理。
    *   如果非 SSA，`Union` 操作自然处理控制流汇聚。

## 5. 实现建议

*   **性能**: 使用 BitSet 存储 `mblock_t` 索引以快速去重 Worklist。
*   **Context**: 传递函数需要访问 `mba` 信息以解析变量名称和类型。
*   **Mop Key**: 必须标准化 `mop_t` 的键生成逻辑，确保同一变量在不同指令中 Key 一致。

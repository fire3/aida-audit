# 过程内污点传播算法：基于工作列表的不动点迭代

本文档详细描述了过程内（Intra-procedural）污点传播的核心算法。该算法采用基于工作列表（Worklist）的不动点迭代（Fixed-Point Iteration）方法，避免了递归分析带来的栈溢出风险和重复计算，能够高效地在控制流图（CFG）上计算污点数据流。

## 1. 核心概念与定义

### 1.1 状态定义 (State Definition)

对于 CFG 中的每个基本块（Basic Block）$B$，我们维护两个状态集合：

*   **$In(B)$**: 进入该基本块时的程序状态。
*   **$Out(B)$**: 离开该基本块时的程序状态。

程序状态 $S$ 包含两部分核心信息：

1.  **污点集合 (TaintSet)**:
    *   包含当前被标记为“污染”的变量（Variables）和内存抽象对象（Abstract Objects）。
    *   表示为：$T \subseteq \text{Vars} \cup \text{Objs}$。
    *   支持操作：`is_tainted(v)`, `taint(v)`, `untaint(v)`。

2.  **别名集合 (AliasSet / Points-to Set)**:
    *   维护当前的指针指向关系，用于解决别名（Alias）造成的污点传播（如 `*p = source()`）。
    *   表示为：$PT: \text{Vars} \to \mathcal{P}(\text{Objs})$。
    *   即：每个指针变量映射到一个可能的内存对象集合。

### 1.2 传递函数 (Transfer Function)

传递函数 $f_B$ 描述了基本块 $B$ 内指令序列如何将 $In(B)$ 转换为 $Out(B)$：

$$ Out(B) = f_B(In(B)) $$

$f_B$ 是块内所有指令传递函数的组合：$f_B = f_{inst_n} \circ \dots \circ f_{inst_1}$。

## 2. 算法流程

### 2.1 初始化 (Initialization)

1.  **构建 CFG**: 获取目标函数的控制流图。
2.  **初始化工作列表 (Worklist)**:
    *   将包含污点源（Source）调用的基本块，或函数的入口基本块（Entry Block）加入 `Worklist`。
    *   通常，为了保证传播的完整性，初始时可将 Entry Block 加入，或者按拓扑序（若无环）加入所有块。对于不动点迭代，只要 Entry Block 在且顺序合理，最终都会收敛。
    *   推荐：`Worklist = [Entry Block]`。
3.  **初始化状态**:
    *   所有块的 $Out[B]$ 初始化为空（$\emptyset$）或全集（取决于具体分析是 Must 还是 May，污点分析通常是 May Analysis，故初始化为空）。
    *   对于包含 Source 的点，如果在函数入口就有污点（如参数），则 Entry Block 的 $In$ 集合需包含这些初始污点。

### 2.2 迭代过程 (Iteration Process)

使用工作列表算法进行迭代，直到所有基本块的状态不再发生变化（达到不动点）。

```python
While Worklist is not empty:
    # 1. 取出一个待处理的基本块
    Block = Worklist.pop() 
    
    # 2. 保存旧的 Out 状态用于后续比对
    Old_Out = Out[Block]
    
    # 3. 计算 In[Block]：合并所有前驱节点(Predecessors)的 Out 集合
    #    Merge 操作通常是集合并集 (Union) 用于 May Analysis
    In[Block] = Union({Out[P] for P in Predecessors(Block)})
    
    # 4. 应用传递函数 (Transfer Function)
    #    在块内逐条指令模拟执行，更新 TaintSet 和 AliasSet
    Current_Out = Transfer_Function(In[Block], Block.instructions)
    
    # 5. 检查是否收敛 (Fixed-Point Check)
    if Current_Out != Old_Out:
        # 数据流发生变化，更新状态
        Out[Block] = Current_Out
        
        # 6. 将受影响的后继节点加入工作列表
        for Succ in Successors(Block):
            if Succ not in Worklist:
                Worklist.push(Succ)
```

## 3. 详细传递函数设计

在步骤 4 中，`Transfer_Function` 需要处理不同类型的指令。

### 3.1 赋值指令 (Assignment): `x = y`

*   **TaintSet 更新**:
    *   如果 `y` 在 $In$ 状态的 TaintSet 中，则将 `x` 加入 TaintSet。
    *   如果 `y` 未被污染，则将 `x` 从 TaintSet 中移除（Strong Update）或保留（Weak Update，取决于是否确定覆盖）。
*   **AliasSet 更新**:
    *   复制指向关系：$PT(x) = PT(y)$。

### 3.2 污点源 (Source): `x = source()`

*   **TaintSet 更新**:
    *   无条件将 `x` 加入 TaintSet。
    *   记录污点来源信息（Evidence）。

### 3.3 污点汇聚点 (Sink): `sink(x)`

*   **检查**:
    *   查询 $In$ 状态的 TaintSet。
    *   如果 `x` 被污染，则触发告警（Finding），记录从 Source 到当前指令的路径。

### 3.4 内存存储 (Store): `*p = y`

*   **Alias 解析**:
    *   查找 $PT(p)$ 获取 `p` 可能指向的对象集合 $O_p = \{o_1, o_2, \dots\}$。
*   **TaintSet 更新**:
    *   如果 `y` 被污染：将 $O_p$ 中所有对象标记为污染（May Taint）。
    *   如果 `y` 未污染且 $PT(p)$ 仅包含唯一对象（Strong Update）：可将该对象去污。否则（Weak Update），不改变原污染状态。

### 3.5 内存读取 (Load): `x = *p`

*   **Alias 解析**:
    *   获取 $O_p = PT(p)$。
*   **TaintSet 更新**:
    *   如果 $O_p$ 中**任意**对象被污染，则将 `x` 标记为污染。

### 3.6 净化/清理 (Sanitization): `x = sanitize(x)`

*   **TaintSet 更新**:
    *   将 `x` 从 TaintSet 中移除。

## 4. 优化策略

1.  **位向量 (Bitvector)**:
    *   如果变量数量固定，使用位向量表示 TaintSet 可极大加速 `Union` 和 `Difference` 操作。
2.  **稀疏分析 (Sparse Analysis)**:
    *   仅在 Def-Use 链上传播，而非在 CFG 所有边上传播（即基于 SSA 形式），可减少迭代次数。
3.  **工作列表排序**:
    *   使用逆后序（Reverse Post-Order, RPO）遍历 CFG 初始化 Worklist，通常能更快收敛。

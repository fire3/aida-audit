# 污点分析设计文档（IFDS 变体 + 摘要复用）

本文档给出可直接落地实现的污点分析方案：过程内采用前向数据流不动点迭代；过程间采用工作列表调度与摘要（Summary）复用。该方案遵循 IFDS 的“有限域 + Join 合并 + 不动点求解”思想，并对指针/堆/全局变量的抽象与转移规则做出明确规定。

---

## 1. 目标与边界

### 1.1 目标

- 在包含指针、堆分配、函数调用的程序上，识别从 `Source` 到 `Sink` 的污点可达性，并输出可重构传播路径。
- 提供可实现的数据结构、状态格（lattice）、转移函数与调度算法，用于直接指导编码。

### 1.2 输入与输出

- **输入**
  - IR/CFG 指令序列（至少覆盖：赋值、取址、解引用读写、堆分配、函数调用、返回、分支跳转）。
  - 函数控制流图（CFG）与调用图（CG）。
  - 规则集：`Source`/`Sink` 识别规则（函数名/签名/属性/注解/模式）。
- **输出**
  - 漏洞记录列表，每条记录包含：
    - `source_site`：Source 调用点（`CallSiteID`）
    - `sink_site`：Sink 调用点（`CallSiteID`）
    - `context`：上下文标识（`ContextID`）
    - `path`：传播链（`InstrID` 序列，可从 `PathRef` 反向重构）
    - `evidence`：触发时的参与参数、关键别名关系快照（可选）

### 1.3 分析粒度（明确选择）

- **过程内**：流敏感（flow-sensitive），路径不敏感（path-insensitive）。
- **过程间**：上下文敏感，采用 **1-CFA（最近一次调用点）**。
- **堆对象**：以 `(alloc_site_id, ctx_id)` 唯一化。
- **更新策略**：对 `*p = v` 采用强/弱更新：当 `pt(p)` 为单元素集合时强更新，否则弱更新。

---

## 2. 标识体系：InstrID / CallSite / Context

### 2.1 InstrID 与 CallSiteID

- `InstrID`：每条 IR 指令的稳定唯一编号（例如文件:行:列 + IR 序号）。
- `CallSiteID`：函数调用指令的 `InstrID`。

### 2.2 ContextID（1-CFA）

```text
ContextID := None | CallSiteID
```

- `None`：根上下文（入口/种子）。
- 过程间调用产生新上下文：`callee_ctx = callsite_id`。

---

## 3. 核心抽象：位置、状态与 Join

### 3.1 抽象位置（Abstract Location）

统一表示栈、堆、全局、返回值；污点与指向关系均在该域上定义。

```text
Loc :=
  StackSlot(func_id, ctx_id, var_id)   // 局部变量槽位（上下文敏感）
| GlobalVar(name)                      // 全局变量槽位
| HeapObj(alloc_site_id, ctx_id)       // 堆对象（alloc site + 上下文）
| RetVal(func_id, ctx_id)              // 返回值槽位（函数 + 上下文）
```

中文解析：

- `StackSlot` 引入 `ctx_id`，用于区分不同调用点下的“栈地址”，保证 `&x` 传递不会跨调用点互相污染。
- `RetVal` 也带 `ctx_id`，保证同一函数在不同调用点产生的返回值槽位独立。

### 3.2 状态（State）

```text
State := {
  pt:    Map<Loc, Set<Loc>>,      // points-to：Loc 存放指针值时可能指向的 Loc 集合
  taint: Map<Loc, PathRef>        // tainted loc -> 路径引用（证据重构用）
}
```

### 3.3 Join 与收敛

- `pt` 采用并集增长：`out.pt[l] = A.pt[l] ∪ B.pt[l]`
- `taint` 对同一 `Loc` 的路径引用做合并（合并前驱集合，见 7.1）

```text
Join(A, B):
  out.pt[l] = A.pt[l] ∪ B.pt[l]
  out.taint[l] = MergePathRef(A.taint[l], B.taint[l])
```

收敛判定：一次迭代后 `pt` 与 `taint` 都不再新增元素则视为不动点。

---

## 4. 预处理：构建与剪枝（Pruning）

目标是缩小分析范围，仅保留可能位于 `Source -> Sink` 路径上的函数。

### 4.1 构建产物

- `CG`：全程序调用图（保守近似）。
- `CFG(f)`：每个函数 `f` 的控制流图。
- `SourceCallSites`：匹配 Source 规则的调用指令集合。
- `SinkCallSites`：匹配 Sink 规则的调用指令集合。

### 4.2 RelevantFuncs 计算

保留集合 `RelevantFuncs = forward_reachable(S) ∩ backward_reachable(T)`：

- `S`：Source 调用点所在函数集合
- `T`：Sink 调用点所在函数集合

```text
ComputeRelevantFuncs(CG, SourceCallSites, SinkCallSites):
  S = { enclosing_func(cs) for cs in SourceCallSites }
  T = { enclosing_func(cs) for cs in SinkCallSites }

  ReachFromSource = forward_reachable(CG, S)
  CanReachSink    = backward_reachable(CG, T)

  return ReachFromSource ∩ CanReachSink
```

中文解析：

- 正向可达保证“可能受 Source 影响”；反向可达保证“可能到达 Sink”；交集后其余函数不进入求解器。

---

## 5. 过程间求解：工作列表 + 摘要复用

### 5.1 任务与全局表

工作列表中元素：

```text
Task := (func_id, ctx_id, in_fp)
```

全局表：

```text
InputState: Map<Task, State>                           // 任务输入状态（与 in_fp 一一对应）
Summary:    Map<Task, State>                           // 任务输出摘要（函数出口状态）
Callers:    Map<Task, Set<(caller_task, callsite_id)>> // 依赖关系（被调用者任务 -> 调用者任务集合）
Worklist:   Queue<Task>
```

### 5.2 输入状态指纹（明确计算规则）

摘要以输入指纹做键，指纹只包含过程间可观测输入：形参与全局。

```text
Fingerprint(func, ctx, state):
  ParamLocs = { StackSlot(func, ctx, param_i) for each param_i }
  GlobalLocs = { all GlobalVar(*) }
  Keys = ParamLocs ∪ GlobalLocs

  return Hash(
    { (k, state.pt[k]) for k in Keys },
    { (k, k in state.taint) for k in Keys }
  )
```

中文解析：

- 指纹对污点只取布尔（是否污染），路径证据不参与哈希，保证摘要稳定复用。
- `all GlobalVar(*)` 指实现侧维护的“全局变量槽位集合”。

### 5.3 全局求解器伪代码

```text
Solve(CG, CFGs, SourceCallSites, SinkCallSites):
  RelevantFuncs = ComputeRelevantFuncs(CG, SourceCallSites, SinkCallSites)

  for cs in SourceCallSites:
    f = enclosing_func(cs)
    if f not in RelevantFuncs:
      continue
    ctx = None
    init = EmptyState()
    fp = Fingerprint(f, ctx, init)
    t = (f, ctx, fp)
    InputState[t] = init
    Worklist.push(t)

  while Worklist not empty:
    t = Worklist.pop()
    (f, ctx, in_fp) = t
    in_state = InputState[t]

    out_state = AnalyzeFunction(f, ctx, in_fp, in_state, RelevantFuncs)

    if Summary.get(t, EmptyState()) == out_state:
      continue

    Summary[t] = out_state

    for (caller_task, _) in Callers.get(t, ∅):
      Worklist.push(caller_task)
```

中文解析：

- 任务的粒度是 `(func, ctx, in_fp)`；当对应摘要更新时唤醒其调用者任务重算。
- Source 调用点所在函数以空状态作为种子进入队列；Source 在转移函数中产生污点事实。

---

## 6. 过程内求解：CFG 上不动点迭代

### 6.1 基本块级别迭代伪代码

```text
AnalyzeFunction(func, ctx, task_in_fp, input_state, RelevantFuncs):
  BlockOut = Map<Block, State>()
  Q = Queue<Block>()

  entry = CFG(func).entry
  BlockOut[entry] = input_state
  Q.push(entry)

  while Q not empty:
    b = Q.pop()

    if b == entry:
      in_s = input_state
    else:
      in_s = JoinAll({ BlockOut[p] for p in preds(b) })

    s = in_s
    for instr in b.instructions:
      s = Transfer(instr, func, ctx, task_in_fp, s, RelevantFuncs)

    if BlockOut.get(b, EmptyState()) != s:
      BlockOut[b] = s
      for succ in succs(b):
        Q.push(succ)

  exit = CFG(func).exit
  return BlockOut.get(exit, EmptyState())
```

中文解析：

- 块入口由前驱出口 `Join` 得到；块内顺序执行转移函数。
- 任一块出口变化将触发其后继重算，直到收敛。

---

## 7. 路径证据（Path）表示

### 7.1 PathRef 与节点池

路径采用“前驱引用”存储，避免在状态中复制长链。

```text
PathNode := { instr_id, prev: Set<PathRef> }
PathRef  := integer index into NodePool
NodePool := append-only array of PathNode
```

污染写入规则：

- `SetTaint(loc)` 创建新节点，`prev` 指向导致该污染的前驱节点集合。
- `MergePathRef` 合并 `prev` 集合；不复制整条链。

### 7.2 漏洞路径重构

Sink 命中时，从 `PathRef` 反向遍历 `prev` 关系即可重构传播链，输出一条或多条 `InstrID` 序列。

---

## 8. 转移函数（Transfer Functions）

记当前状态为 `S = {pt, taint}`。辅助操作：

```text
IsTainted(S, l): l in S.taint
ClearTaint(S, l): remove l from S.taint
Pts(S, l): S.pt.get(l, ∅)
SetPts(S, l, targets): S.pt[l] = targets
JoinPts(S, l, targets): S.pt[l] = Pts(S,l) ∪ targets
```

位置构造：

```text
LocOfVar(func, ctx, var) = StackSlot(func, ctx, var)
LocOfRet(func, ctx)      = RetVal(func, ctx)
LocOfHeap(site, ctx)     = HeapObj(site, ctx)
```

### 8.1 赋值：`x = y`

```text
TransferAssign(x, y, func, ctx, S, instr_id):
  lx = LocOfVar(func, ctx, x)
  ly = LocOfVar(func, ctx, y)

  SetPts(S, lx, Pts(S, ly))

  if IsTainted(S, ly):
    S.taint[lx] = MakePath(instr_id, prev={S.taint[ly]})
  else:
    ClearTaint(S, lx)

  return S
```

中文解析：

- 指向关系为值拷贝。
- 污点随值拷贝传播；未污染则清除目标污染。

### 8.2 取址：`x = &y`

```text
TransferAddrOf(x, y, func, ctx, S, instr_id):
  lx = LocOfVar(func, ctx, x)
  ly = LocOfVar(func, ctx, y)

  SetPts(S, lx, { ly })
  ClearTaint(S, lx)
  return S
```

中文解析：

- `&y` 产生指针值，points-to 为 `{Loc(y)}`；不引入数据污染。

### 8.3 载入：`x = *p`

```text
TransferLoad(x, p, func, ctx, S, instr_id):
  lx = LocOfVar(func, ctx, x)
  lp = LocOfVar(func, ctx, p)
  targets = Pts(S, lp)

  new_pts = ∅
  prevs = ∅
  for t in targets:
    new_pts = new_pts ∪ Pts(S, t)
    if IsTainted(S, t):
      prevs = prevs ∪ { S.taint[t] }

  SetPts(S, lx, new_pts)
  if prevs != ∅:
    S.taint[lx] = MakePath(instr_id, prev=prevs)
  else:
    ClearTaint(S, lx)

  return S
```

中文解析：

- 读取 `p` 指向位置集合的“内容”：
  - 指针内容合并为 `x` 的 points-to。
  - 任一被读位置被污染则 `x` 被污染，路径前驱为命中的被污染位置路径引用集合。

### 8.4 存值：`*p = y`（强/弱更新）

```text
TransferStore(p, y, func, ctx, S, instr_id):
  lp = LocOfVar(func, ctx, p)
  ly = LocOfVar(func, ctx, y)
  targets = Pts(S, lp)

  for t in targets:
    if |targets| == 1:
      SetPts(S, t, Pts(S, ly))
      if IsTainted(S, ly):
        S.taint[t] = MakePath(instr_id, prev={S.taint[ly]})
      else:
        ClearTaint(S, t)
    else:
      JoinPts(S, t, Pts(S, ly))
      if IsTainted(S, ly):
        old = { S.taint[t] } if IsTainted(S, t) else ∅
        S.taint[t] = MakePath(instr_id, prev=old ∪ {S.taint[ly]})

  return S
```

中文解析：

- `pt(p)` 单元素时写入目标确定，覆盖旧值（强更新）；污染同样覆盖/清除。
- `pt(p)` 多元素时目标不确定，points-to 只增长（弱更新）；污染只新增传播，不清除既有污染。

### 8.5 堆分配：`x = malloc(...)` / `x = new T(...)`

```text
TransferAlloc(x, alloc_site_id, func, ctx, S, instr_id):
  lx = LocOfVar(func, ctx, x)
  obj = LocOfHeap(alloc_site_id, ctx)

  SetPts(S, lx, { obj })
  ClearTaint(S, lx)
  ClearTaint(S, obj)
  SetPts(S, obj, ∅)
  return S
```

中文解析：

- 新堆对象以 `(alloc_site, ctx)` 唯一化；对象内容初始清洁。

### 8.6 函数调用：`r = callee(a1, a2, ...)`

调用转移分三类：Source、Sink、普通函数。

#### 8.6.1 Source 调用

```text
TransferCallSource(r, func, ctx, S, callsite_id):
  lr = LocOfVar(func, ctx, r)
  S.taint[lr] = MakePath(callsite_id, prev=∅)
  return S
```

中文解析：

- Source 的返回值直接产生污染事实，路径起点为该调用点。

#### 8.6.2 Sink 调用（漏洞触发）

```text
TransferCallSink(args..., func, ctx, S, callsite_id):
  for arg in args:
    la = LocOfVar(func, ctx, arg)
    if IsTainted(S, la):
      ReportVuln(path_ref=S.taint[la], sink_site=callsite_id, ctx=ctx)
    for t in Pts(S, la):
      if IsTainted(S, t):
        ReportVuln(path_ref=S.taint[t], sink_site=callsite_id, ctx=ctx)
  return S
```

中文解析：

- 同时检查参数值本身与其指向内容是否污染，命中即报告漏洞并携带路径引用。

#### 8.6.3 普通调用（调度 + 摘要复用）

普通调用在调用点执行三件事：构造被调用者输入、登记依赖并入队、用当前已知摘要推进返回效果。

```text
TransferCallNormal(r, callee, args..., func, ctx, caller_task_in_fp, S, callsite_id, RelevantFuncs):
  if callee not in RelevantFuncs:
    return S

  callee_ctx = callsite_id
  in2 = EmptyState()

  for i in [0..n-1]:
    ai = LocOfVar(func, ctx, args[i])
    fi = StackSlot(callee, callee_ctx, param_i)
    SetPts(in2, fi, Pts(S, ai))
    if IsTainted(S, ai):
      in2.taint[fi] = MakePath(callsite_id, prev={S.taint[ai]})

  for each global g in AllGlobals:
    SetPts(in2, g, Pts(S, g))
    if IsTainted(S, g):
      in2.taint[g] = S.taint[g]

  fp2 = Fingerprint(callee, callee_ctx, in2)
  t2 = (callee, callee_ctx, fp2)

  Callers[t2].add(((func, ctx, caller_task_in_fp), callsite_id))

  if t2 not in InputState:
    InputState[t2] = in2
    Worklist.push(t2)

  out2 = Summary.get(t2, EmptyState())

  lr = LocOfVar(func, ctx, r)
  ret = LocOfRet(callee, callee_ctx)
  SetPts(S, lr, Pts(out2, ret))
  if IsTainted(out2, ret):
    S.taint[lr] = MakePath(callsite_id, prev={out2.taint[ret]})
  else:
    ClearTaint(S, lr)

  for each global g in AllGlobals:
    SetPts(S, g, Pts(S, g) ∪ Pts(out2, g))
    if IsTainted(out2, g):
      old = { S.taint[g] } if IsTainted(S, g) else ∅
      S.taint[g] = MakePath(callsite_id, prev=old ∪ {out2.taint[g]})

  return S
```

中文解析：

- 形参通过 `StackSlot(callee, callee_ctx, param_i)` 表示；调用上下文由调用点固定为 `callee_ctx = callsite_id`。
- 被调用者任务由 `(callee, callee_ctx, fp2)` 唯一标识；同一指纹重复到达只登记依赖关系，不重复创建任务输入。
- 调用点使用“当前已知摘要”推进返回值与全局变量；摘要更新后调用者会被唤醒重算，最终达到过程间不动点。

---

## 9. 全局变量与别名一致性

### 9.1 全局变量

- 全局变量以 `GlobalVar(name)` 进入 `Loc` 域，与堆对象/栈槽位同等对待。
- 调用时将全局作为隐式输入复制给被调用者；返回时将摘要中的全局信息 join 合并回调用者状态。

### 9.2 指针别名

- 别名由 `pt` 给出：若 `p` 与 `q` 的 points-to 集合包含同一 `Loc`，则二者别名。
- `*p = y` 写入 `pt(p)` 的每个目标；后续 `x = *q` 若读到同一目标即可传播污点。

---

## 10. 收敛性检查项（实现侧必须满足）

- `Loc` 域有限：由 `(func, ctx, var/alloc_site)` 的有限组合构成。
- Join 使用并集；转移函数允许对目标键覆盖（赋值/强更新），整体在有限域上收敛到不动点。
- 摘要键有限：`in_fp` 由有限键集合（形参+全局）计算，触发次数有限。

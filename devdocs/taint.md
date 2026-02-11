# 过程内污点传播算法：基于 IDA MicroCode 的工作列表设计

本文档描述基于 IDA MicroCode（Hex-Rays Decompiler IR）的过程内（Intra-procedural）污点传播算法。算法采用工作列表（Worklist）不动点迭代方法，在 MicroCode 基本块（`mblock_t`）级别的控制流图（CFG）上计算污点数据流，输出结构化的污染对象集合、传播路径及 Sink 命中报告。

---

## 目录

1. [核心概念与 IDA MicroCode 映射](#1-核心概念与-ida-microcode-映射)
2. [数据结构定义](#2-数据结构定义)
3. [传递函数](#3-传递函数)
4. [算法流程与各-Pass-输出规范](#4-算法流程与各-pass-输出规范)
5. [针对-IDA-MicroCode-的特殊处理](#5-针对-ida-microcode-的特殊处理)
6. [完整输出流程总览](#6-完整输出流程总览)

---

## 1. 核心概念与 IDA MicroCode 映射

本算法运行于 IDA MicroCode 层级（`MMAT_LOCOPT` 或 `MMAT_CALLS`），利用其清晰的数据流语义完成过程内污点分析。

### 1.1 输入（Inputs）

**Microcode Block Array（`mba_t *mba`）**

目标函数的 MicroCode 表示，包含控制流图（CFG）：由 `mblock_t` 节点及前驱（`pred`）/ 后继（`succ`）边构成。

**污点规则集（Source / Sink / Sanitizer Rules）**

| 规则类型 | 触发条件 | 典型示例 |
|----------|----------|----------|
| Source | 函数调用或内存读取引入污点 | `recv`, `read`, `fgets`, `getenv` |
| Sink | 操作不能接受污点参数 | `system`, `execve`, `strcpy` dst 参数 |
| Sanitizer | 对污点数据执行净化 | `strtol`（有效范围转换）、自定义校验函数 |

### 1.2 操作数唯一键（`_mop_key`）

每个 `mop_t` 操作数以字符串键唯一标识：

| 操作数类型 | 键格式 | 示例 |
|------------|--------|------|
| 寄存器（`mop_r`） | `reg:{index}` | `reg:0`（RAX） |
| 栈变量（`mop_S`） | `stack:{offset}` | `stack:-0x18` |
| 局部变量（`mop_l`） | `lvar:{index}` | `lvar:3` |
| 全局变量（`mop_v`） | `global:{ea}` | `global:0x4000` |

### 1.3 程序状态（State）

每个基本块 $B$ 维护两个状态：

- **$In(B)$**：进入该基本块时的程序状态
- **$Out(B)$**：离开该基本块时的程序状态

程序状态 $S$ 由两部分组成：

- **TaintedObjectSet**：当前被污染的操作数集合，每个元素为一个 `TaintedObject` 记录
- **AliasSet**：指针别名映射，`Pointer Key → {Target Keys}`，用于处理间接内存访问

---

## 2. 数据结构定义

### 2.1 `TaintedObject`——污染对象记录

`TaintedObject` 是本算法的核心数据单元，完整描述一个被污染操作数的来源、属性及传播历史。

| 字段 | 类型 | 含义 |
|------|------|------|
| `key` | `string` | 操作数唯一键（格式见 1.2 节） |
| `taint_id` | `UUID` | 污染标识，用于聚合同来源污点 |
| `source_ea` | `ea_t` | 引入污点的指令地址 |
| `source_func` | `string` | 引入污点的函数名（如 `recv`） |
| `mop_type` | `mop_t.t` | 操作数类型枚举（`mop_r` / `mop_S` / `mop_l` / `mop_v`） |
| `size_bytes` | `int` | 操作数字节宽度 |
| `propagation_depth` | `int` | 从 Source 经过的传播步数 |
| `propagation_chain` | `List[StepRecord]` | 传播路径节点列表（详见 2.3 节） |
| `attrs` | `TaintedObjAttrs` | 污染属性集合（详见 2.2 节） |

### 2.2 `TaintedObjAttrs`——污染对象属性

`TaintedObjAttrs` 记录每个污染对象的语义属性，供报告过滤和过程间分析消费。

| 属性字段 | 类型 | 说明 |
|----------|------|------|
| `is_local_var` | `bool` | 是否为函数局部变量（`mop_l` 或未溢出到全局的 `mop_S`） |
| `is_stack_spill` | `bool` | 是否为寄存器溢出到栈（由 `m_stx` 写入 `mop_S` 推断） |
| `is_global_var` | `bool` | 是否为全局 / 静态变量（`mop_v`，ea 落入 `.data` / `.bss` 段） |
| `is_func_param` | `bool` | 是否为当前函数的形参（在 Entry Block 前无 def，由 `lvar_t::is_arg_var()` 确认） |
| `is_func_retval` | `bool` | 是否来自函数返回值（挂在 `m_call` 的 `d` 字段） |
| `call_arg_positions` | `List[CallArgInfo]` | 作为哪些函数调用的第几个参数出现（全量记录，含非 Sink 调用） |
| `is_ptr` | `bool` | 是否疑似指针（基于指针宽度判断或在 `ldx` / `stx` 中被解引用） |
| `points_to_tainted` | `bool` | 若为指针：其指向区域是否也被污染（由 AliasSet 交叉推断） |
| `is_cond_checked` | `bool` | 传播链上是否存在对该值的条件分支检查（不保证安全，仅供参考） |
| `sanitized_by` | `string \| null` | 经过净化函数时记录函数名；否则为 `null` |

### 2.3 `StepRecord`——传播路径节点

`StepRecord` 记录单步传播事件，所有节点串联构成完整的污染传播链。

| 字段 | 类型 | 含义 |
|------|------|------|
| `insn_ea` | `ea_t` | 发生传播的指令地址 |
| `mcode` | `mcode_t` | MicroCode 操作码（`m_mov` / `m_add` 等） |
| `from_key` | `string` | 传播源操作数键 |
| `to_key` | `string` | 传播目标操作数键 |
| `block_serial` | `int` | 所在基本块编号 |
| `reason` | `PropReason` | 传播原因枚举（见下表） |

**`PropReason` 枚举定义**

| 枚举值 | 含义 |
|--------|------|
| `DATA_MOVE` | `m_mov` 直接赋值传播 |
| `ARITHMETIC` | 算术 / 逻辑运算结果依赖污点操作数 |
| `MEM_LOAD` | 内存读取（`m_ldx`）从污染内存加载 |
| `MEM_STORE` | 内存写入（`m_stx`）将污点写入目标 |
| `CALL_ARG_IN` | 函数调用传入污点参数（callee 未知，保守传播） |
| `CALL_RET_OUT` | 函数返回值被标记为污点（Source 规则命中） |
| `PHI_MERGE` | 控制流汇聚时 Union 操作合并污点 |
| `ALIAS_MAY` | 别名分析结论为 May-Alias，保守传播 |

### 2.4 `CallArgInfo`——参数位置记录

| 字段 | 类型 | 含义 |
|------|------|------|
| `call_ea` | `ea_t` | 调用指令地址 |
| `callee` | `string` | 被调函数名或地址字符串 |
| `arg_index` | `int` | 第几个参数（0-based） |
| `is_sink` | `bool` | 该被调函数是否为 Sink |
| `arg_size` | `int` | 参数字节宽度 |

### 2.5 `AliasSet`——别名映射

`AliasSet` 是一个映射表：

```
Pointer Key  →  Set<Target Key>
```

用于处理 `m_ldx` / `m_stx` 间接内存访问。当目标集合无法静态确定时，以特殊标记 `Unknown` 表示，触发保守（Over-taint）策略。

---

## 3. 传递函数（Transfer Function）

传递函数 $f_B$ 模拟基本块内指令序列（`mblock_t::head` 到 `mblock_t::tail`）的执行，逐条处理 `minsn_t`。

指令级函数签名：

$$S_{out} = f_{\text{inst}}(S_{in},\ \text{minsn})$$

### 3.1 数据移动（`m_mov`）

**指令：** `mov  d,  l`

```python
# TaintSet 更新
if is_tainted(l):
    taint(d, chain=l.chain + [Step(insn, DATA_MOVE)], reason=DATA_MOVE)
else:
    untaint(d)    # Strong Update：d 被完全覆盖

# AliasSet 更新
PT(d) = PT(l)    # 指针传播

# 属性更新
if tainted(d):
    d.attrs.is_local_var   = is_lvar(d)
    d.attrs.is_stack_spill = (d.mop_type == mop_S)
    d.attrs.is_ptr         = is_pointer_sized(d) or used_in_ldx_stx(d)
```

### 3.2 算术运算（`m_add` / `m_sub` / `m_and` 等）

**指令：** `add  d,  l,  r`

```python
if is_tainted(l) or is_tainted(r):
    merged = merge_chains(l, r)    # 合并两侧传播路径
    taint(d, chain=merged, reason=ARITHMETIC)
else:
    untaint(d)

# 指针偏移特例
if is_ptr(l) and is_const(r):
    PT(d) = Shift(PT(l), r)        # 偏移后更新 Points-to 集合
else:
    PT(d) = Unknown                # 保守：丢弃别名信息
```

### 3.3 内存读取（`m_ldx`）

**指令：** `ldx  d,  l,  r`（`d = *(l + r)`）

```python
addr_key = resolve_addr(l, r)
targets  = PT(addr_key)            # 别名解析

if any(is_tainted(o) for o in targets):
    # 选取传播深度最深的污染源作为代表
    src = max(tainted_targets, key=lambda o: o.propagation_depth)
    taint(d, chain=src.chain + [Step(insn, MEM_LOAD)], reason=MEM_LOAD)
    d.attrs.is_ptr = is_pointer_sized(d)
elif targets == Unknown:
    taint(d, reason=ALIAS_MAY)     # Over-taint 策略
```

### 3.4 内存写入（`m_stx`）

**指令：** `stx  d,  l,  r`（`*(d + l) = r`）

```python
addr_key = resolve_addr(d, l)
targets  = PT(addr_key)

if is_tainted(r):
    for o in targets:
        taint(o, chain=r.chain + [Step(insn, MEM_STORE)], reason=MEM_STORE)
        o.attrs.is_stack_spill = (o.mop_type == mop_S)
else:
    if is_must_alias(targets):     # 唯一目标 → Strong Update
        untaint(targets[0])
    # 多目标 → Weak Update：保留原有污点
```

### 3.5 函数调用（`m_call`）

**指令：** `call  d,  l,  args`

```python
# ① Source 规则
if callee_matches_source(l):
    out_mop = get_output_mop(l, d, args)    # 返回值或 out 参数
    taint(out_mop,
          source_ea=insn.ea,
          source_func=callee_name(l),
          chain=[],
          reason=CALL_RET_OUT)
    out_mop.attrs.is_func_retval = True

# ② Sink 规则
if callee_matches_sink(l):
    for idx, arg in enumerate(args):
        if is_tainted(arg):
            emit_finding(arg,
                         sink_ea=insn.ea,
                         sink_func=callee_name(l),
                         arg_index=idx)

# ③ 参数属性更新（所有调用均执行）
for idx, arg in enumerate(args):
    if is_tainted(arg):
        arg.attrs.call_arg_positions.append(CallArgInfo(
            call_ea   = insn.ea,
            callee    = callee_name(l),
            arg_index = idx,
            is_sink   = callee_matches_sink(l),
            arg_size  = arg.size_bytes
        ))

# ④ Sanitizer 规则
if callee_matches_sanitizer(l):
    untaint(d)
    mark_sanitized(args, by=callee_name(l))

# ⑤ 默认保守传播（未知被调函数）
elif not callee_is_known(l):
    if any(is_tainted(a) for a in args):
        taint(d, reason=CALL_ARG_IN)   # 返回值保守依赖任意污染参数
```

---

## 4. 算法流程与各 Pass 输出规范

算法分为四个 Pass，依次执行，每个 Pass 产出独立的结构化输出对象。

---
## 4.1 Pass 0 — 预处理与初始化

在进入工作列表迭代前执行一次，完成 CFG 快照、状态表初始化及函数内静态站点扫描。

> `lvar_t` 元信息（名称、类型、参数归因等）按需通过 `mba->vars` / `lvar_t::is_arg_var()` 实时查询，无需在此阶段提前缓存。

---

### 处理内容

1. **CFG 快照**：遍历 `mba->blocks`，建立 `cfg_edges`（`pred` / `succ` 边表）及块编号索引。
2. **状态表初始化**：为所有块创建空的 `In[B]` 和 `Out[B]`，初始工作列表置为 `{entry_block}`。
3. **入口污点扫描**：扫描 Entry Block，将函数形参（`lvar_t::is_arg_var() == true`）及具备初始污点标记的全局变量写入 `initial_taint_keys`。
4. **全量站点扫描**：**一次性遍历所有块的全部指令**，按指令类型分类，产出三张静态站点表：

   | 站点表 | 触发指令 | 记录内容 |
   |--------|----------|----------|
   | `read_sites` | `m_ldx` | 读取地址表达式 `(l, r)`、目标键、所在块及指令地址 |
   | `write_sites` | `m_stx` | 写入地址表达式 `(d, l)`、源键、所在块及指令地址 |
   | `call_sites` | `m_call` | 被调函数名/地址、参数列表操作数键、返回值目标键、所在块及指令地址；同时标注 Source / Sink / Sanitizer 类别 |

   这三张表在 Pass 1 迭代中直接复用，避免重复遍历指令流；`call_sites` 还作为 Pass 3 报告生成时 `intermediate_funcs` 列表的基础索引。

---

### 输出：`InitResult`

| 字段 | 类型 | 内容 |
|------|------|------|
| `block_count` | `int` | CFG 基本块总数（`mba->qty`） |
| `entry_serial` | `int` | 入口块编号（通常为 0） |
| `In` | `Map<int, State>` | 所有块初始 In 状态（均为空集） |
| `Out` | `Map<int, State>` | 所有块初始 Out 状态（均为空集） |
| `worklist` | `Queue<mblock_t*>` | 初始队列，仅含入口块 |
| `cfg_edges` | `List[(src, dst)]` | 全部 CFG 边（用于传播路径重建） |
| `initial_taint_keys` | `Set[string]` | 入口块初始污染操作数键集合（形参 + 全局初始污点）；对应完整 `TaintedObject` 在 Pass 1 首次处理 Entry Block 时构建 |
| `read_sites` | `List[ReadSite]` | 全量内存读取站点 |
| `write_sites` | `List[WriteSite]` | 全量内存写入站点 |
| `call_sites` | `List[CallSite]` | 全量函数调用站点（含 Source / Sink / Sanitizer 分类） |

---

### 站点记录结构

**`ReadSite`**

| 字段 | 类型 | 含义 |
|------|------|------|
| `insn_ea` | `ea_t` | 指令地址 |
| `block_serial` | `int` | 所在基本块编号 |
| `src_key` | `string` | 被写入源操作数键（`r`） |
| `dst_key` | `string` | 读取目标操作数键（`d`） |

**`WriteSite`**

| 字段 | 类型 | 含义 |
|------|------|------|
| `insn_ea` | `ea_t` | 指令地址 |
| `block_serial` | `int` | 所在基本块编号 |
| `src_key` | `string` | 被写入源操作数键（`r`） |
| `dst_key` | `string` | 读取目标操作数键（`d`） |

**`CallSite`**

| 字段 | 类型 | 含义 |
|------|------|------|
| `insn_ea` | `ea_t` | 调用指令地址 |
| `block_serial` | `int` | 所在基本块编号 |
| `callee` | `string` | 被调函数名或地址字符串 |
| `arg_keys` | `List[string]` | 各参数操作数键（按序，0-based） |
| `ret_key` | `string \| null` | 返回值目标操作数键（`m_call` 的 `d` 字段，无则为 `null`） |
| `site_type` | `enum` | `SOURCE` / `SINK` / `SANITIZER` / `UNKNOWN` |


---

### 4.2 Pass 1 — 工作列表迭代

工作列表不动点迭代，反复处理基本块直至所有块的 Out 状态收敛。

#### 算法伪代码

```python
while worklist not empty:
    B = worklist.pop()

    # ① Meet：合并所有前驱的 Out 状态
    Current_In = State()
    for P_idx in B.pred:
        Current_In.merge(Out[P_idx])
        # 同一 key 的两个 TaintedObject 合并规则：
        #   - propagation_chain 取 union（去重）
        #   - attrs 按位 OR（保守合并）
        #   - 补记 reason |= PHI_MERGE

    # ② Transfer：逐指令应用传递函数
    Current_Out = Current_In.clone()
    inst = B.head
    while inst:
        Current_Out = apply_transfer(Current_Out, inst)
        inst = inst.next

    # ③ 收敛检测
    if not Current_Out.equals(Out[B.serial]):
        Out[B.serial] = Current_Out
        for S_idx in B.succ:
            if S_idx not in worklist:
                worklist.push(mba.get_mblock(S_idx))
```

#### 每轮迭代输出：`BlockIterResult`

| 字段 | 类型 | 内容 |
|------|------|------|
| `block_serial` | `int` | 当前处理的块编号 |
| `iteration_round` | `int` | 本块第几次进入工作列表 |
| `in_state` | `State snapshot` | 本次 In 状态快照（调试模式存储） |
| `out_state` | `State snapshot` | 本次 Out 状态快照 |
| `state_changed` | `bool` | Out 状态是否与上次不同（触发后继激活） |
| `new_findings` | `List[Finding]` | 本块本轮新发现的 Sink 命中（去重） |
| `activated_succs` | `List[int]` | 本轮加入工作列表的后继块编号 |

#### 收敛后输出：`ConvergedResult`

| 字段 | 类型 | 内容 |
|------|------|------|
| `converged` | `bool` | 是否正常收敛（未超出最大迭代轮数） |
| `total_iterations` | `int` | 全部块处理总次数（含重入） |
| `Out` | `Map<int, State>` | 每个基本块收敛后的最终 Out 状态 |
| `In_final` | `Map<int, State>` | 每个基本块最终 In 状态（由前驱 Out 推算） |
| `all_tainted_objects` | `List[TaintedObject]` | 函数内所有曾被污染的操作数（全集，含已 untaint 的历史节点） |
| `all_findings` | `List[Finding]` | 所有 Sink 命中（去重后） |
| `cfg_taint_coverage` | `float` | 被污染指令数 / 总指令数（覆盖率参考指标） |

---

### 4.3 Pass 2 — 属性精化（Attribute Refinement）

在收敛结果基础上，对每个 `TaintedObject` 执行一次全局后处理，填充需要跨块信息才能确定的属性字段。

#### 处理项

| 处理项 | 数据来源 | 写入字段 |
|--------|----------|----------|
| 参数归因 | Entry Block In 中的污染对象 vs `mba` 参数列表 | `attrs.is_func_param` |
| 条件检查标记 | CFG 中所有条件分支指令（`m_jnz` / `m_jz` 等）的操作数 | `attrs.is_cond_checked` |
| 净化传播标注 | 传播链中是否经过 Sanitizer 调用 | `attrs.sanitized_by` |
| 指针解引用链 | `AliasSet` 与 `TaintedObjectSet` 交叉检查 | `attrs.points_to_tainted` |
| 全局变量标注 | `mop_v` 的 `ea` 落入 `.data` / `.bss` 段 | `attrs.is_global_var` |

#### 输出：`RefinedTaintDB`

| 字段 | 类型 | 内容 |
|------|------|------|
| `tainted_objects` | `List[TaintedObject]` | 属性精化后的污染对象全集 |
| `param_taints` | `List[TaintedObject]` | `attrs.is_func_param == true` 的子集 |
| `global_taints` | `List[TaintedObject]` | `attrs.is_global_var == true` 的子集 |
| `ptr_taints` | `List[TaintedObject]` | `attrs.is_ptr == true` 的子集 |
| `sink_arg_taints` | `List[TaintedObject]` | `call_arg_positions` 中含 `is_sink == true` 的子集 |

---

### 4.4 Pass 3 — 报告生成（Finding Emission）

将 Pass 1 的 `all_findings` 与 Pass 2 的 `RefinedTaintDB` 合并，生成完整的结构化分析报告。

#### `Finding` 完整结构

| 字段 | 类型 | 含义 |
|------|------|------|
| `finding_id` | `UUID` | 唯一报告 ID |
| `severity` | `enum` | `HIGH` / `MEDIUM` / `LOW`（基于 `is_cond_checked` 和 `sanitized_by` 评定） |
| `source_ea` | `ea_t` | 污点来源指令地址 |
| `source_func` | `string` | 引入污点的函数名 |
| `sink_ea` | `ea_t` | Sink 指令地址 |
| `sink_func` | `string` | Sink 函数名 |
| `sink_arg_index` | `int` | 污点命中 Sink 的参数位置（0-based） |
| `taint_object` | `TaintedObject` | 命中 Sink 时的污染对象完整记录（含 `attrs`） |
| `propagation_chain` | `List[StepRecord]` | 从 Source 到 Sink 的完整传播路径 |
| `chain_length` | `int` | 传播链节点数 |
| `intermediate_funcs` | `List[string]` | 传播链经过的中间函数调用列表 |
| `is_cond_checked` | `bool` | 路径上是否存在条件检查（不保证安全，仅供参考） |
| `sanitized_by` | `string \| null` | 若经过净化函数则记录函数名，否则为 `null` |

#### Severity 评级逻辑

| 条件 | Severity |
|------|----------|
| `sanitized_by != null` | `LOW`（已净化，保留记录供人工复核） |
| `sanitized_by == null` 且 `is_cond_checked == true` | `MEDIUM`（有条件检查但未净化，存在绕过可能） |
| `sanitized_by == null` 且 `is_cond_checked == false` | `HIGH`（无任何检查或净化） |

#### 输出：`AnalysisReport`

| 字段 | 类型 | 内容 |
|------|------|------|
| `func_ea` | `ea_t` | 被分析函数起始地址 |
| `func_name` | `string` | 函数名 |
| `analysis_time_ms` | `int` | 分析耗时（毫秒） |
| `maturity` | `MMAT_*` | MicroCode 成熟度级别 |
| `converged` | `bool` | 是否正常收敛 |
| `findings` | `List[Finding]` | 所有 Sink 命中报告（按 `severity` 降序排列） |
| `tainted_objects` | `List[TaintedObject]` | 函数内所有污染对象（含完整属性，按 `propagation_depth` 升序） |
| `block_summaries` | `Map<int, BlockSummary>` | 每基本块的污点摘要（过程间分析接口） |
| `stats` | `AnalysisStats` | 统计信息 |

#### `BlockSummary` 结构

供过程间分析（Inter-procedural Analysis）消费，是函数摘要（Function Summary）的核心组成部分。

| 字段 | 类型 | 内容 |
|------|------|------|
| `block_serial` | `int` | 块编号 |
| `in_taint_keys` | `Set[string]` | 进入块时被污染的操作数键集合 |
| `out_taint_keys` | `Set[string]` | 离开块时被污染的操作数键集合 |
| `new_sources` | `List[ea_t]` | 块内新产生污点的 Source 指令地址 |
| `sink_hits` | `List[Finding]` | 块内 Sink 命中记录 |
| `taint_gen` | `Set[string]` | 块内新生成的污点键（Gen 集合） |
| `taint_kill` | `Set[string]` | 块内被清除的污点键（Kill 集合） |

#### `AnalysisStats` 结构

| 字段 | 类型 | 内容 |
|------|------|------|
| `total_insns` | `int` | 总指令数 |
| `tainted_insns` | `int` | 产生 / 传播污点的指令数 |
| `total_tainted_objects` | `int` | 曾被污染的操作数总数（历史最大，含已 untaint） |
| `live_tainted_objects` | `int` | 最终 `Out[Exit]` 中仍存活的污染对象数 |
| `findings_high` | `int` | `HIGH` severity Finding 数 |
| `findings_medium` | `int` | `MEDIUM` severity Finding 数 |
| `findings_low` | `int` | `LOW` severity Finding 数 |
| `alias_unknown_count` | `int` | 别名无法解析（触发 Over-taint）的次数 |
| `worklist_iterations` | `int` | 工作列表总迭代次数 |

---

## 5. 针对 IDA MicroCode 的特殊处理

### 5.1 成熟度级别选择

| 成熟度 | 特点 | 推荐场景 |
|--------|------|----------|
| `MMAT_LOCOPT` | 局部优化后，`m_mov` 丰富，栈变量已转为 `mop_l` / `mop_S` | 通用污点分析（推荐） |
| `MMAT_CALLS` | 调用规范化，参数布局清晰，`is_func_param` 属性更准确 | 重点关注跨函数传播 |
| `MMAT_GLBOPT2` | 全局优化后，部分变量被内联，传播链可能断裂 | 不推荐，除非有特定需求 |

### 5.2 Sub-instructions（`mop_d`）递归处理

MicroCode 操作数可能包含嵌套子指令（如 `add(mul(a, b), c)`）。传递函数须先递归计算子表达式的污点状态，再计算外层：

```python
def eval_mop_taint(mop, state):
    if mop.t == mop_d:           # 嵌套子指令
        return eval_insn_taint(mop.d, state)
    return state.is_tainted(mop_key(mop))
```

### 5.3 `attrs.is_func_param` 的精确判定

函数形参识别须结合 `mba` 的 `lvars` 元信息：

```python
for lvar in mba.vars:
    if lvar.is_arg():                    # lvar_t::is_arg_var()
        param_keys.add(f'lvar:{lvar.idx}')
    if lvar.is_stk_var():
        # 栈参数：正偏移通常为参数（x86 调用约定）
        if lvar.location.stkoff() > 0:
            param_keys.add(f'stack:{lvar.location.stkoff()}')
```

### 5.4 控制流汇聚处的 Meet 操作

当多条前驱边的 Out 状态在某基本块 B 汇聚时，执行 Union：

- **TaintedObjectSet**：同一 `key` 的多个 `TaintedObject` 合并，`propagation_chain` 取并集，`attrs` 按位 OR，补记 `reason |= PHI_MERGE`
- **AliasSet**：同一指针键的目标集合取并集
- 若任意前驱中 `key` 被污染，则 B 的 `In` 中该 `key` 被视为污染（May-Taint 语义）

### 5.5 循环收敛保证

由于污点集合单调递增（仅 `taint` / `untaint` 操作，不存在重排序），且操作数键空间有限，工作列表算法保证在有限步内收敛。建议设置最大迭代轮数上限（如 `block_count * 3`），超限时置 `converged = false` 并记录警告。

---

## 6. 完整输出流程总览

四个 Pass 形成完整的分析流水线，每个 Pass 的输出均可独立序列化（JSON / MessagePack），支持持久化及外部工具消费。

| Pass | 名称 | 主要输入 | 核心处理 | 主要输出 |
|------|------|----------|----------|----------|
| Pass 0 | 预处理与初始化 | `mba_t`, 规则集 | CFG 快照；状态表初始化；lvar 元信息提取 | `InitResult` |
| Pass 1 | 工作列表迭代 | `InitResult` | Meet + Transfer；不动点迭代 | `ConvergedResult` |
| Pass 2 | 属性精化 | `ConvergedResult` | 跨块属性填充；条件检查标记；净化链追溯 | `RefinedTaintDB` |
| Pass 3 | 报告生成 | `ConvergedResult` + `RefinedTaintDB` | Finding 组装；Severity 评级；统计汇总 | `AnalysisReport` |

`BlockSummary`（包含于 `AnalysisReport`）是过程间分析的主要接口，上层调用方（Caller）分析可以此作为被调函数（Callee）的污点行为摘要，实现模块化组合。

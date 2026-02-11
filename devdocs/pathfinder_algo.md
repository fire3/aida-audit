# PathFinder 算法设计文档

本文档描述 `backend/aida_cli/pathfinder.py` 模块的设计与实现。`PathFinder` 是一个基于静态分析的跨过程（Inter-procedural）路径搜索工具，在二进制程序的函数调用图（Call Graph）上枚举从污点源（Source）调用者到污点汇聚点（Sink）调用者的潜在调用路径，为后续指令级污点传播分析提供路径候选集。

文档中所有 IDA API 均基于实测可用接口，来自 `idautils`、`ida_funcs`、`idc` 模块。

---

## 目录

1. [模块概述](#1-模块概述)
2. [规则集设计（RuleSet）](#2-规则集设计ruleset)
3. [数据结构定义](#3-数据结构定义)
4. [核心流程](#4-核心流程)
5. [搜索策略](#5-搜索策略)
6. [关键子过程](#6-关键子过程)
7. [结果聚合与去重](#7-结果聚合与去重)
8. [边界条件与错误处理](#8-边界条件与错误处理)
9. [性能约束与参数配置](#9-性能约束与参数配置)
10. [模块流程总览](#10-模块流程总览)

---

## 1. 模块概述

### 1.1 定位与职责

`PathFinder` 工作在**函数调用图（Call Graph）**级别，不执行指令级数据流分析。其职责边界如下：

| 职责 | 说明 |
|------|------|
| **负责** | 在 Call Graph 上枚举 Source → Sink 的函数调用链 |
| **负责** | 解析 Source / Sink / Propagator 规则，定位对应函数及其调用者 |
| **负责** | 处理直接调用与部分间接调用（函数指针、vtable） |
| **不负责** | 指令级数据流分析或污点传播 |
| **不负责** | 路径可行性验证（路径上是否真正存在数据依赖） |

### 1.2 输入与输出

**输入：**

| 参数 | 类型 | 说明 |
|------|------|------|
| `ruleset` | `RuleSet` | 包含 Source / Sink / Propagator 规则列表 |
| `config` | `PathFinderConfig` | 搜索参数配置（详见第 9 节） |

**输出：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `paths` | `List[PathRecord]` | 所有找到的调用路径（已去重，按策略来源标注） |
| `stats` | `SearchStats` | 搜索统计信息 |
| `errors` | `List[SearchError]` | 搜索过程中的警告与错误 |

---

## 2. 规则集设计（RuleSet）

### 2.1 设计目标

规则集是 `PathFinder` 的知识驱动核心，描述哪些函数引入污点（Source）、哪些函数消费污点（Sink）、哪些函数在污点传播链上充当中转（Propagator）。规则设计需满足以下目标：

- **语义明确**：Source / Sink / Propagator 三类角色的字段定义严格区分，不共用歧义字段
- **可扩展**：支持精确名称匹配与正则表达式，覆盖 `_chk` 变体、平台前缀等命名变体
- **自描述**：每条规则携带足够的元信息（label、cwe、severity），供报告层直接消费

### 2.2 `RuleSet` 类定义

```python
class RuleSet:
    def __init__(self, rule_id, cwe, title, severity, sources, sinks, propagators):
        self.rule_id     = rule_id      # str：规则集唯一 ID，如 "cwe-78"
        self.cwe         = cwe          # str：对应 CWE 编号
        self.title       = title        # str：规则集名称
        self.severity    = severity     # str："high" / "medium" / "low"
        self.sources     = self._compile_rules(sources)
        self.sinks       = self._compile_rules(sinks)
        self.propagators = self._compile_rules(propagators)

    def _compile_rules(self, rules):
        """预编译 pattern 字段为 re 对象，加速后续匹配。"""
        compiled = []
        for rule in rules or []:
            entry = dict(rule)
            pattern = entry.get("pattern")
            if pattern:
                entry["regex"] = re.compile(pattern, re.IGNORECASE)
            compiled.append(entry)
        return compiled
```

### 2.3 Source 规则字段规范

Source 规则描述**引入污点的函数**，关注的是哪个参数或返回值携带了不可信数据。

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | `str` | 二选一 | 精确函数名，如 `"recv"` |
| `pattern` | `str` | 二选一 | 正则表达式，编译后存于 `regex` 字段 |
| `args` | `List[int]` \| `None` | 否 | 携带污点的**输出参数**位置（0-based）；`None` 表示不关注特定参数 |
| `ret` | `bool` | 否 | `True` 表示**返回值**携带污点（如 `getenv`）；默认 `False` |
| `label` | `str` | 建议填写 | 人类可读标识，用于报告展示 |

**设计说明：** `args` 在 Source 规则中表示"污点输出到哪个参数"（write side），与 Sink 规则中"哪个参数接收污点"（read side）方向相反，字段名相同但语义不同——**建议**后续版本将 Source 的该字段重命名为 `out_args`，Sink 的重命名为 `in_args`，以消除歧义。当前版本维持 `args` 以保持向后兼容。

**示例：**

```python
{"name": "recv",   "args": [1],  "ret": False, "label": "recv"}
{"name": "getenv", "args": None, "ret": True,  "label": "getenv"}
{"pattern": r"^get.*input$", "args": [0], "ret": False, "label": "custom_input"}
```

### 2.4 Sink 规则字段规范

Sink 规则描述**消费污点的危险函数**，关注的是哪个参数不能接收不可信数据。

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | `str` | 二选一 | 精确函数名 |
| `pattern` | `str` | 二选一 | 正则表达式 |
| `args` | `List[int]` \| `None` | 否 | 危险的**输入参数**位置（0-based）；`None` 表示所有参数均危险（如 `execl` 可变参数） |
| `label` | `str` | 否 | 人类可读标识 |

**示例：**

```python
{"name": "system",        "args": [0]}
{"name": "execl",         "args": None}    # 所有参数均为危险输入
{"name": "CreateProcessA","args": [1]}
```

### 2.5 Propagator 规则字段规范

Propagator 规则描述**传播污点的中间函数**，表达"污点从哪个参数流入，流出到哪个参数或返回值"。

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | `str` | 二选一 | 精确函数名 |
| `pattern` | `str` | 二选一 | 正则表达式（用于覆盖 `_chk` 等变体） |
| `from_args` | `List[int]` | 是 | 污点**输入**参数位置 |
| `to_args` | `List[int]` \| `None` | 否 | 污点**输出**参数位置；`None` 表示无输出参数传播 |
| `ret` | `bool` | 否 | `True` 表示返回值携带传播后的污点（如 `strdup`）；默认 `False` |

**当前版本已知缺失项：**

| 缺失字段 | 含义 | 影响 |
|----------|------|------|
| `ret: True` on propagators | 函数返回传播副本（如 `strdup`） | 漏报通过返回值传播的路径 |
| `clobbers` | 函数写入目标但不依赖污点来源（如 `memset`） | 可能出现误报（本应净化的路径未被截断） |

**示例：**

```python
{"name": "strcpy",  "from_args": [1], "to_args": [0]}
{"name": "sprintf", "from_args": [1], "to_args": [0]}
# _chk 变体用正则覆盖
{"pattern": r"^_*strcpy_chk$",  "from_args": [1], "to_args": [0]}
{"pattern": r"^_*memcpy_chk$",  "from_args": [1], "to_args": [0]}
# 补充：strdup 通过返回值传播
{"name": "strdup",  "from_args": [0], "to_args": None, "ret": True}
```

### 2.6 内置规则集：CWE-78（OS Command Injection）

`default_cwe78_rules()` 提供针对操作系统命令注入的内置规则集，覆盖以下范围：

**Source 覆盖：**

| 函数 | 污点输出 | 说明 |
|------|----------|------|
| `recv` | `args[1]` | 网络输入缓冲区 |
| `recvfrom` | `args[1]` | 网络输入缓冲区 |
| `read` | `args[1]` | 文件/管道读入缓冲区 |
| `fgets` | `args[0]` | 标准输入缓冲区 |
| `gets` | `args[0]` | 标准输入（已废弃，高危） |
| `scanf` / `fscanf` | `args[1]` | 格式化输入 |
| `getenv` | `ret` | 环境变量字符串 |

**待补充的 Source（当前版本未覆盖）：**

| 函数 | 原因 |
|------|------|
| `fread` | 文件读取到缓冲区，`args[0]` 携带污点 |
| `getline` | POSIX 行读取，返回值及 `args[0]` 携带污点 |
| `recvmsg` | 高级网络接收接口 |
| `gets_s` / `scanf_s` | 安全版本，仍可引入污点 |

**Sink 覆盖：** `system`、`popen`、`execl/lp/le`、`execv/ve/vp`、`CreateProcess[A/W]`、`WinExec`、`ShellExecute[A/W]`、`ShellExecuteEx[A/W]`

**Propagator 覆盖：** `strcpy`、`strncpy`、`strcat`、`strncat`、`sprintf`、`snprintf`、`memcpy`、`memmove` 及其 `_chk` 变体

---

## 3. 数据结构定义

### 3.1 `PathFinderConfig`

```python
@dataclass
class PathFinderConfig:
    max_depth:            int  = 100
    max_paths:            int  = 100
    ancestor_max_depth:   int  = 10
    enable_indirect_call: bool = True
    strategies: List[str] = field(
        default_factory=lambda: ['forward', 'reverse', 'common_ancestor']
    )
```

### 3.2 `FuncNode`

调用图的基本节点。

```python
@dataclass(frozen=True)
class FuncNode:
    ea:    int        # 函数起始地址（由 ida_funcs.get_func(ref).start_ea 获取）
    name:  str        # 函数名（由 ida_funcs.get_func_name(ea) 获取）
    roles: List[str]  # 节点在路径中的角色标记
```

### 3.3 `PathRecord`

单条调用路径的完整描述。

| 字段 | 类型 | 说明 |
|------|------|------|
| `path_id` | `str` | 路径唯一标识（对路径 EA 序列做哈希） |
| `nodes` | `List[FuncNode]` | 路径节点，index 0 为 Source 侧，最后一个为 Sink 侧 |
| `source` | `dict` | Source 信息：`name`、`ea`（hex str）、`args` |
| `sink` | `dict` | Sink 信息：`name`、`ea`（hex str）、`args` |
| `strategy` | `str` | `'forward'` / `'reverse'` / `'common_ancestor'` |
| `depth` | `int` | 路径节点数 |
| `has_indirect` | `bool` | 路径中是否包含间接调用边 |

**`source` / `sink` 字段结构：**

```python
{
    "name": "recv",          # 规则中的 name 字段（精确匹配时）或匹配到的函数名
    "ea":   "0x401000",      # 十六进制字符串
    "args": [1]              # 对应规则中的 args 字段
}
```

**`nodes.roles` 角色标记：**

| 角色 | 说明 |
|------|------|
| `source_caller` | 路径起点，调用 Source 的函数 |
| `sink_caller` | 路径终点，调用 Sink 的函数 |
| `common_ancestor` | 公共祖先路径中的祖先节点 |
| `intermediate` | 其他中间节点 |

### 3.4 `SearchStats`

```python
@dataclass
class SearchStats:
    source_funcs_found:   int   # 识别到的 Source 函数数
    sink_funcs_found:     int   # 识别到的 Sink 函数数
    source_callers_found: int   # Source 调用者数
    sink_callers_found:   int   # Sink 调用者数
    paths_forward:        int   # 前向搜索路径数
    paths_reverse:        int   # 反向搜索路径数
    paths_ancestor:       int   # 公共祖先搜索路径数
    paths_total:          int   # 去重后总路径数
    nodes_visited:        int   # 搜索访问函数节点总数
    search_time_ms:       int   # 搜索耗时（毫秒）
```

### 3.5 `SearchError`

```python
@dataclass
class SearchError:
    level:   str   # 'warning' 或 'error'
    stage:   str   # 发生阶段，如 'marker_identification'、'forward_search'
    message: str
```

---

## 4. 核心流程

整体执行分为三个阶段：**标记识别 → 调用者定位 → 路径搜索**。

### 4.1 阶段一：标记识别（Marker Identification）

**目标：** 在二进制符号表中定位 Source 和 Sink 函数的有效地址。

**名称收集（`_collect_names`）：**

使用 `idautils.Names()` 遍历二进制中所有已命名地址，同时剥离常见前缀变体，建立统一的 `name → ea` 映射：

```python
def _collect_names(self):
    name_map = {}
    for ea, name in idautils.Names():
        name_map[name] = ea
        # 剥离 __imp_ 前缀：使 "__imp_recv" 也能被 "recv" 规则匹配
        if name.startswith("__imp_"):
            name_map[name[6:]] = ea
        # 剥离单下划线前缀：覆盖 MSVC/GCC 的 C 函数修饰
        elif name.startswith("_"):
            name_map[name[1:]] = ea
    return name_map
```

> **为何使用 `idautils.Names()` 而非 `enum_import_names`：** `idautils.Names()` 涵盖导入表、导出表、已分析函数的全量命名地址，接口稳定，无需额外处理模块枚举，适合通用场景。

**名称解析回退（`_resolve_name`）：**

对于 `idautils.Names()` 中未出现但可能存在的名称，使用 `idc.get_name_ea_simple()` 做精确回退查找，并尝试 `_`、`__imp_`、`__imp__`、`.` 等前缀变体：

```python
def _resolve_name(self, name):
    ea = idc.get_name_ea_simple(name)
    if ea != self.badaddr:
        return ea
    for prefix in ("_", "__imp_", "__imp__", "."):
        ea = idc.get_name_ea_simple(prefix + name)
        if ea != self.badaddr:
            return ea
    return self.badaddr
```

> **`BADADDR` 的获取：** 优先从 `ida_idaapi.BADADDR` 读取，回退到 `idc.BADADDR`，最终兜底值为 `0xFFFFFFFFFFFFFFFF`，以兼容不同 IDA 版本。

**规则匹配（`_match_rules_against_names`）：**

对每条规则，按以下优先级顺序匹配：

1. **精确名称匹配**：在 `name_map` 中直接查找 `rule["name"]`
2. **名称解析回退**：调用 `_resolve_name` 尝试前缀变体
3. **正则表达式匹配**：若规则含 `regex` 字段，遍历 `name_map` 执行 `regex.match()`

```python
def _match_rules_against_names(self, rules, name_map, target_set, rule_map):
    for rule in rules:
        matched_ea = None

        # 1. 精确名称匹配
        name = rule.get("name")
        if name:
            matched_ea = name_map.get(name) or None
            if matched_ea is None:
                resolved = self._resolve_name(name)
                if resolved != self.badaddr:
                    matched_ea = resolved

        # 2. 正则匹配（精确匹配未命中时）
        if matched_ea is None and rule.get("regex"):
            for n, ea in name_map.items():
                if rule["regex"].match(n):
                    matched_ea = ea
                    break

        if matched_ea is not None and matched_ea != self.badaddr:
            target_set.add(matched_ea)
            rule_map[matched_ea] = rule
```

> **注意：** 正则使用 `.match()` 而非 `.fullmatch()`，前者匹配字符串开头，后者要求完全匹配。若规则意图全量匹配（如 `^system$`），pattern 中应显式添加 `$`。建议统一在规则 `pattern` 中使用 `^...$` 形式，并在文档中明确约定。

### 4.2 阶段二：调用者定位（Caller Resolution）

**目标：** Source / Sink 通常为库函数，路径的实际起点和终点是调用它们的函数（Callers）。

**方法：** `_get_callers(target_eas) -> Set[int]`

```python
def _get_callers(self, target_eas):
    callers = set()
    for target_ea in target_eas:
        for ref in idautils.CodeRefsTo(target_ea, 0):
            # flow=0：仅收集调用引用，排除顺序执行流
            func = ida_funcs.get_func(ref)
            if func:
                callers.add(func.start_ea)
    return callers
```

> **`CodeRefsTo(ea, flow)` 说明：** 第二参数 `flow=0`（即 `False`）表示仅返回显式控制转移引用（`call` 指令），排除顺序执行流。这是避免将非调用的代码引用误判为 caller 的关键。

**调用者到目标的反向映射（`_map_callers_to_targets`）：**

用于在结果构建阶段确定"某个 caller 具体调用了哪个 Source / Sink 函数"，在存在多个 Source 或 Sink 函数时尤为重要：

```python
def _map_callers_to_targets(self, target_eas):
    caller_map = {}  # caller_ea -> Set[target_ea]
    for target_ea in target_eas:
        for ref in idautils.CodeRefsTo(target_ea, 0):
            func = ida_funcs.get_func(ref)
            if func:
                caller_map.setdefault(func.start_ea, set()).add(target_ea)
    return caller_map
```

---

## 5. 搜索策略

`PathFinder` 实现三种互补的搜索策略，覆盖不同的调用图拓扑结构。三种策略独立执行，结果统一在第 7 节聚合去重。

### 5.1 前向搜索（Forward Search）

**适用场景：** 标准调用链，Source Caller 直接或间接调用 Sink Caller。

```
Source Caller  →  [中间函数...]  →  Sink Caller
                                        ↓
                                       Sink
```

**算法：**

```python
def _bfs_search(self, start_nodes, end_nodes, neighbor_fn=None):
    if not start_nodes or not end_nodes:
        return []
    if neighbor_fn is None:
        neighbor_fn = self._get_callees

    queue      = deque([(start, [start]) for start in start_nodes])
    visited    = set(start_nodes)   # 全局 visited：跨 start_nodes 共享（见注）
    found_paths = []

    while queue:
        curr_ea, path = queue.popleft()

        if len(path) > self.MAX_DEPTH:
            continue

        if curr_ea in end_nodes:
            found_paths.append(path)
            if len(found_paths) >= self.MAX_PATHS:
                break
            continue    # 到达终点后不再向下展开，避免路径过长

        for callee in neighbor_fn(curr_ea):
            if callee not in visited:
                visited.add(callee)
                queue.append((callee, path + [callee]))

    return found_paths
```

> **关于全局 `visited` 的设计取舍：** 当前实现中，所有 `start_nodes` 共享同一 `visited` 集合。这意味着：若节点 X 在处理 Source Caller A 时已被访问，则处理 Source Caller B 时不会再次访问 X。此设计**不会产生误报**（已发现的路径均真实存在），但可能导致**漏报**（B 经过 X 到达 Sink 的路径被跳过）。取舍理由：在大型二进制中，为每个 start_node 维护独立 visited 集合会导致时间和内存开销爆炸，全局共享是可接受的性能优先策略。

**调用方式（前向）：**

```python
fwd_paths = self._bfs_search(source_callers, sink_callers)
```

### 5.2 反向搜索（Reverse Search）

**适用场景：** 捕获 Sink Caller 直接或间接调用 Source Caller 的非典型数据流（如回调注册后被 Source 触发的场景）。

**算法：** 复用 `_bfs_search`，交换 `start_nodes` 与 `end_nodes`，对结果路径进行翻转：

```python
rev_paths = self._bfs_search(sink_callers, source_callers)
# 翻转路径，使 index 0 统一为 Source 侧
for p in rev_paths:
    result = _build_result(p[::-1])
```

**输出约定：** 翻转后的路径与前向路径格式一致，`nodes[0]` 为靠近 Source 的一侧，`nodes[-1]` 为靠近 Sink 的一侧。

### 5.3 公共祖先搜索（Common Ancestor Search）

**适用场景：** Source Caller 与 Sink Caller 不在同一调用链上，而是共享一个公共父函数（Common Ancestor）分别调用两侧。

```
        Common Ancestor
       /               \
 Source Caller      Sink Caller
      |                  |
    Source              Sink
```

**典型模式：** `main` 函数先后调用 `read_input`（间接调 Source）和 `exec_output`（间接调 Sink），`main` 即为公共祖先。

**算法：**

```python
def find_common_ancestors(self, source_callers, sink_callers):
    # 阶段 1：从 Source Callers 向上 BFS，构建祖先路径表
    source_ancestors = {}   # ancestor_ea -> path_from_source_caller_to_ancestor
    queue         = deque([(start, [start]) for start in source_callers])
    visited_source = set(source_callers)

    while queue:
        curr, path = queue.popleft()
        source_ancestors[curr] = path           # 记录到达 curr 的路径

        if len(path) > self.MAX_ANCESTOR_DEPTH:
            continue

        for caller in self._get_callers_single(curr):
            if caller not in visited_source:
                visited_source.add(caller)
                queue.append((caller, path + [caller]))

    # 阶段 2：从 Sink Callers 向上 BFS，检测与 source_ancestors 的交集
    queue        = deque([(start, [start]) for start in sink_callers])
    visited_sink = set(sink_callers)
    common_paths = []

    while queue:
        curr, path_from_sink = queue.popleft()

        if curr in source_ancestors:
            src_path = source_ancestors[curr]
            # src_path:       [source_caller, ..., common_ancestor]
            # path_from_sink: [sink_caller,   ..., common_ancestor]
            #
            # 目标路径：[source_caller, ..., common_ancestor, ..., sink_caller]
            # path_from_sink[-2::-1]：将 path_from_sink 去掉末尾的 common_ancestor 后逆序
            #   即 [倒数第二个节点, ..., sink_caller]
            # 合并：src_path + path_from_sink[-2::-1]
            merged = src_path + path_from_sink[-2::-1]
            common_paths.append((merged, curr))

        if len(path_from_sink) > self.MAX_ANCESTOR_DEPTH:
            continue

        for caller in self._get_callers_single(curr):
            if caller not in visited_sink:
                visited_sink.add(caller)
                queue.append((caller, path_from_sink + [caller]))

    return common_paths
```

**路径合并逻辑说明：**

设公共祖先为 A，Source Caller 为 S，Sink Caller 为 K：

- `src_path` = `[S, p1, p2, A]`（从 S 向上走到 A）
- `path_from_sink` = `[K, q1, A]`（从 K 向上走到 A）
- `path_from_sink[-2::-1]` = 对 `[K, q1, A]` 去掉最后的 `A`，即 `[K, q1]`，再逆序得 `[q1, K]`
- 合并结果 = `[S, p1, p2, A, q1, K]`

最终路径含义：从 Source Caller 沿调用链向上到达公共祖先，再向下到达 Sink Caller，语义上表示两者经由同一祖先关联。返回值为 `(merged_path, common_ancestor_ea)`，用于在节点角色标记中标出公共祖先节点。

---

## 6. 关键子过程

### 6.1 被调函数解析（`_get_callees`）

`_get_callees` 收集某函数的所有被调函数，覆盖直接调用与间接调用两种模式。

```python
def _get_callees(self, func_ea):
    func = ida_funcs.get_func(func_ea)
    if not func:
        return set()

    callees = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):

        # ① 直接调用：CodeRefsFrom 收集代码跳转引用
        for ref in idautils.CodeRefsFrom(head, 0):
            ref_func = ida_funcs.get_func(ref)
            # 仅收集函数入口点（排除函数内部跳转）
            if ref_func and ref_func.start_ea == ref:
                callees.add(ref_func.start_ea)

        # ② 间接调用：DataRefsFrom + 两级解引用
        for dref in idautils.DataRefsFrom(head):
            # 第一级：dref 是数据地址（可能是函数指针变量或 vtable 起始）
            for sub_dref in idautils.DataRefsFrom(dref):
                # 第二级：sub_dref 是槽内实际函数地址
                ref_func = ida_funcs.get_func(sub_dref)
                if ref_func and ref_func.start_ea == sub_dref:
                    callees.add(ref_func.start_ea)

    return callees
```

**两级 `DataRefsFrom` 解引用的含义：**

IDA 对 vtable 和全局函数指针的表示通常为两级数据引用结构：

```
call [rax]          ← 指令地址
  │
  └─ DataRefsFrom(insn_ea) → vtable_slot_ea   ← 第一级：指向数据段中的槽地址
                                  │
                                  └─ DataRefsFrom(vtable_slot_ea) → func_ea  ← 第二级：槽内存储的函数指针
```

直接对函数指针变量的调用也遵循类似模式：指令引用全局变量地址，变量内存储目标函数地址。

> **局限性：** 动态赋值的函数指针（运行时写入）、经过混淆的间接跳转无法静态解析，属于已知欠近似（Under-approximation），不影响已发现路径的正确性，但可能漏报经由这些调用点的路径。

### 6.2 上层调用者查询（`_get_callers_single`）

用于公共祖先搜索中向上遍历调用图。与 `_get_callers` 的区别是输入为单个地址。

```python
def _get_callers_single(self, func_ea):
    callers = set()
    for ref in idautils.CodeRefsTo(func_ea, 0):
        func = ida_funcs.get_func(ref)
        if func:
            callers.add(func.start_ea)
    return callers
```

### 6.3 路径结果构建（`_build_result`）

将原始路径（EA 列表）转换为带有 Source / Sink 语义信息的 `PathRecord`：

```python
def _build_result(self, path_nodes, has_indirect, strategy, ancestor_ea=None):
    if not path_nodes:
        return None

    start_caller = path_nodes[0]    # Source 侧第一个节点
    end_caller   = path_nodes[-1]   # Sink 侧最后一个节点

    # Source 信息：从 source_caller_map 查找 start_caller 调用的具体 Source 函数
    src_info = None
    if start_caller in self.source_caller_map:
        src_ea = next(iter(self.source_caller_map[start_caller]))
        rule   = self.source_rules.get(src_ea, {})
        src_info = {
            "name": rule.get("name"),
            "ea":   hex(src_ea),
            "args": rule.get("args")
        }

    # Sink 信息：从 sink_caller_map 查找 end_caller 调用的具体 Sink 函数
    sink_info = None
    if end_caller in self.sink_caller_map:
        sink_ea = next(iter(self.sink_caller_map[end_caller]))
        rule    = self.sink_rules.get(sink_ea, {})
        sink_info = {
            "name": rule.get("name"),
            "ea":   hex(sink_ea),
            "args": rule.get("args")
        }

    return {
        "path_id": self._hash_path(path_nodes),
        "nodes":   self._format_nodes(path_nodes, strategy, ancestor_ea),
        "source":  src_info,
        "sink":    sink_info,
        "strategy": strategy,
        "depth":   len(path_nodes),
        "has_indirect": has_indirect
    }
```

> **关于 `next(iter(...))` 的取舍：** 当同一 Caller 调用了多个 Source 函数时，当前实现仅取第一个。这是有意的简化设计：Call Graph 级别的路径报告以连接关系为主，多 Source 绑定的精确对应关系由后续指令级分析处理。若需完整报告，可将 `src_info` 改为列表。

**节点格式化（`_format_nodes`）：**

```python
def _format_nodes(self, path_nodes, strategy, ancestor_ea):
    nodes = []
    last_index = len(path_nodes) - 1
    for idx, ea in enumerate(path_nodes):
        roles = []
        if idx == 0:
            roles.append("source_caller")
        if idx == last_index:
            roles.append("sink_caller")
        if strategy == "common_ancestor" and ancestor_ea is not None and ea == ancestor_ea:
            roles.append("common_ancestor")
        if not roles:
            roles.append("intermediate")
        nodes.append({"name": ida_funcs.get_func_name(ea), "ea": hex(ea), "roles": roles})
    return nodes
```

---

## 7. 结果聚合与去重

三种策略执行完毕后，将结果合并、去重、排序。

### 7.1 去重规则

路径唯一性由路径的 **EA 序列**决定。两条路径的节点 EA 序列完全一致时视为重复，**按策略优先级保留先发现的记录**：

```
优先级：forward > reverse > common_ancestor
```

### 7.2 聚合流程

```python
def aggregate_results(fwd_paths, rev_paths, common_paths):
    seen = set()
    merged = []

    for raw_list in (fwd_paths, rev_paths, common_paths):
        for result in raw_list:
            # 用路径 EA 元组作为去重键
            key = tuple(node["ea"] for node in result["nodes"])
            if key not in seen:
                seen.add(key)
                merged.append(result)

    # 按路径长度升序排列（较短路径优先展示）
    merged.sort(key=lambda r: len(r["nodes"]))
    return merged
```

### 7.3 输出 JSON 格式

每条路径结果的完整 JSON 结构如下：

```json
{
  "path_id": "3b1c6f2d7d4df5e9f9b5a1a7a0b3c8b5e0e5d7aa",
  "nodes": [
    { "name": "read_input",   "ea": "0x401000", "roles": ["source_caller"] },
    { "name": "process_data", "ea": "0x401100", "roles": ["intermediate"] },
    { "name": "exec_output",  "ea": "0x401200", "roles": ["sink_caller"] }
  ],
  "strategy": "forward",
  "depth": 3,
  "has_indirect": false,
  "source": {
    "name": "recv",
    "ea":   "0x405000",
    "args": [1]
  },
  "sink": {
    "name": "system",
    "ea":   "0x406000",
    "args": [0]
  }
}
```

---

## 8. 边界条件与错误处理

| 场景 | 处理方式 | 影响范围 |
|------|----------|----------|
| 某条规则无任何名称匹配 | 记录 `warning`，继续执行其他规则 | 该规则对应的函数缺失，不影响已匹配规则 |
| Source 或 Sink 规则均无匹配 | `identify_markers` 完成后，`find_paths` 直接返回 `[]` | 整个搜索无输出 |
| `source_callers` 或 `sink_callers` 为空集 | `_bfs_search` 开头判断提前返回 `[]` | 对应策略无输出，记录 `warning` |
| Source Caller 与 Sink Caller 有交集（同一函数既调 Source 又调 Sink） | 该函数作为长度为 1 的路径，在 BFS 起点即命中 `end_nodes` | 生成 `depth=1` 路径，正常输出 |
| 调用图存在环路（递归调用） | BFS `visited` 集合防止重复入队，不会死循环 | 环路上的节点仅访问一次，不影响无环部分路径 |
| 路径深度超过 `MAX_DEPTH` | `continue` 截断该分支 | 超深路径漏报（性能优先取舍） |
| 找到路径数达到 `MAX_PATHS` | `break` 提前结束当前策略 | 超量路径漏报（性能优先取舍） |
| `ida_funcs.get_func(ref)` 返回 `None` | 跳过该引用 | 不属于任何函数的孤立代码块忽略 |
| `ref_func.start_ea != ref`（非函数入口点引用） | 跳过，仅收集函数入口点 | 排除函数内部标签引用，避免误将跳转目标当被调函数 |
| 间接调用二级解引用无法定位函数 | 跳过该 `sub_dref` | 动态函数指针漏报（欠近似，已知局限） |
| `idc.get_name_ea_simple` 抛出异常 | `try/except` 捕获，返回 `BADADDR` | 单条规则匹配失败，不影响其他规则 |

---

## 9. 性能约束与参数配置

### 9.1 参数说明

| 参数 | 默认值 | 作用 |
|------|--------|------|
| `MAX_DEPTH` | 100 | BFS 路径最大节点数，防止深度爆炸 |
| `MAX_PATHS` | 100 | 单策略最大返回路径数，防止结果集过大 |
| `MAX_ANCESTOR_DEPTH` | 10 | 公共祖先向上 BFS 最大深度；因内存占用与深度正相关，需较小值 |
| `enable_indirect_call` | `True` | 是否解析间接调用；禁用可显著提升速度，代价是漏报间接调用路径 |

### 9.2 复杂度分析

设调用图节点数为 $V$，Source Caller 数为 $S$，Sink Caller 数为 $K$，`MAX_DEPTH` 为 $D$，`MAX_ANCESTOR_DEPTH` 为 $D_a$。

| 策略 | 时间复杂度 | 空间复杂度 | 主要瓶颈 |
|------|------------|------------|----------|
| 前向搜索 | $O(V)$（全局 visited 共享） | $O(V \cdot D)$ | 路径存储随深度线性增长 |
| 反向搜索 | $O(V)$ | $O(V \cdot D)$ | 同上 |
| 公共祖先搜索 | $O((S + K) \cdot V)$ | $O(V \cdot D_a)$ | `source_ancestors` 字典内存 |

> **大型二进制调优建议（> 10,000 函数）：** 将 `MAX_ANCESTOR_DEPTH` 设为 5，`MAX_PATHS` 设为 50，`enable_indirect_call` 设为 `False`，可将分析时间控制在 30 秒以内。

---

## 10. 模块流程总览

```
输入：RuleSet + PathFinderConfig
         │
         ▼
┌─────────────────────────────────┐
│  阶段 1：标记识别                │
│  identify_markers()             │
│  · idautils.Names() 收集全量名称│
│  · 前缀剥离：__imp_ / _         │
│  · idc.get_name_ea_simple() 回退│
│  · 精确匹配 + regex.match() 匹配 │
│  输出：source_eas, source_rules  │
│        sink_eas,   sink_rules   │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  阶段 2：调用者定位              │
│  _get_callers()                 │
│  · idautils.CodeRefsTo(ea, 0)  │
│  · ida_funcs.get_func(ref)      │
│  _map_callers_to_targets()      │
│  · 构建 caller→target 反向映射  │
│  输出：source_callers            │
│        sink_callers              │
│        source_caller_map        │
│        sink_caller_map          │
└──────────────┬──────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│  阶段 3：路径搜索（三策略顺序执行）                    │
│                                                      │
│  ┌─────────────────┐  ┌─────────────────┐            │
│  │ 前向搜索         │  │ 反向搜索         │            │
│  │ _bfs_search()   │  │ _bfs_search()   │            │
│  │ source→sink     │  │ sink→source     │            │
│  │ 结果直接使用     │  │ 结果翻转 [::-1] │            │
│  └────────┬────────┘  └────────┬────────┘            │
│           │                    │                      │
│  ┌────────┴────────────────────┴──────────────────┐  │
│  │  公共祖先搜索  find_common_ancestors()          │  │
│  │  · BFS 上溯 source_callers → source_ancestors  │  │
│  │  · BFS 上溯 sink_callers，检测交集              │  │
│  │  · 合并路径：src_path + path[-2::-1]            │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────┬───────────────────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  阶段 4：结果构建与聚合   │
              │  _build_result()        │
              │  · 绑定 source/sink 信息 │
              │  · _format_nodes() 格式化 │
              │  aggregate_results()    │
              │  · EA 序列去重           │
              │  · 按 depth 升序排列     │
              └────────────┬────────────┘
                           │
                           ▼
              输出：List[PathRecord]（JSON）
              · nodes：节点列表（name + ea + roles）
              · source：Source 函数信息
              · sink：Sink 函数信息
```

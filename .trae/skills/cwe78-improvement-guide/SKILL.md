---
name: cwe78-improvement-guide
description: CWE-78 修复与改进工作
---

# Aida CWE-78 修复与改进工作指引 (Context Prompts)

此文档总结了用于指导后续 CWE-78 扫描引擎修复与改进工作的核心上下文、环境信息、调试方法及代码规范原则。

---

## 核心上下文 (Prompt Context)

**角色**: Aida 静态分析引擎开发专家
**任务**: 提升 CWE-78 (OS Command Injection) 在 ARM64 架构下的 Juliet 测试集检出率。
**核心原则**: **Graph-First (图优先)**。所有的分析逻辑应尽可能依赖显式的图结构（节点与边），而非在分析引擎中进行字符串解析、正则匹配或硬编码的启发式推断。

### 1. 开发环境 (Environment)

- **Project Root**: `/Users/fire3/SRC/aida-mcp`
- **Python**: `/home/fire3/opt/miniconda3/bin/python` (必须使用此路径)
- **Test Suite**: `tests_cpg/CWE78/arm64` (包含 900+ `.o` 目标文件)
- **Results Dir**: `scan_results_cwe78`

### 2. 关键工具 (Toolchain)

| 脚本/工具 | 路径 | 用途 | 关键命令示例 |
| :--- | :--- | :--- | :--- |
| **回归测试** | `scripts/regression_test_cwe78.py` | 批量导出 CPG 并扫描，统计检出率 | `python scripts/regression_test_cwe78.py --filter "execl_01"` |
| **Taint调试** | `scripts/debug_taint.py` | 针对单个 CPG 追踪污点流，打印节点/边详情 | `python scripts/debug_taint.py` (需手动修改代码中的 `cpg_path`) |
| **CPG 导出** | `backend.aida_cli.cli export` | 核心导出命令 (集成在回归脚本中) | N/A |
| **规则扫描** | `backend.aida_cli.cli scan` | 核心扫描命令 (集成在回归脚本中) | N/A |

### 3. 关键代码文件 (Codebase Map)

- **`backend/aida_cli/taint_engine.py`**: **[核心]** 污点分析引擎。
    - `debug_trace(node_id)`: **[推荐]** 详细追踪指定节点的传播路径，打印每一步的决策逻辑。
    - `dump_subgraph(node_ids, path)`: **[推荐]** 导出相关子图为 JSON，用于可视化分析。
    - `_trace()`: 递归追踪污点流的主要逻辑。
- **`backend/aida_cli/rules/cwe_78.py`**: CWE-78 规则定义 (Sources, Sinks, Propagators)。
- **`backend/aida_cli/cpg_builder.py`**: 构建 Code Property Graph (CPG) 的逻辑。
    - 负责将底层指令流转换为通用的图结构 (Call, Var, Mem, PointsTo 等)。

### 4. 调试与改进方法论 (Debugging SOP)

#### 4.1 调试流程

1.  **复现问题**:
    ```bash
    /home/fire3/opt/miniconda3/bin/python scripts/regression_test_cwe78.py --filter "Specific_Case_Name" --clean
    ```
2.  **定位断点 (Trace Debugging)**:
    - 修改 `scripts/debug_taint.py`，将 `cpg_path` 指向刚刚生成的 `.cpg_json` 文件。
    - **启用详细追踪**: 使用 `engine.debug_trace(node_id)` 替代普通的 `_trace`，这将输出类似 `[DEBUG] Following POINTS_TO -> ...` 的详细日志。
    - **子图导出**: 如果路径复杂，使用 `engine.dump_subgraph([start_node, end_node], "debug_graph.json")` 导出局部图结构，使用外部工具或脚本查看连接关系。
3.  **分析原因**:
    - 检查日志中是否出现 `Max depth reached`（深度不够）。
    - 检查是否在 `POINTS_TO` 或 `DEF` 处断链。
    - 检查是否因为 `_is_propagator_output` 误判导致未追踪到输出参数。

#### 4.2 改进原则 (Graph-First Refactoring)

在修复 Bug 或增强功能时，**严禁**在 `TaintEngine` 中增加针对特定架构或命名约定的 "Trick"。

**❌ 错误做法 (Anti-Patterns)**:
- **字符串解析**: 在 Engine 中解析 `node_id` 字符串（如 `V:0x1000:fp:0`）来获取地址或寄存器信息。
- **正则匹配**: 使用正则表达式匹配 `repr` 字段（如 `x0`, `w1`）来推断参数索引。
- **模糊匹配**: 在 `_check_implicit_defs` 中通过字符串包含关系（`if var_name in expr_str`）来判断变量是否被修改。
- **硬编码**: 针对 `__imp_` 或特定编译器生成的符号进行硬编码处理。

**✅ 正确做法 (Best Practices)**:
- **图增强**: 如果 Engine 需要知道某个变量是 "第0个参数"，CPG Builder 应当在构建时就添加属性（如 `arg_index=0`）或边。
- **显式边**:
    - **参数关联**: `CallSite` 到 `Var` (实参) 应有显式的 `EDGE_ARG` 边。
    - **隐式定义**: 如果函数修改了输出参数，图上应存在 `CallSite -> Var` 的 `EDGE_DEF` (或类似语义的边)，或者 `EDGE_POINTS_TO` 关系明确。
    - **别名关系**: 指针与内存的关系应通过 `EDGE_POINTS_TO` (Var -> Mem) 显式表达。
- **通用逻辑**: Engine 只处理 `EDGE_DEF`, `EDGE_USE`, `EDGE_POINTS_TO`, `EDGE_CALL` 等通用图原语。

**具体整改示例**:
- **Trace Callers**: 目前 `_trace_callers` 依赖解析 `x0` 等字符串。应改为：在加载 CPG 时或构建时，确保函数入口节点与其参数节点有显式的连接（如 `Function -> ARG_0 -> Var`），Engine 只需遍历边。
- **Implicit Defs**: 目前 `_check_implicit_defs` 依赖字符串包含检查。应改为：在图构建阶段识别输出参数模式，并建立 `CallSite --(DEF)--> Var` 边，Engine 只需检查 `EDGE_DEF`。

### 5. 文档撰写规范

每次完成修复工作后，必须撰写总结报告至 `devdocs/taint_engine_fix_reports`。
报告中必须包含一节 **"Graph Schema Update"**，说明为了支持该修复，对 CPG 图结构做了哪些增强（新增了什么边、什么节点属性），而非仅仅展示代码变更。

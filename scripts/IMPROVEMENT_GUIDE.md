# Aida CWE-78 修复与改进工作指引 (Context Prompts)

此文档总结了用于指导后续 CWE-78 扫描引擎修复与改进工作的核心上下文、环境信息、调试方法及代码经验。你可以将以下内容作为“System Prompt”或“Context”提供给 AI 助手，以便快速进入工作状态。

---

## 核心上下文 (Prompt Context)

**角色**: Aida 静态分析引擎开发专家
**任务**: 提升 CWE-78 (OS Command Injection) 在 ARM64 架构下的 Juliet 测试集检出率。
**当前状态**: 已完成基础回归测试脚本搭建，初步修复了 taint 引擎中 propagator output 的识别问题。

### 1. 开发环境 (Environment)
- **Project Root**: `/Users/fire3/SRC/aida-mcp`
- **Python**: `/opt/anaconda3/bin/python` (必须使用此路径)
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
    - `_trace()`: 递归追踪污点流的主要逻辑。如果断链，通常需要在这里加 `print` 调试。
    - `_is_propagator_output()`: 判断函数调用是否将污点从输入参数传递到输出参数（如 `recv(socket, buf, ...)` 中的 `buf`）。**刚修复过此处逻辑。**
- **`backend/aida_cli/rules/cwe_78.py`**: CWE-78 规则定义。
    - 定义了 `SOURCES` (如 `recv`, `fgets`) 和 `SINKS` (如 `execl`, `system`)。
    - 定义了 `PROPAGATORS` (传播者)。
- **`backend/aida_cli/cpg_builder.py`**: 构建 Code Property Graph (CPG) 的逻辑。
    - 节点类型: `NODE_CALL`, `NODE_VAR`, `NODE_EXPR`, `NODE_INSTR`。
    - 边类型: `EDGE_ARG`, `EDGE_DEF`, `EDGE_USE`, `EDGE_CALL_OF`。

### 4. 调试与改进方法论 (Debugging SOP)

当遇到 **False Negative (漏报)** 时，请遵循以下步骤：

1.  **复现问题**:
    ```bash
    /opt/anaconda3/bin/python scripts/regression_test_cwe78.py --filter "Specific_Case_Name" --clean
    ```
2.  **定位断点**:
    - 修改 `scripts/debug_taint.py`，将 `cpg_path` 指向刚刚生成的 `.cpg_json` 文件。
    - 运行 `scripts/debug_taint.py`，查看 Source 是否被识别，以及 Taint Trace 在哪里中断。
    - **技巧**: 在 `taint_engine.py` 的 `_trace` 方法中取消注释 `print(f"DEBUG: _trace ...")` 以查看递归路径。
3.  **常见原因分析**:
    - **Propagator 失效**: `_is_propagator_output` 未能正确识别输出参数（例如变量名匹配失败，或表达式结构不匹配）。
    - **DEF 缺失**: 变量的定义（DEF）边未正确连接到 Instruction。
    - **别名分析缺失**: 数据通过指针或结构体字段传递，但引擎未追踪该路径。
    - **Source/Sink 缺失**: 规则文件 `cwe_78.py` 中缺少特定的 API 定义。
4.  **验证修复**:
    - 再次运行 `debug_taint.py` 确认 Trace 通路。
    - 再次运行 `regression_test_cwe78.py` 确认检出。

---

## 示例：如何向 AI 提问

如果你需要 AI 协助修复一个新的漏报案例，请使用以下模板：

> "我正在修复 CWE-78 的漏报问题。环境是 `/Users/fire3/SRC/aida-mcp`。
> 测试用例 `CWE78_..._02-bad` 未被检出。
> 我已经运行了回归脚本，生成了 CPG 在 `scan_results_cwe78/...`。
> 我使用 `debug_taint.py` 发现污点流在 `recv` 函数处中断。
> 请阅读 `backend/aida_cli/taint_engine.py`，帮我分析为什么 `recv` 的 buffer 参数没有被标记为污点源并传播？"


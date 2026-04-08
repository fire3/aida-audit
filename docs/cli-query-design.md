# AIDA-AUDIT Query CLI 设计文档

## 1. 设计目标

为了提供比原生 MCP 工具更简洁、表达能力更强的命令行查询体验，我们对 `aida-audit query` 进行了重新编排。
核心目标包括：
1. **压缩工具数量**：将 20+ 个细碎的 MCP 工具接口（如按名字查函数、按地址查函数、查被调用函数等）按“实体（Entity）”聚合成少数几个核心子命令。
2. **统一参数传递**：摒弃复杂的 JSON 字符串传参，仅支持标准的 POSIX 命令行长短参数（如 `--name`, `--address`），对人类和 LLM 都更加友好且不易出错。
3. **三重输出模式**：通过全局参数控制输出格式，支持 `json`（供 LLM 稳定解析）、`text`（使用 `rich` 库渲染终端表格/高亮文本，供人类阅读）以及 `markdown`（适合生成报告或 Markdown 格式的展示）。

---

## 2. 全局选项 (Global Options)

所有 `query` 子命令均支持以下全局选项：

| 参数 | 简写 | 说明 | 默认值 |
| :--- | :--- | :--- | :--- |
| `--project` | `-p` | 包含导出 `.db` 文件的项目目录路径 | `.` (当前目录) |
| `--format` | `-f` | 输出格式，可选值为 `json`, `text` 或 `markdown` | `text` |

**输出行为规范：**
*   **`--format json`**：严格输出 JSON 字符串，不包含任何 ANSI 颜色控制符，确保 LLM 和 `jq` 等工具可直接解析。
*   **`--format text`**：使用 Python `rich` 库，以表格、树状图、语法高亮等形式在终端美观展示数据。
*   **`--format markdown`**：输出标准的 Markdown 格式文本，包含 Markdown 表格、带有语言标签的代码块等，非常适合粘贴到文档或供偏好 Markdown 的系统解析。

---

## 3. 核心子命令编排 (Subcommands)

我们将原本零散的 MCP 工具聚合为以下 4 个核心子命令：`project`, `binary`, `function`, `symbol`。

### 3.1 `project` - 项目级信息查询
整合 `get_project_overview` 和 `get_project_binaries`。

**命令格式：**
```bash
aida-audit query project [--detail] [--limit N] [--offset N]
```
**参数说明：**
*   `--detail`: 是否拉取项目下所有二进制的扩展元数据（对应 MCP 的 `detail=True`）。
*   `--limit`, `--offset`: 分页参数，默认展示前 50 个二进制文件。

**表达能力增强：**
一次调用即可同时总览项目概况（架构、能力等）并列出关键的二进制文件清单，无需调用两次。

### 3.2 `binary` - 二进制元数据查询
对应 `get_binary_metadata`。

**命令格式：**
```bash
aida-audit query binary <binary_name>
```
**参数说明：**
*   `<binary_name>`: 必填位置参数，指定二进制文件名（如 `target.bin`）。

### 3.3 `function` - 函数多维查询（核心压缩）
将 `list_binary_functions`, `get_binary_function_by_name`, `get_binary_function_by_address`, `get_binary_function_pseudocode_by_address`, `get_binary_function_callees` 等 5+ 个工具**压缩为 1 个**表达能力极强的命令。

**命令格式：**
```bash
aida-audit query function --binary <name> [查询条件] [扩展信息开关]
```

**参数说明：**
*   **基础参数**:
    *   `--binary, -b <name>`: (必填) 目标二进制文件名。
*   **查询条件 (互斥或组合)**:
    *   *不带任何条件时，默认执行列表查询 (list)*
    *   `--name, -n <str>`: 按函数名称精确/模糊查找。
    *   `--address, -a <hex>`: 按函数十六进制地址查找（如 `0x401000`）。
    *   `--limit`, `--offset`: 列表查询时的分页参数。
*   **扩展信息开关 (按需组装)**:
    *   `--pseudocode`: 在返回的函数信息中自动附带其伪代码（内部自动调用 `get_binary_function_pseudocode_by_address`）。
    *   `--calls`: 在返回的信息中自动附带该函数的 Caller（调用者）和 Callee（被调用者）列表。

**LLM 使用场景示例：**
LLM 发现了一个可疑地址 `0x4005a0`，想要分析它的伪代码和调用关系。
过去需要 3 次工具调用：查地址得函数名 -> 查伪代码 -> 查调用关系。
现在只需要 1 次 CLI 调用：
```bash
aida-audit query function -b target.bin -a 0x4005a0 --pseudocode --calls -f json
```

### 3.4 `symbol` - 符号查询解析
将 `list_binary_symbols`, `resolve_address`, `resolve_symbol` 压缩为一个命令。

**命令格式：**
```bash
aida-audit query symbol --binary <name> [--name <str>] [--address <hex>]
```

**参数说明：**
*   `--binary, -b <name>`: (必填) 目标二进制。
*   `--name, -n <str>`: 提供符号名称进行地址解析。
*   `--address, -a <hex>`: 提供地址解析对应的符号名。
*(如果 `--name` 和 `--address` 都不提供，则默认列出所有符号列表)*

### 3.5 `audit` - 审计数据库查询 (可选支持)
整合对漏洞、任务和计划的查询。

**命令格式：**
```bash
aida-audit query audit --type <plan|task|finding> [--id <id>]
```
**参数说明：**
*   `--type, -t`: 查询的数据实体类型。
*   `--id`: 指定特定 ID 查询详情，否则返回列表。

---

## 4. 输出示例 (Output Examples)

### 4.1 JSON 模式 (`--format json`)
```json
{
  "success": true,
  "data": {
    "name": "printf",
    "address": "0x401000",
    "pseudocode": "int printf(const char *format, ...) {\n ... \n}",
    "callees": ["vprintf"]
  }
}
```

### 4.2 Text/Rich 模式 (`--format text`)
使用 `rich.table` 和 `rich.syntax` 渲染：
```text
[二进制: target.bin] 函数详情
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 属性         ┃ 值                                 ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 函数名       │ printf                             │
│ 地址         │ 0x401000                           │
│ 大小         │ 120 bytes                          │
└──────────────┴────────────────────────────────────┘

[伪代码]
  1 int printf(const char *format, ...) {
  2     return vprintf(format, args);
  3 }

[调用者 (Callers)]
- main (0x402000)
```

### 4.3 Markdown 模式 (`--format markdown`)
输出原生的 Markdown 格式代码：

```markdown
### [二进制: target.bin] 函数详情

| 属性 | 值 |
| --- | --- |
| 函数名 | printf |
| 地址 | 0x401000 |
| 大小 | 120 bytes |

#### 伪代码
```c
int printf(const char *format, ...) {
    return vprintf(format, args);
}
```

#### 调用者 (Callers)
* main (0x402000)
```

## 5. 实现路径规划

1. 在 `backend/aida_audit/` 下创建 `query_cmd.py`。
2. 使用 `argparse` 构建带子命令的 CLI 树（`project`, `binary`, `function`, `symbol`, `audit`）。
3. 解析参数后，在内部按需实例化 `McpService` 或直接调用 `ProjectStore` / `AuditDatabase` 的底层 API，组装并聚合数据。
4. 引入 `rich` 库处理 `--format text` 的终端渲染；引入 `json` 库处理 `--format json` 的格式化输出；手动组装或利用 `rich.console.Console(record=True)`/第三方库处理 `--format markdown` 的输出。
5. 将 `query_cmd.main()` 注册进 `cli.py`。
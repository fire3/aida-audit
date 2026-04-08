# AIDA-AUDIT Query CLI 设计文档

## 1. 设计目标

为了提供比原生 MCP 工具更简洁、表达能力更强的命令行查询体验，我们对 `aida-audit query` 进行了重新编排。
核心目标包括：
1. **压缩工具数量**：将 20+ 个细碎的 MCP 工具接口（如按名字查函数、按地址查函数、查被调用函数等）按“实体（Entity）”聚合成少数几个核心子命令。
2. **统一参数传递**：摒弃复杂的 JSON 字符串传参，仅支持标准的 POSIX 命令行长短参数（如 `--name`, `--address`），对人类和 LLM 都更加友好且不易出错。
3. **三重输出模式**：通过全局参数控制输出格式，支持 `json`（供 LLM 稳定解析）、`text`（使用 `rich` 库渲染终端表格/高亮文本，供人类阅读）以及 `markdown`（适合生成报告或 Markdown 格式的展示）。
4. **详尽友好的帮助文档 (`--help`)**：提供清晰的命令层次、参数说明和使用示例，方便 LLM 随时查询自身可用的能力及正确的调用方式。

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

#### 调用者 (Callers)
* main (0x402000)
```

## 5. 帮助系统 (`--help`) 设计规范

为了让 LLM 能够自我发现和纠错，`query` 命令及其所有子命令必须提供极其详细的帮助信息。

### 5.1 全局帮助 (`aida-audit query --help`)
必须清晰列出：
1. **工具定位**：说明这是用于查询二进制分析与审计数据的工具。
2. **核心概念**：简述 Project, Binary, Function, Symbol, Audit 等实体的关系。
3. **子命令列表**：带有简短但精确的说明。
4. **全局参数**：说明 `--project` 和 `--format` 的作用，特别是不同 format 的使用场景。

### 5.2 子命令帮助 (例如 `aida-audit query function --help`)
必须包含：
1. **功能描述**：说明该命令聚合了哪些底层能力（如：获取函数元数据、伪代码、调用关系）。
2. **参数分组**：利用 `argparse` 的 `add_argument_group` 将参数分类：
   - 必填参数 (Required Arguments)
   - 查询条件 (Search Criteria)
   - 扩展信息开关 (Extension Flags)
3. **使用示例 (Examples)**：提供至少 2-3 个真实的调用示例，尤其是对于 LLM 常见的组合查询场景：
   ```text
   Examples:
     # 1. 列表查询：获取目标二进制中的前 50 个函数
     aida-audit query function -b target.bin --limit 50
     
     # 2. 精确查询：按地址查询函数并同时拉取伪代码和调用关系
     aida-audit query function -b target.bin -a 0x401000 --pseudocode --calls -f json
   ```
4. **互斥说明**：明确指出哪些参数不能同时使用（例如 `--name` 和 `--address` 通常是互斥的查询条件）。

## 6. 实现路径规划与开发指导

为了确保代码结构清晰、可维护，并严格对齐本设计文档，开发需遵循以下详细步骤与技术选型：

### 6.1 目录与模块结构划分
在 `backend/aida_audit/` 目录下新增以下结构，避免单文件代码过长：
*   `query_cmd.py`: CLI 的主入口文件，负责 `argparse` 的根解析和子命令路由。
*   `query/`: 新建目录，用于存放不同实体的查询处理逻辑。
    *   `__init__.py`
    *   `project_handler.py`: 处理 `project` 子命令。
    *   `binary_handler.py`: 处理 `binary` 子命令。
    *   `function_handler.py`: 处理 `function` 子命令（核心逻辑最重的地方）。
    *   `symbol_handler.py`: 处理 `symbol` 子命令。
    *   `audit_handler.py`: 处理 `audit` 子命令。
    *   `formatter.py`: 统一负责 `json`, `text`, `markdown` 三种格式的输出渲染逻辑。

### 6.2 核心依赖与初始化机制
1.  **数据源直接调用**：不要通过 HTTP 或启动 MCP Server 进程，而是直接在当前进程实例化 `ProjectStore` 和 `AuditDatabase`，直接调用其底层的 Python API 抓取数据。这与 `McpService` 内部调用的接口是同一套。
2.  **统一上下文上下文**：在 `query_cmd.py` 解析出全局参数 `--project` 后，初始化 `ProjectStore` 实例，并将其作为上下文传递给各个 `handler`。

### 6.3 `argparse` 构建规范
1.  **使用 `argparse.RawTextHelpFormatter`**：确保 `description` 和 `epilog` 中的换行和缩进（特别是 Examples 部分）能够被原样输出，不会被自动折叠。
2.  **严格使用 `add_argument_group`**：在各个子命令中，必须明确划分参数组。例如在 `function_handler` 中：
    ```python
    required_group = parser.add_argument_group('Required Arguments')
    search_group = parser.add_argument_group('Search Criteria (Mutex)')
    ext_group = parser.add_argument_group('Extension Flags')
    ```
3.  **互斥组校验**：对于 `function` 和 `symbol`，利用 `parser.add_mutually_exclusive_group()` 强制校验 `--name` 和 `--address` 只能二选一。

### 6.4 格式化输出 (Formatter) 架构
新建一个 `OutputFormatter` 类，接收结构化的 Python 字典/列表数据，并根据 `--format` 参数派发到具体渲染函数：
*   **JSON 渲染**：直接使用标准库 `json.dumps(data, indent=2)` 打印，不要附加任何额外的前缀/后缀。
*   **Text/Rich 渲染**：
    *   必须使用 `rich.console.Console()` 进行输出。
    *   对于列表数据（如函数列表），使用 `rich.table.Table`。
    *   对于包含代码块的数据（如伪代码），使用 `rich.syntax.Syntax` 实现 C 语言高亮。
*   **Markdown 渲染**：
    *   **不要**试图用 `rich` 来生成纯 Markdown 文本。
    *   使用纯 Python 字符串拼接：手动构造 `| Column | Value |` 的表格结构和 ````c ```` 的代码块结构，然后通过普通 `print()` 输出，确保没有任何 ANSI 颜色转义字符污染输出结果。

### 6.5 主入口集成
最后，在现有的 `backend/aida_audit/cli.py` 中：
1.  导入 `query_cmd`。
2.  在主命令分发逻辑中增加 `elif command == "query": query_cmd.main()`。
3.  更新 `cli.py` 的全局 Help 信息，增加对 `query` 命令的简要说明。
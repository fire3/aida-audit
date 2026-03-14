# AIDA-AUDIT

AIDA-AUDIT 是一个强大的工具，旨在连接 IDA Pro 二进制分析与现代 AI 辅助工作流。它提供了一种无缝的方式从 IDA Pro 导出分析数据，并通过丰富的 Web UI 或 Model Context Protocol (MCP) 进行程序化探索。

## 功能特性

*   **导出 (Export)**: 自动化运行 IDA Pro 或 Ghidra，将二进制元数据（函数、字符串、导入导出表、伪代码等）提取到可移植的 SQLite 数据库中。自动初始化工作区并配置 MCP 客户端。
*   **Web 界面 (Web UI)**: 一个现代化的交互式 Web 界面，用于浏览和分析导出的数据。
*   **MCP 服务器 (MCP Server)**: 完全兼容 Model Context Protocol 的服务器，允许 AI 助手查询和理解二进制结构。
*   **智能体自动审计**: 一个由 LLM 驱动的智能体系统，可自动规划、执行和验证二进制安全审计，并提供实时反馈和详细报告。
*   **REST API**: 基于 FastAPI 的后端，支持自定义集成。

## 安装指南

### 环境要求

*   **Python 3.9+**
*   **IDA Pro**: 使用 IDA 后端导出时需要。
*   **Ghidra**: 使用 Ghidra 后端导出时需要安装。
*   **JDK**: Ghidra 运行所需（若使用官方包内置 JDK 可跳过单独安装）。
*   **Node.js**: 仅当你计划从源码构建前端时需要（可选）。

### 安装 IDA Pro lib（必须）

为了使 `aida-audit export` 命令正常工作（使用 IDA 后端时），你需要安装 IDA Pro 的 Python 库。

1.  确保 IDA Pro 已安装并配置好相关环境。
2.  进入 IDA Pro 安装目录（比如 C:\Program Files\IDA Professional 9.2\ ）下的 `idalib/python` 子目录。
3.  该目录下有一个idapro目录，两个py文件，分别是setup.py和py-activate-lidalib.py文件。
4.  在该目录下，执行python命令：
    ```bash
    pip install .
    ```
5.  安装完成后，执行 `python py-activate-lidalib.py` 文件，激活 IDA Pro 的 Python 库。

### 安装 Node.js (可选)
如果计划从源码构建安装aida-audit，需要安装 Node.js。

1.  下载并安装 Node.js 最新版本。
2.  验证安装：
    ```bash
    node -v
    npm -v
    ```

### 安装 Ghidra 与 JDK（使用 Ghidra 后端时必须）

1.  安装 JDK（如果你的 Ghidra 发行包没有内置 JDK）。
2.  下载并解压 Ghidra。
3.  配置环境变量 `GHIDRA_HOME` 指向 Ghidra 根目录（包含 `support/analyzeHeadless(.bat)`）。
4.  验证路径：
    ```bash
    # Windows
    %GHIDRA_HOME%\support\analyzeHeadless.bat
    # Linux/macOS
    $GHIDRA_HOME/support/analyzeHeadless
    ```

### 源码构建与安装

我们提供了一个 PowerShell 脚本，可以自动构建前端、打包后端并安装到你的 Python 环境中。

1.  进入 `backend` 目录：
    ```powershell
    cd backend
    ```
2.  Windows 可以运行构建安装脚本：
    ```powershell
    .\build_and_install.ps1
    ```
    Linux/MacOS 可以运行构建安装脚本：
    ```bash
    ./build_and_install.sh
    ```

该脚本会自动执行以下操作：
*   构建前端项目。
*   将前端资源复制到后端包中。
*   将内置 skill 复制到后端包中。
*   构建 Python wheel 包。
*   使用 `pip` 安装 `aida-audit`。

### PIP 安装

如果你只需要后端，或者想直接安装预编译的 wheel 包：

```bash
pip install aida-audit
```

## 使用说明

安装完成后，你可以在终端直接使用 `aida-audit` 命令。

### 1. 导出分析数据 (`export`)

`export` 命令会启动一个无界面的 IDA Pro 或 Ghidra 实例来分析二进制文件并保存结果。该命令会自动在输出目录中初始化工作区并配置 MCP 客户端。

```bash
aida-audit export <target_binary> -o <output_directory>
```

**参数说明：**
*   `<target_binary>`: 目标二进制文件路径（如 `.exe`, `.so`, 固件组件等）。
*   `-o, --out-dir`: 结果输出目录，用于保存 SQLite 数据库 (`.db`) 和其他文件。

**高级选项：**
*   `-s, --scan-dir <dir>`: **批量模式**。递归扫描指定目录以解析依赖关系（在分析固件文件系统时非常有用）。
*   `-j <n>`: 并行工作线程数（默认：4）。
*   `--backend <ida|ghidra>`: 选择导出后端（默认：`ida`）。
*   `--verbose`: 启用详细日志输出。
*   `--log-file <path>`: 将日志写入文件。
*   使用 `--backend ghidra` 时，请先在环境中设置 `GHIDRA_HOME`。

**工作区初始化：**
export 命令会在输出目录中自动创建以下文件：
*   `opencode.json`: OpenCode 项目配置（包含 MCP 服务器）。
*   `.mcp.json`: MCP 客户端配置。
*   `.trae/mcp.json`: Trae 客户端 MCP 配置。
*   `.claude/settings.local.json`: Claude 桌面版设置。
*   `.opencode/skills/`: OpenCode 兼容 skills（如果有）。

**示例：**
```bash
# 分析单个二进制文件
aida-audit export ./bin/httpd -o ./output

# 分析固件根目录下的二进制文件，并解析依赖
aida-audit export ./squashfs-root/usr/sbin/httpd -o ./output --scan-dir ./squashfs-root

# 使用 Ghidra 后端导出（使用环境变量）
aida-audit export ./bin/httpd -o ./output --backend ghidra

# 使用通配符导出多个目标
aida-audit export ./lib/uams/uams_* -o ./output
```

### 2. 启动服务 (`serve`)

`serve` 命令会同时启动 Web UI 和 MCP 服务器。

```bash
aida-audit serve [project_path]
```

**参数说明：**
*   `[project_path]`: 包含导出 `.db` 文件的目录路径。默认为当前目录 (`.`)。

**选项：**
*   `--host`: 绑定主机地址 (默认: `127.0.0.1`)。
*   `--port`: 端口号 (默认: `8765`)。

**访问界面：**
服务启动后，打开浏览器访问：
**http://localhost:8765**

**MCP服务器地址:**
**http://localhost:8765/mcp**

## 智能体自动审计 (Automated Code Audit)

AIDA-AUDIT 内置了一套先进的智能体系统，旨在自动化安全审计流程。该系统利用大语言模型 (LLM) 和模型上下文协议 (MCP) 对二进制文件进行深度分析。

### 核心能力

*   **智能规划**: `PlanAgent` 分析目标二进制文件的结构，并根据代码的具体特征制定全面、高层次的审计计划。
*   **自主执行**: `AuditAgent` 通过将计划分解为具体任务来执行审计。它利用丰富的工具集来探索代码、分析控制流并识别潜在漏洞。
*   **验证与确认**: 专门的 `VerificationAgent` 会审查发现的漏洞，以最大限度地减少误报并确保报告的准确性。
*   **实时仪表盘**: 通过 Web UI 的“实时 (Live)”标签页，实时监控智能体的思考过程、工具使用情况和发现结果。
*   **循环检测**: 先进的循环检测机制防止智能体陷入重复分析的死循环。
*   **双语报告**: 支持生成中文和英文的报告及漏洞发现。

### 工作原理

1.  **初始化**: 启动审计会话时，系统会初始化智能体并从导出的数据库中加载必要的上下文。
2.  **规划阶段**: 规划智能体 (PlanAgent) 概览二进制文件的函数、字符串和导入表，以制定审计策略。
3.  **审计循环**: 审计智能体 (AuditAgent) 从计划中领取任务，使用工具（如 `audit_report_finding`, `audit_create_note`）记录工作内容，并更新任务状态。
4.  **完成**: 所有任务完成后或用户停止会话时，系统将生成最终报告。

## 开发指南

### 目录结构
*   `backend/`: Python 源代码（FastAPI、IDA 脚本、MCP 实现）。
*   `frontend/`: React/TypeScript 前端源代码。
*   `devdocs/`: 设计文档和 API 规范。

### 开发模式运行
1.  **后端**: `cd backend && uvicorn aida-audit.server_cmd:app --reload`
2.  **前端**: `cd frontend && npm run dev`
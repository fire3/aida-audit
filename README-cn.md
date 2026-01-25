# AIDA-MCP

AIDA-MCP 是一个强大的工具，旨在连接 IDA Pro 二进制分析与现代 AI 辅助工作流。它提供了一种无缝的方式从 IDA Pro 导出分析数据，并通过丰富的 Web UI 或 Model Context Protocol (MCP) 进行程序化探索。

## 功能特性

*   **导出 (Export)**: 自动化运行 IDA Pro，将二进制元数据（函数、字符串、导入导出表、伪代码等）提取到可移植的 SQLite 数据库中。
*   **Web 界面 (Web UI)**: 一个现代化的交互式 Web 界面，用于浏览和分析导出的数据。
*   **MCP 服务器 (MCP Server)**: 完全兼容 Model Context Protocol 的服务器，允许 AI 助手（如 Claude, Trae 等）查询和理解二进制结构。
*   **REST API**: 基于 FastAPI 的后端，支持自定义集成。

## 安装指南

### 环境要求

*   **Python 3.9+**
*   **IDA Pro**: `aida-mcp export` 命令需要依赖 IDA Pro 环境来运行分析。
*   **Ghidra**: 使用 Ghidra 后端导出时需要安装。
*   **JDK**: Ghidra 运行所需（若使用官方包内置 JDK 可跳过单独安装）。
*   **Node.js**: 仅当你计划从源码构建前端时需要（可选）。

### 安装 IDA Pro lib（必须）

为了使 `aida-mcp export` 命令正常工作，你需要安装 IDA Pro 的 Python 库。

1.  确保 IDA Pro 已安装并配置好相关环境。
2.  进入 IDA Pro 安装目录（比如 C:\Program Files\IDA Professional 9.2\ ）下的 `idalib/python` 子目录。
3.  该目录下有一个idapro目录，两个py文件，分别是setup.py和py-activate-lidalib.py文件。
4.  在该目录下，执行python命令：
    ```bash
    pip install .
    ```
5.  安装完成后，执行 `python py-activate-lidalib.py` 文件，激活 IDA Pro 的 Python 库。

### 安装 Node.js (可选)
如果计划从源码构建安装aida-mcp，需要安装 Node.js。

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
*   构建 Python wheel 包。
*   使用 `pip` 安装 `aida-mcp`。

### PIP 安装

如果你只需要后端，或者想直接安装预编译的 wheel 包：

```bash
pip install aida-mcp
```

## 使用说明

安装完成后，你可以在终端直接使用 `aida-mcp` 命令。

### 1. 导出分析数据 (`export`)

`export` 命令会启动一个无界面的 IDA Pro 实例来分析二进制文件并保存结果。

```bash
aida-mcp export <target_binary> -o <output_directory>
```

**参数说明：**
*   `<target_binary>`: 目标二进制文件路径（如 `.exe`, `.so`, 固件组件等）。
*   `-o, --out-dir`: 结果输出目录，用于保存 SQLite 数据库 (`.db`) 和其他文件。

**高级选项：**
*   `-s, --scan-dir <dir>`: **批量模式**。递归扫描指定目录以解析依赖关系（在分析固件文件系统时非常有用）。
*   `-j <n>`: 并行工作线程数（默认：4）。
*   `--verbose`: 启用详细日志输出。
*   `--backend <ida|ghidra>`: 选择导出后端（默认：`ida`）。
*   `--ghidra-home <dir>`: Ghidra 安装目录（可选，优先级高于 `GHIDRA_HOME`）。
*   `--export-c`: 同时导出反编译的 C 文件。

**示例：**
```bash
# 分析单个二进制文件
aida-mcp export ./bin/httpd -o ./output

# 分析固件根目录下的二进制文件，并解析依赖
aida-mcp export ./squashfs-root/usr/sbin/httpd -o ./output --scan-dir ./squashfs-root

# 使用 Ghidra 后端导出（使用环境变量）
aida-mcp export ./bin/httpd -o ./output --backend ghidra

# 使用 Ghidra 后端导出（显式指定 Ghidra 目录）
aida-mcp export ./bin/httpd -o ./output --backend ghidra --ghidra-home <path_to_ghidra>

# 导出反编译 C 文件
aida-mcp export ./bin/httpd -o ./output --export-c

# 使用通配符导出多个目标
aida-mcp export ./lib/uams/uams_* -o ./output
```

### 2. 启动服务 (`serve`)

`serve` 命令会同时启动 Web UI 和 MCP 服务器。

```bash
aida-mcp serve [project_path]
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

### 3. 安装 MCP 配置 (`install`)

`install` 命令用于生成或更新各种 MCP 客户端（如 OpenCode, Claude Code, Trae）的配置文件。

```bash
aida-mcp install --client <client_name>
```

**选项：**
*   `--client`: 要配置的 MCP 客户端。支持的值：`opencode`, `claude-code`, `trae`, `cline`, `roo-code`。可以指定多个客户端（例如 `--client opencode --client trae`）。
*   `--transport`: 传输模式。可选值：`stdio` (默认), `http`。
    *   `stdio`: 启动本地 Python 进程。
    *   `http`: 连接到正在运行的服务器（需要先运行 `aida-mcp serve`）。
*   `--url`: HTTP 传输的 URL (默认: `http://127.0.0.1:8765/mcp`)。
*   `--output`: 输出路径。
    *   `auto` (默认): 尝试定位客户端的配置文件并合并配置。
    *   `-`: 打印到标准输出 (stdout)。
    *   `<path>`: 写入指定的文件或目录。

**示例：**
```bash
# 为 OpenCode 安装配置 (stdio 模式)
aida-mcp install --client opencode

# 为 Claude Code 安装配置 (使用 HTTP 传输)
aida-mcp install --client claude-code --transport http

# 将配置打印到标准输出
aida-mcp install --client trae --output -
```

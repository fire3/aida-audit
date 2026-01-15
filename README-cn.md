# AIDA-MCP

AIDA-MCP 是一个强大的工具，旨在连接 IDA Pro 二进制分析与现代 AI 辅助工作流。它提供了一种无缝的方式从 IDA Pro 导出分析数据，并通过丰富的 Web UI 或 Model Context Protocol (MCP) 进行程序化探索。

## 功能特性

*   **导出 (Export)**: 自动化运行 IDA Pro，将二进制元数据（函数、字符串、导入导出表、伪代码等）提取到可移植的 SQLite 数据库中。
*   **Web 界面 (Web UI)**: 一个现代化的交互式 Web 界面，用于浏览和分析导出的数据。
*   **MCP 服务器 (MCP Server)**: 完全兼容 Model Context Protocol 的服务器，允许 AI 助手（如 Claude, Trae 等）查询和理解二进制结构。
*   **REST API**: 基于 FastAPI 的后端，支持自定义集成。

## 安装指南

### 环境要求

*   **Python 3.8+**
*   **IDA Pro**: `export` 命令需要依赖 IDA Pro 环境来运行分析。
*   **Node.js**: 仅当你计划从源码构建前端时需要（可选）。

### 自动构建与安装（推荐）

我们提供了一个 PowerShell 脚本，可以自动构建前端、打包后端并安装到你的 Python 环境中。

1.  进入 `backend` 目录：
    ```powershell
    cd backend
    ```
2.  运行构建安装脚本：
    ```powershell
    .\build_and_install.ps1
    ```

该脚本会自动执行以下操作：
*   构建 React 前端项目。
*   将前端资源复制到后端包中。
*   构建 Python wheel 包。
*   使用 `pip` 安装 `aida-mcp`。

### 手动安装

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
*   `--scan-dir <dir>`: **批量模式**。递归扫描指定目录以解析依赖关系（在分析固件文件系统时非常有用）。
*   `-j <n>`: 并行工作线程数（默认：4）。
*   `--verbose`: 启用详细日志输出。

**示例：**
```bash
# 分析单个二进制文件
aida-mcp export ./bin/httpd -o ./output

# 分析固件根目录下的二进制文件，并解析依赖
aida-mcp export ./squashfs-root/usr/sbin/httpd -o ./output --scan-dir ./squashfs-root
```

### 2. 启动服务 (`serve`)

`serve` 命令会同时启动 Web UI 和 MCP 服务器。

```bash
aida-mcp serve [project_path]
```

**参数说明：**
*   `[project_path]`: （可选）包含导出 `.db` 文件或 `export_index.json` 的目录路径。默认为当前目录 (`.`)。

**选项：**
*   `--host`: 绑定主机地址 (默认: `127.0.0.1`)。
*   `--port`: 端口号 (默认: `8765`)。

**访问界面：**
服务启动后，打开浏览器访问：
**http://localhost:8765**

## 开发说明

### 目录结构
*   `backend/`: Python 源代码 (FastAPI, IDA 脚本, MCP 实现)。
*   `frontend/`: 用于 Web UI 的 React/TypeScript 源代码。
*   `devdocs/`: 设计文档和 API 规范。

### 开发模式运行
1.  **后端**: `cd backend && uvicorn aida_mcp.server_cmd:app --reload`
2.  **前端**: `cd frontend && npm run dev`

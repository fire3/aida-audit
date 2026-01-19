# AIDA-MCP Help

AIDA-MCP 是一个强大的工具，旨在连接 IDA Pro 二进制分析与现代 AI 辅助工作流。它提供了一种无缝的方式从 IDA Pro 导出分析数据，并通过丰富的 Web UI 或 Model Context Protocol (MCP) 进行程序化探索。

## 使用指南

### 1. 导出分析数据 (Export)

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

**示例：**
```bash
# 分析单个二进制文件
aida-mcp export ./bin/httpd -o ./output

# 分析固件根目录下的二进制文件，并解析依赖
aida-mcp export ./squashfs-root/usr/sbin/httpd -o ./output --scan-dir ./squashfs-root
```

### 2. 启动服务 (Serve)

`serve` 命令会同时启动 Web UI 和 MCP 服务器。

```bash
aida-mcp serve [project_path]
```

**参数说明：**
*   `[project_path]`: 包含导出 `.db` 文件或 `export_index.json` 的目录路径。默认为当前目录 (`.`)。

**选项：**
*   `--host`: 绑定主机地址 (默认: `127.0.0.1`)。
*   `--port`: 端口号 (默认: `8765`)。

### 3. MCP 客户端配置

要让 Claude 等 AI 助手使用此工具，请配置 `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ida-mcp": {
      "command": "python",
      "args": [
        "-m", 
        "ida_project_mcp.mcp_stdio_server", 
        "--project", 
        "C:/path/to/your/project"
      ]
    }
  }
}
```

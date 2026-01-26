# AIDA-CLI Help

AIDA-CLI is a powerful tool designed to bridge IDA Pro binary analysis with modern AI-assisted workflows. It provides a seamless way to export analysis data from IDA Pro and explore it programmatically via a rich Web UI or the Model Context Protocol (MCP).

## User Guide

### 1. Export Analysis Data (Export)

The `export` command launches a headless IDA Pro instance to analyze the binary and save the results.

```bash
aida-cli export <target_binary> -o <output_directory>
```

**Arguments:**
*   `<target_binary>`: Path to the target binary (e.g., `.exe`, `.so`, firmware components).
*   `-o, --out-dir`: Output directory for saving the SQLite database (`.db`) and other files.

**Advanced Options:**
*   `-s, --scan-dir <dir>`: **Batch Mode**. Recursively scans the specified directory to resolve dependencies (useful when analyzing firmware filesystems).
*   `-j <n>`: Number of parallel worker threads (default: 4).
*   `--verbose`: Enable verbose logging output.
*   `--export-c`: Export the decompiled C file alongside the database.

**Examples:**
```bash
# Analyze a single binary
aida-cli export ./bin/httpd -o ./output

# Analyze a binary within a firmware root and resolve dependencies
aida-cli export ./squashfs-root/usr/sbin/httpd -o ./output --scan-dir ./squashfs-root

# Export decompiled C output
aida-cli export ./bin/httpd -o ./output --export-c

# Export multiple targets via wildcard
aida-cli export ./lib/uams/uams_* -o ./output
```

### 2. Start Service (Serve)

The `serve` command starts both the Web UI and the MCP Server.

```bash
aida-cli serve [project_path]
```

**Arguments:**
*   `[project_path]`: Directory path containing the exported `.db` files. Defaults to the current directory (`.`).

**Options:**
*   `--host`: Bind host address (default: `127.0.0.1`).
*   `--port`: Port number (default: `8765`).

### 3. MCP Client Configuration

Configure OpenCode by adding an MCP server entry to your `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "aida-cli": {
      "type": "remote",
      "url": "http://localhost:8765/mcp",
      "enabled": true
    }
  }
}
```

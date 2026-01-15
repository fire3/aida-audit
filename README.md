# AIDA-MCP

AIDA-MCP is a powerful tool designed to bridge the gap between IDA Pro binary analysis and modern AI-assisted workflows. It provides a seamless way to export analysis data from IDA Pro and explore it through a rich Web UI or programmatically via the Model Context Protocol (MCP).

## Features

*   **Export**: Automated extraction of binary metadata (functions, strings, imports, exports, pseudocode, etc.) from IDA Pro into portable SQLite databases.
*   **Web UI**: A modern, interactive web interface to browse and analyze the exported data.
*   **MCP Server**: A fully compliant Model Context Protocol server that allows AI assistants (like Claude, Trae, etc.) to query and reason about the binary structure.
*   **REST API**: A FastAPI-backed backend for custom integrations.

## Installation

### Prerequisites

*   **Python 3.8+**
*   **IDA Pro**: Required for the `export` command (to run the analysis).
*   **Node.js**: Required only if you plan to build the frontend from source (optional).

### Automatic Build & Install (Recommended)

We provide a PowerShell script that builds the frontend, packages the backend, and installs the tool into your Python environment.

1.  Navigate to the `backend` directory:
    ```powershell
    cd backend
    ```
2.  Run the build and install script:
    ```powershell
    .\build_and_install.ps1
    ```

This script will:
*   Build the React frontend.
*   Copy the frontend assets to the backend package.
*   Build the Python wheel.
*   Install `aida-mcp` using `pip`.

### Manual Installation

If you only need the backend or want to install from a pre-built wheel:

```bash
pip install aida-mcp
```

## Usage

Once installed, the `aida-mcp` command is available in your terminal.

### 1. Export Analysis Data (`export`)

The `export` command runs a headless IDA Pro instance to analyze a binary and save the results.

```bash
aida-mcp export <target_binary> -o <output_directory>
```

**Arguments:**
*   `<target_binary>`: Path to the binary file (e.g., `.exe`, `.so`, firmware component).
*   `-o, --out-dir`: Directory where the SQLite database (`.db`) and other artifacts will be saved.

**Advanced Options:**
*   `--scan-dir <dir>`: **Bulk Mode**. Recursively scans the specified directory for dependencies (useful for analyzing firmware file systems).
*   `-j <n>`: Number of parallel workers (default: 4).
*   `--verbose`: Enable detailed logging.

**Example:**
```bash
# Analyze a single binary
aida-mcp export ./bin/httpd -o ./output

# Analyze a binary within a firmware root, resolving dependencies
aida-mcp export ./squashfs-root/usr/sbin/httpd -o ./output --scan-dir ./squashfs-root
```

### 2. Start the Server (`serve`)

The `serve` command launches the Web UI and the MCP server.

```bash
aida-mcp serve [project_path]
```

**Arguments:**
*   `[project_path]`: (Optional) Path to the directory containing your exported `.db` files or `export_index.json`. Defaults to the current directory (`.`).

**Options:**
*   `--host`: Host address to bind to (default: `127.0.0.1`).
*   `--port`: Port number (default: `8765`).

**Accessing the UI:**
Once the server is running, open your browser and navigate to:
**http://localhost:8765**

## Development

### Directory Structure
*   `backend/`: Python source code (FastAPI, IDA scripts, MCP implementation).
*   `frontend/`: React/TypeScript source code for the Web UI.
*   `devdocs/`: Design documentation and API specifications.

### Running in Development Mode
1.  **Backend**: `cd backend && uvicorn aida_mcp.server_cmd:app --reload`
2.  **Frontend**: `cd frontend && npm run dev`

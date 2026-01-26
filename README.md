# AIDA-MCP

AIDA-MCP is a powerful tool designed to bridge the gap between IDA Pro binary analysis and modern AI-assisted workflows. It provides a seamless way to export analysis data from IDA Pro and explore it through a rich Web UI or programmatically via the Model Context Protocol (MCP).

## Features

*   **Export**: Automated extraction of binary metadata (functions, strings, imports, exports, pseudocode, etc.) from IDA Pro into portable SQLite databases.
*   **Web UI**: A modern, interactive web interface to browse and analyze the exported data.
*   **MCP Server**: A fully compliant Model Context Protocol server that allows AI assistants (like Claude, Trae, etc.) to query and reason about the binary structure.
*   **REST API**: A FastAPI-backed backend for custom integrations.

## Installation

### Prerequisites

*   **Python 3.9+**
*   **IDA Pro**: Required for the `aida-mcp export` command (to run the analysis).
*   **Ghidra**: Required when exporting with the Ghidra backend.
*   **JDK**: Required for running Ghidra (skip if your Ghidra bundle includes a JDK).
*   **Node.js**: Required only if you plan to build the frontend from source (optional).

### Install IDA Pro lib (Required)

To make the `aida-mcp export` command work properly, you need to install the IDA Pro Python library.

1.  Ensure IDA Pro is installed and the environment is configured.
2.  Navigate to the `idalib/python` subdirectory under your IDA Pro installation directory (e.g., `C:\Program Files\IDA Professional 9.2\`).
3.  In this directory, you should find an `idapro` folder, along with `setup.py` and `py-activate-lidalib.py` files.
4.  Run the following command in this directory:
    ```bash
    pip install .
    ```
5.  After installation, run `python py-activate-lidalib.py` to activate the IDA Pro Python library.

### Install Node.js (Optional)

If you plan to build and install `aida-mcp` from source, you need to install Node.js.

1.  Download and install the latest version of Node.js.
2.  Verify the installation:
    ```bash
    node -v
    npm -v
    ```

### Install Ghidra and JDK (Required for the Ghidra backend)

1.  Install a JDK (if your Ghidra bundle does not include one).
2.  Download and extract Ghidra.
3.  Set `GHIDRA_HOME` to the Ghidra root directory (it must contain `support/analyzeHeadless(.bat)`).
4.  Verify the path:
    ```bash
    # Windows
    %GHIDRA_HOME%\support\analyzeHeadless.bat
    # Linux/macOS
    $GHIDRA_HOME/support/analyzeHeadless
    ```

### Source Build & Install

We provide scripts to automatically build the frontend, package the backend, and install the tool into your Python environment.

1.  Navigate to the `backend` directory:
    ```powershell
    cd backend
    ```
2.  For Windows, run the build and install script:
    ```powershell
    .\build_and_install.ps1
    ```
    For Linux/MacOS, run the build and install script:
    ```bash
    ./build_and_install.sh
    ```

This script will automatically:
*   Build the React frontend.
*   Copy the frontend assets to the backend package.
*   Copy the built-in skills into the backend package.
*   Build the Python wheel.
*   Install `aida-mcp` using `pip`.

### PIP Installation

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
*   `<target_binary>`: Path to the target binary file (e.g., `.exe`, `.so`, firmware component).
*   `-o, --out-dir`: Directory where the SQLite database (`.db`) and other artifacts will be saved.

**Advanced Options:**
*   `-s, --scan-dir <dir>`: **Bulk Mode**. Recursively scans the specified directory for dependencies (useful for analyzing firmware file systems).
*   `-j <n>`: Number of parallel workers (default: 4).
*   `--verbose`: Enable detailed logging.
*   `--backend <ida|ghidra>`: Choose the export backend (default: `ida`).
*   `--ghidra-home <dir>`: Ghidra install directory (optional, overrides `GHIDRA_HOME`).
*   `--export-c`: Export the decompiled C file alongside the database.

**Example:**
```bash
# Analyze a single binary
aida-mcp export ./bin/httpd -o ./output

# Analyze a binary within a firmware root, resolving dependencies
aida-mcp export ./squashfs-root/usr/sbin/httpd -o ./output --scan-dir ./squashfs-root

# Export with the Ghidra backend (using GHIDRA_HOME)
aida-mcp export ./bin/httpd -o ./output --backend ghidra

# Export with the Ghidra backend (explicit path)
aida-mcp export ./bin/httpd -o ./output --backend ghidra --ghidra-home <path_to_ghidra>

# Export decompiled C output
aida-mcp export ./bin/httpd -o ./output --export-c

# Export multiple targets via wildcard
aida-mcp export ./lib/uams/uams_* -o ./output
```

### 2. Start the Server (`serve`)

The `serve` command launches the Web UI and the MCP server.

```bash
aida-mcp serve [project_path]
```

**Arguments:**
*   `[project_path]`: Path to the directory containing exported `.db` files. Defaults to the current directory (`.`).

**Options:**
*   `--host`: Host address to bind to (default: `127.0.0.1`).
*   `--port`: Port number (default: `8765`).

**Accessing the UI:**
Once the server is running, open your browser and navigate to:
**http://localhost:8765**

**MCP Server Address:**
**http://localhost:8765/mcp**

### 3. Install MCP Configuration (`install`)

The `install` command generates or updates the configuration file for various MCP clients (e.g., OpenCode, Claude Code, Trae). The `config` command is an alias.

```bash
aida-mcp install --client <client_name>
```

**Options:**
*   `--client`: The MCP client to configure. Supported values: `opencode`, `claude-code`, `trae`, `cline`, `roo-code`. You can specify multiple clients (e.g., `--client opencode --client trae`).
*   `--transport`: The transport mode. Choices: `stdio` (default), `http`.
    *   `stdio`: Starts a local python process.
    *   `http`: Connects to a running server (requires `aida-mcp serve` to be running).
*   `--url`: The URL for the HTTP transport (default: `http://127.0.0.1:8765/mcp`).
*   `--output`: Output path.
    *   `auto` (default): Tries to locate the client's configuration file and merge the config.
    *   `-`: Print to stdout.
    *   `<path>`: Write to a specific file or directory.

**Examples:**
```bash
# Install for OpenCode (stdio mode)
aida-mcp install --client opencode

# Install for Claude Code using HTTP transport
aida-mcp install --client claude-code --transport http

# Print configuration to stdout
aida-mcp install --client trae --output -
```

### 4. Initialize Workspace (`workspace`)

The `workspace` command creates a local workspace directory with MCP client configs and skills.

```bash
aida-mcp workspace --init <workspace_dir>
```

**What it creates:**
*   `<workspace_dir>/project/`: Place your exported `.db` files here.
*   `<workspace_dir>/skills/`: Built-in skills copied from the package.
*   `<workspace_dir>/mcp_<client>.json`: Client configs for the selected clients.

**Options:**
*   `--client`: Target clients (default: opencode, roo-code, trae, claude-code, cline).
*   `--transport`: `stdio` (default) or `http`.
*   `--url`: MCP server URL when using `http`.

## Development

### Directory Structure
*   `backend/`: Python source code (FastAPI, IDA scripts, MCP implementation).
*   `frontend/`: React/TypeScript source code for the Web UI.
*   `devdocs/`: Design documentation and API specifications.

### Running in Development Mode
1.  **Backend**: `cd backend && uvicorn aida_mcp.server_cmd:app --reload`
2.  **Frontend**: `cd frontend && npm run dev`

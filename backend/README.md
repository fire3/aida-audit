# AIDA MCP Backend

This is the backend tool for AIDA MCP. It provides functionality to export IDA Pro databases and serve them via MCP (Model Context Protocol).

## Features

- **Export**: Analyze binaries using IDA Pro and export metadata to a local SQLite database.
- **Serve**: Serve the exported project data via an MCP-compliant HTTP server.

## Installation

### Prerequisites

- Python 3.8+
- IDA Pro (for export functionality)
- Valid IDA Python environment (for export)

### Install from Source

1. Navigate to the `backend` directory.
2. Run the following command:

   ```bash
   pip install .
   ```

### Install from Wheel (if packaged)

You can use the provided build scripts to automatically build and install the package:

**Windows (PowerShell):**
```powershell
./build_and_install.ps1
```

**Windows (CMD):**
```batch
build_and_install.bat
```

Or manually:

1. Build the package:
   ```bash
   python -m build
   ```
2. Install the generated wheel:
   ```bash
   pip install dist/aida_mcp-0.1.0-py3-none-any.whl
   ```

## Development (No Install)

Use this section when you want to run and test the backend directly from source without installing a wheel.

1. Open a terminal and go to the `backend` directory:
   ```bash
   cd backend
   ```
2. Run commands directly with Python module execution:
   ```bash
   python -m aida_mcp.cli export <path_to_binary> -o <output_directory>
   python -m aida_mcp.cli serve [path_to_project_or_db]
   ```
3. If you want to use Ghidra for export, set `GHIDRA_HOME` or pass `--ghidra-home`:
   ```bash
   python -m aida_mcp.cli export <path_to_binary> -o <output_directory> --backend ghidra --ghidra-home <path_to_ghidra>
   ```
4. If you want to use IDA for export, ensure your Python environment can import IDA's Python API as noted below in the Export Command section.

## Usage

After installation, the `aida-mcp` command will be available in your Python scripts directory.

### Export Command

Analyzes a binary and exports it to a database in the output directory.

```bash
aida-mcp export <path_to_binary> -o <output_directory>
```

Options:
- `--scan-dir <dir>`: Enable bulk mode to scan for dependencies in the given directory.
- `-j <workers>`: Number of parallel workers (default: 4).
- `--verbose`: Enable verbose output.
- `--export-c`: Export the decompiled C file alongside the database.

**Note**: This command requires a Python environment that can access IDA Pro's Python API. If you are using the system Python, ensure `PYTHONPATH` includes IDA's python directory, or run this tool using `idapyswitch` configured python.

### Serve Command

Starts the MCP HTTP server.

```bash
aida-mcp serve [path_to_project_dir]
```

Arguments:
- `project`: Path to the exported project directory (optional, default: current directory).

Options:
- `--host`: Host to bind to (default: 127.0.0.1).
- `--port`: Port to bind to (default: 8765).

### Install Command

Generates MCP client configuration files.

```bash
aida-mcp install --client <client_name>
```

Options:
- `--client`: Client name (`opencode`, `claude-code`, `trae`, etc.).
- `--transport`: `stdio` or `http` (default: `stdio`).
- `--output`: Output path or `-` for stdout (default: `auto`).

## Directory Structure

- `aida_mcp/`: Source code package.
- `setup.py`: Packaging configuration.

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

## Usage

After installation, the `aida-mcp` command will be available in your Python scripts directory.

### Export Command

Analyzes a binary and exports it to a database file.

```bash
aida-mcp export <path_to_binary> -o <output_db_path>
```

Options:
- `--scan-dir <dir>`: Enable bulk mode to scan for dependencies in the given directory.
- `-j <workers>`: Number of parallel workers (default: 4).
- `--verbose`: Enable verbose output.

**Note**: This command requires a Python environment that can access IDA Pro's Python API. If you are using the system Python, ensure `PYTHONPATH` includes IDA's python directory, or run this tool using `idapyswitch` configured python.

### Serve Command

Starts the MCP HTTP server.

```bash
aida-mcp serve [path_to_project_or_db]
```

Arguments:
- `project`: Path to the exported project directory or database file (optional, default: current directory).

Options:
- `--host`: Host to bind to (default: 127.0.0.1).
- `--port`: Port to bind to (default: 8765).

## Directory Structure

- `aida_mcp/`: Source code package.
- `setup.py`: Packaging configuration.

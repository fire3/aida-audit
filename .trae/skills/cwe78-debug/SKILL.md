---
name: "cwe78-debug"
description: "Debugs CWE78 regression test misses. Invoke when analyzing scan failures or 'missed' results in regression tests."
---

# CWE78 Debugging & Analysis Skill

This skill provides context, workflows, and tools for debugging CWE-78 (OS Command Injection) detection issues in the AIDA-MCP project.

## 1. Project Context

-   **Core Technology**: The project is based on **IDA Pro** for binary analysis and scanning. It does **NOT** analyze source code directly.
-   **No Source Code**: Do not attempt to search for the target binary's source code within the project repositories. The analysis is performed on the binary structure (Microcode/Assembly).

## 2. Exporting Decompiled Source Code

If you need to reference the source code for understanding the logic (e.g., verifying a vulnerability), you can export the decompiled C code using `aida_cli`.

**Command:**
```bash
python -m aida_cli.cli export <target_binary> -o <output_directory> --export-c
```

**Parameters:**
-   `<target_binary>`: Path to the binary file.
-   `-o <output_directory>`: Directory to save results.
-   `--export-c`: **Critical flag** to enable Hex-Rays decompiler output.

**Output:**
-   The decompiled code will be saved in `<output_directory>` (e.g., as `.c` file or inside the DB).

## 3. Taint Path Find Mechanism

-   **Code Reference**: [taint_cmd.py](backend/aida_cli/taint_cmd.py)
-   **Rules**: Defined in [taint_rules.py](backend/aida_cli/taint_rules.py).
    -   **Sources**: Entry points (e.g., `recv`, `getenv`).
    -   **Sinks**: Dangerous functions (e.g., `system`, `execl`).
    -   **Propagators**: Functions that transfer taint (e.g., `strcpy`, `memcpy`).

## 4. Debugging Techniques
-   **Regression Test**: [regression_test_cwe78.py](scripts/regression_test_cwe78.py)
    -   Run specific case: `... --filter <case_name> --verbose --clean`
-  **Check Rules**: Ensure the Source/Sink/Propagator function is defined in `taint_rules.py`.

## 5. Environment
-   **Interpreter**: `/home/fire3/opt/miniconda3/bin/python`
-   **Project Root**: `/home/fire3/SRC/aida-mcp`
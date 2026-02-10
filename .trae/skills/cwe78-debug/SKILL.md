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

## 3. Taint Propagation Mechanism

The scanner uses a **Microcode-based Taint Engine** (`MicrocodeTaintEngine`) that operates on IDA's intermediate representation (Microcode).

-   **Code Reference**: [ida_microcode_taint.py](backend/aida_cli/ida_microcode_taint.py)
-   **Core Logic**:
    -   **Graph-First**: Relies on explicit graph edges (DEF, USE, POINTS_TO) rather than string matching.
    -   **Instruction-Level**: Propagates taint through Microcode instructions (MMAT_LVARS level).
    -   **Taint State**: Tracks taint on Operands (Registers, Stack Slots, Globals) and Memory (Abstract Memory Objects).
    -   **Interprocedural Analysis**:
        -   Uses **Function Summaries** (`_generate_summary`) to handle cross-function propagation.
        -   Calculates "Out-Args" (pointer parameters modified by callee) and "Return Value" taint.
        -   Sorts functions by dependency (Callees first) to build summaries bottom-up.
-   **Rules**: Defined in [taint_rules.py](backend/aida_cli/taint_rules.py).
    -   **Sources**: Entry points (e.g., `recv`, `getenv`).
    -   **Sinks**: Dangerous functions (e.g., `system`, `execl`).
    -   **Propagators**: Functions that transfer taint (e.g., `strcpy`, `memcpy`).

## 4. Debugging Techniques

### 4.1 Flags & Logs
-   **`--verbose`**: Enable detailed logging. Critical for tracing the taint engine's decision path.
    -   *Look for*: `taint.flow`, `scan.function.start`, `taint.sink.hit`.
-   **`--keep`**: Preserve temporary artifacts (IDB, logs) in `scan_results_*/`.
    -   *Files*: `scan.stdout.log` (Engine output), `export.stdout.log` (IDA output).

### 4.2 Key Scripts
-   **Regression Test**: [regression_test_cwe78.py](scripts/regression_test_cwe78.py)
    -   Run specific case: `... --filter <case_name> --keep --verbose`
-   **Trace Debugger**: [debug_taint.py](scripts/debug_taint.py)
    -   Use this to trace taint propagation for a specific node or argument in the graph.
-   **Visualizer**: [visualize_func.py](scripts/visualize_func.py)
    -   Generate visualizations of the function's Control Flow Graph (CFG) or Data Flow Graph (DFG).

### 4.3 Common Debugging Workflow
1.  **Reproduce**: Run the specific test case with `--keep --verbose`.
    ```bash
    /home/fire3/opt/miniconda3/bin/python scripts/regression_test_cwe78.py --filter <case_name> --keep --verbose
    ```
2.  **Analyze Logs**: Check `scan.stdout.log` in the result directory.
    -   Did it find the Source? (Search "Source found" or "rules.dynamic.add")
    -   Did it trace propagation? (Search "taint.flow" or "taint.call.propagate")
    -   Did it hit the Sink? (Search "taint.sink.hit")
3.  **Inspect Decompilation**: If propagation fails, use `export --export-c` to see the Hex-Rays output and compare with what the engine "sees" (Microcode).
4.  **Check Rules**: Ensure the Source/Sink/Propagator function is defined in `taint_rules.py`.

## 5. Environment
-   **Interpreter**: `/home/fire3/opt/miniconda3/bin/python`
-   **Project Root**: `/home/fire3/SRC/aida-mcp`

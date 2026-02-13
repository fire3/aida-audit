---
name: "cwe78-debug"
description: "Debugs CWE78 regression test misses. Invoke when analyzing scan failures or 'missed' results in regression tests."
---

# CWE78 Debugging & Analysis Skill

This skill provides context, workflows, and tools for debugging CWE-78 (OS Command Injection) detection issues in the AIDA-MCP project.

## 1. Project Context

-   **Core Technology**: The project is based on **IDA Pro** for binary analysis and scanning. It does **NOT** analyze source code directly.
-   **No Source Code**: Do not attempt to search for the target binary's source code within the project repositories. The analysis is performed on the binary structure (Microcode/Assembly).

## 2. Debugging Techniques
-   **Regression Test**: [regression_test_cwe78.py](scripts/regression_test_cwe78.py)
    -   Run specific case: `... --filter <case_name>`
    -   Run a small number of cases in the regression test: `... --limit <case_number>`
-  **Check Rules**: Ensure the Source/Sink/Propagator function is defined in `taint_rules.py`.
- **Export C**: Export  decompiled  C for better analysis. For Example
```
    aida-cli export --export-c tests_cpg/CWE78/arm64/CWE78_OS_Command_Injection__char_connect_socket_execlp_32-bad -o tmp
```
    The decompiled C code will be saved in the `tmp` directory.
- The User may give a failed case name, You should use '--filter <case_name>' to run the specific case.

## 3. Taint Path Find Mechanism
-   **Code Reference**: [fixed_point_engine.py](backend/aida_cli/microcode/fixed_point_engine.py)

## 4. Environment
-   **Interpreter**: `/home/fire3/opt/miniconda3/bin/python`
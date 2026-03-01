---
name: aida-cli-rce-analysis
description: Guide for auditing RCE related CWEs using AIDA MCP
license: MIT
compatibility: opencode
---

# AIDA MCP RCE Analysis Skill Guide

This document guides agents on how to use the AIDA MCP toolset to audit Remote Code Execution (RCE) findings. It focuses on specific CWEs related to arbitrary code execution, including Command Injection, Buffer Overflows, and Unsafe Deserialization.

## 1. Core Concepts

- **Remote Code Execution (RCE)**: The ability for an attacker to execute arbitrary commands or code on the target machine.
- **CWE-78 (OS Command Injection)**: Improper neutralization of special elements used in an OS command.
- **CWE-120/121/122 (Buffer Overflow)**: Copying data to a buffer without checking its size, potentially overwriting return addresses or function pointers.
- **CWE-502 (Deserialization of Untrusted Data)**: The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.
- **Sink-to-Source Analysis**: The primary method for RCE auditing. Identify dangerous functions (sinks) and trace their arguments back to untrusted inputs (sources).

## 2. Skill Patterns

### 2.1 Command Injection Auditing (CWE-78)
**Goal**: Detect paths where user input flows into OS command execution APIs.

1.  **Identify Sinks**: `list_binary_imports(binary_name)`
    *   POSIX: `system`, `popen`, `exec`, `execl`, `execv`, `execle`, `execve`, `execvp`.
    *   Windows: `WinExec`, `ShellExecute`, `ShellExecuteEx`, `CreateProcess`, `CreateProcessA`, `CreateProcessW`, `_wsystem`, `_popen`.
2.  **Locate Usage**: `get_binary_cross_references(binary_name, address=SINK_ADDRESS)`
3.  **Trace Argument Origin**:
    *   Analyze the calling function: `get_binary_function_pseudocode_by_address(binary_name, addresses=FUNCTION_ADDRESS)`
    *   Identify the command string buffer.
    *   Trace backwards using `get_binary_function_callers` if the buffer is passed as an argument.
4.  **Check Sanitization**:
    *   Look for whitelisting or strict formatting (e.g., using `execve` with fixed arguments vs `system` with concatenated strings).
    *   Flag any string concatenation involving input variables before the sink.

### 2.2 Dynamic Loading & Injection (CWE-94/426/427)
**Goal**: Detect loading of code/libraries from untrusted paths.

1.  **Identify Sinks**:
    *   POSIX: `dlopen`, `dlsym`.
    *   Windows: `LoadLibrary`, `LoadLibraryEx`, `GetProcAddress`.
2.  **Analyze Path Construction**:
    *   Is the library path absolute or relative?
    *   Can the user influence the search path (DLL Hijacking)?
    *   Is the path constructed from environment variables or config files?

## 3. Analysis Workflow Best Practices

1.  **Prioritize Sinks**: Start with `system`/`exec` (CWE-78) as they are the easiest to exploit and verify. 
2.  **Context Matters**: A `system("clear")` is safe. A `system(cmd_buf)` where `cmd_buf` comes from `recv()` is critical.
3.  **Variable Tracing**:
    *   When you see `sink(arg)`, rename `arg` to `sink_input`.
    *   Look for assignments `sink_input = ...`.
    *   If `sink_input` is a function argument, jump to callers.

## 4. Reporting Standard

- **Write clear, concise, and well-structured reports following this template.**
- **Use user language in the report to avoid confusion.**

### 4.1 Report Template

```markdown
# RCE Analysis Report: [Binary Name]

## 1. Executive Summary
*   **Target**: `[Binary Name]`
*   **Risk Level**: `[Critical/High/Medium]`
*   **Summary**: Found [N] RCE findings. [Brief description].

## 2. Findings Summary
| ID | CWE | Sink | Confidence |
| :--- | :--- | :--- | :--- |
| `RCE-1` | `CWE-78` | `system` | `High` |
| `RCE-2` | `CWE-121` | `strcpy` | `Medium` |

## 3. Detailed Findings

### RCE-1: [Title]
*   **CWE**: [e.g., CWE-78 OS Command Injection]
*   **Sink**: `[Function] @ [Address]`
*   **Source**: `[Function] @ [Address]` (if traced)
*   **Description**: The application constructs a command string using `sprintf` with untrusted input from `recv` and passes it to `system` without validation.
*   **Evidence**:
    > [Pseudocode snippet]

### RCE-2: ...

## 4. Recommendations
*   Replace `system` with `execve` and pass arguments as an array.
*   Use `strncpy` or `snprintf` instead of `strcpy`/`sprintf`.
*   Validate input lengths before copying.
```

---
name: aida-mcp-guide
description: Analysis Skill Guide for AIDA MCP
license: MIT
compatibility: opencode
---

# AIDA MCP Reverse Engineering Skills Guide

This document aims to guide users (and AI models) on how to efficiently perform reverse engineering using the toolset provided by AIDA MCP. We decompose the analysis process into common "Skill Patterns", where each pattern corresponds to a specific sequence of tool calls.

## 1. Core Concepts

- **Binary Name (binary_name)**: The `binary_name` here usually refers to the filename of the IDA database (without extension, or depending on the specific loading context), for example, `chilli`. This parameter is required when using all tools specific to a binary.
- **Address**: Addresses typically support Hexadecimal Strings (e.g., `"0x401000"`) or Integers (e.g., `4198400`).
- **Context**: Analysis is not isolated; it usually requires combining Disassembly, Pseudocode, and Cross-References (Xrefs) to understand.

## 2. Skill Patterns

### 2.1 Exploration & Overview

**Scenario**: Starting to analyze a new binary file and needing to understand its basic structure, exported functions, and referenced external libraries.

*   **List all binary files**: `get_project_binaries()`
    *   *Purpose*: Determine what analysis targets are currently available.
*   **View Exported Functions (Public API)**: `list_binary_exports(binary_name)`
    *   *Purpose*: Understand what functionality this module provides externally (if it is a DLL/SO).
*   **View Imported Functions (Dependencies)**: `list_binary_imports(binary_name)`
    *   *Purpose*: Understand what external functionality this module depends on (e.g., network `socket`, file `CreateFile`, encryption `Crypt`, etc.).
*   **Browse Internal Functions**: `list_binary_functions(binary_name, limit=20)`
    *   *Purpose*: Get a list of functions, can be used with `offset` for pagination.

### 2.2 String Analysis

**Scenario**: The program outputs specific error messages or logs, or specific text is displayed on the interface, and you want to find the code logic that handles this text.

1.  **Search Strings**: `search_strings(search_string="Error", match="contains")`
    *   *Purpose*: Search for the string in all binaries. If the binary is known, `search_string_symbol_in_binary` can also be used.
    *   *Output*: Get the `address` of the string (e.g., `0x4050A0`).
2.  **Find References (Xrefs)**: `get_string_xrefs(binary_name, string_address="0x4050A0")`
    *   *Purpose*: Find who uses this string.
    *   *Output*: Get a list of code addresses referencing this string (e.g., `0x401200`).
3.  **Locate Code**: `get_disassembly_context(binary_name, address="0x401200")`
    *   *Purpose*: View the assembly code context at the reference location to analyze the logic.

### 2.3 Deep Function Analysis

**Scenario**: You have located an interesting function address (e.g., via string tracing or the export table) and need to thoroughly understand its behavior.

**Important Principle**: Prioritize using pseudocode for logic analysis. Use disassembly only when pseudocode is inaccurate or when low-level details are needed.

1.  **Pseudocode First**: `get_binary_function_pseudocode_by_address(binary_name, function_address)`
    *   *Purpose*: Read high-level code similar to C. This is the fastest and most effective way to understand function logic, variable flow, and control structures. **Be sure to call this tool first.**
2.  **Auxiliary Analysis (Deep Dive)**: Combine references to understand function context.
    *   **Who calls me? (Callers)**: `get_binary_function_callers(binary_name, function_address)` -> Understand trigger conditions and parameter sources.
    *   **Who do I call? (Callees)**: `get_binary_function_callees(binary_name, function_address)` -> Understand the sub-functionality this function depends on.
3.  **View Disassembly (Disassembly as Fallback)**: `get_binary_disassembly_context(binary_name, address)`
    *   *Purpose*: Use only when pseudocode is ambiguous, missing details, or when specific instructions (such as encryption instructions, obfuscated instructions) need to be checked.
    *   *Note*: Do not read large amounts of disassembly code from the start; it is extremely inefficient.

### 2.4 API Auditing

**Scenario**: Suspecting malicious behavior in the program (e.g., network callback, file theft) and wishing to audit calls to sensitive APIs.

1.  **Find Sensitive Imports**: `list_binary_imports(binary_name)` -> Filter for `InternetOpen`, `CreateFile`, `RegOpenKey`, etc.
2.  **Find API References**: `get_binary_cross_references(binary_name, address=IMPORT_ADDRESS)`
    *   *Note*: The address of imported functions is usually in the `.idata` section.
3.  **Analyze Call Sites**:
    *   **Step A (Recommended)**: Get the pseudocode of the function where the reference is located using `get_binary_function_pseudocode_by_address` to see how the API is called.
    *   **Step B (Alternative)**: If you only need to see parameter passing, use `get_binary_disassembly_context(binary_name, address=XREF_ADDRESS)` to view instructions before the call (e.g., `PUSH` or register assignment).

### 2.5 Algorithm & Constant Identification

**Scenario**: Identifying encryption algorithms or specific protocols.

1.  **Search Magic Numbers/Constants**: `search_immediates_in_binary(binary_name, value="0x67452301")` (MD5 Constant)
    *   *Purpose*: Quickly locate the core transformation functions of encryption algorithms. This is the most effective way to locate standard algorithms (AES, DES, MD5, SHA, etc.).
2.  **Search Byte Patterns**: `search_bytes_pattern_in_binary(binary_name, pattern="55 8B EC")`
    *   *Purpose*: Find specific instruction sequences or file headers.
3.  **Multi-Binary Search**: If unsure which module it is in, use `search_functions_in_project` or `search_exported_function_in_project` for cross-module searching.

## 3. FAQ & Best Practices

*   **Pseudocode vs Disassembly**:
    *   **Golden Rule**: Always prioritize pseudocode (`get_binary_function_pseudocode_by_address`).
    *   **Why?**: Pseudocode abstracts away low-level details like stack balancing and register allocation, directly showing business logic.
    *   **When Disassembly?**: Consult disassembly only when dealing with obfuscated code, inline assembly, or pseudocode errors caused by compiler optimizations.
*   **Context Window**:
    *   `get_binary_disassembly_context` returns lines of code before and after the target address by default. If you need to see longer code, it is recommended to use the pseudocode tool.
*   **Address Format**:
    *   Tools can intelligently handle hex strings (with `0x`) and decimal integers. It is recommended to consistently use hex strings.

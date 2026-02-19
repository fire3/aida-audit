---
name: aida-cli-attack-surface-analysis
description: Guide for Attack Surface Analysis using AIDA MCP
license: MIT
compatibility: opencode
---

# AIDA MCP Attack Surface Analysis Skill Guide

This document guides agents on how to use the AIDA MCP toolset to perform Code Attack Surface Analysis. It focuses on finding **source points** (untrusted external input entering the program) as the first and most critical step, then connecting sources to **sinks** to form candidate exploit chains. It also prescribes a standardized reporting format.

## 1. Core Concepts

- **Attack Surface**: The sum of all paths for data/commands into and out of the application, and the code that protects these paths.
- **Source Point (Source)**: Any program point that introduces **untrusted external data** into the process (network reads, file reads, environment variables, IPC/RPC messages, CLI args, registry/config, etc.).
- **Entry Point (Control Entry)**: A control-flow entry into the binary from the outside (exports, callbacks, RPC dispatchers, message handlers). Entry points often *contain* sources, but they are not the same concept.
- **Sink**: A sensitive operation that becomes dangerous when influenced by untrusted input (command execution, file writes, dynamic code loading, unsafe memory operations, risky deserialization).
- **Reachability**: Whether a sink is reachable from a source through a realistic call path and data-flow path.
- **Evidence Standard**: Every claim in the report must be backed by a tool output snippet (pseudocode, xrefs, strings entry, etc.) and a concrete location (function name + address).

## 2. Skill Patterns

### 2.1 Project Triage (Always First)
**Goal**: Establish scope and pick targets.

*   **Get project overview**: `get_project_overview()`
*   **List binaries**: `get_project_binaries(offset=0, limit=50, detail=true)`
*   **Pick a binary and get metadata**: `get_binary_metadata(binary_name)`
    *   Use metadata to determine platform hints (PE/ELF), architecture, and whether strings/imports/xrefs are available.

### 2.2 Source Point Discovery (Primary Best Practice)
**Goal**: Find where *untrusted* data enters the process. Start from the most common real-world sources: **network input**, **file input**, **environment/CLI input**, **IPC/RPC**, then use **data features** (strings, magic numbers, protocol markers) to accelerate.

#### 2.2.1 Network Input Sources
**What to look for**: imports that read bytes from network sockets or higher-level HTTP/TLS stacks.

1.  **Enumerate candidate APIs from imports**: `list_binary_imports(binary_name, offset=0, limit=50)` (paginate until exhausted).
    *   Common POSIX sources: `accept`, `recv`, `recvfrom`, `read`, `readv`, `SSL_read`, `BIO_read`.
    *   Common Windows sources: `recv`, `WSARecv`, `InternetReadFile`, `WinHttpReadData`, `HttpReceiveHttpRequest`, `WSARecvFrom`.
2.  **Pivot from the import address to call sites**: `get_binary_cross_references(binary_name, address=IMPORT_ADDRESS)`
    *   For imported functions, the relevant call sites are typically in the `"to"` list (incoming xrefs to the import thunk).
3.  **Promote each call site to a containing function**: `resolve_address(binary_name, address=XREF_ADDRESS)` and/or `get_binary_function_by_address(binary_name, addresses=FUNCTION_ADDRESS)`
4.  **Analyze the containing function in pseudocode**: `get_binary_function_pseudocode_by_address(binary_name, addresses=FUNCTION_ADDRESS)`
    *   Confirm the **actual source buffer**, **length**, **ownership**, and **boundary checks**.
5.  **Estimate attack surface**:
    *   If the read happens in a loop and feeds a parser, treat this as a high-priority source.
    *   If the source is followed by decoding (base64, URL decode, JSON parse, protobuf parse), mark the decoder/parser as part of the source pipeline.

#### 2.2.2 File Input Sources
**What to look for**: imports that open/read files, memory-map files, or load configuration.

1.  **Enumerate candidate APIs from imports**: `list_binary_imports(binary_name, ...)`
    *   POSIX: `open`, `fopen`, `read`, `fread`, `mmap`, `readlink`.
    *   Windows: `CreateFile`, `ReadFile`, `GetFileSize`, `MapViewOfFile`.
2.  **Pivot to call sites**: `get_binary_cross_references(binary_name, address=IMPORT_ADDRESS)`
3.  **Validate that the file path is attacker-controlled**:
    *   Look for file paths coming from CLI args, environment variables, registry/config, IPC messages, or user-writable directories.
    *   Use strings to identify config files or extensions (see 2.2.5).

#### 2.2.3 Environment Variables and CLI Argument Sources
**What to look for**: APIs that fetch environment variables or command line strings, which can be attacker-controlled in many deployment models.

1.  **Enumerate candidate APIs from imports**: `list_binary_imports(binary_name, ...)`
    *   POSIX: `getenv`, `setenv`, `getopt`, `getopt_long`.
    *   Windows: `GetEnvironmentVariableA/W`, `GetCommandLineA/W`, `CommandLineToArgvW`.
2.  **Pivot to call sites**: `get_binary_cross_references(binary_name, address=IMPORT_ADDRESS)`
3.  **Confirm trust boundary** in pseudocode:
    *   Does the value directly control file paths, command strings, dynamic library loads, network destinations, or deserialization?

#### 2.2.4 IPC & RPC Sources (High Leverage)
**What to look for**: named pipes, RPC frameworks, shared memory, message queues, COM/DCOM, D-Bus, gRPC, custom protocol dispatchers.

1.  **Enumerate IPC/RPC-related imports**: `list_binary_imports(binary_name, ...)`
    *   Windows named pipe: `CreateNamedPipe`, `ConnectNamedPipe`, `PeekNamedPipe`, `ReadFile` (pipe handle).
    *   Windows RPC/COM: `Rpc*`, `CoCreateInstance`, `CoInitialize*`, `NdrClientCall*`.
    *   POSIX: `socket` with `AF_UNIX`, `bind`, `accept`, `recv`, `shm_open`, `mmap`, `msgget/msgrcv`, `mq_receive`.
2.  **Pivot to dispatch points**:
    *   For RPC/COM frameworks, the *real* source is often a **dispatcher** function. Use xrefs on framework APIs to find the dispatcher, then enumerate handlers via callees/callers:
        *   `get_binary_function_callees(binary_name, function_address, depth=2, limit=200)`
        *   `get_binary_function_callers(binary_name, function_address, depth=2, limit=200)`
3.  **Confirm message boundaries**:
    *   Identify how message length is computed, whether the code trusts length fields, and whether it copies into fixed-size buffers.

### 2.3 Control Entry Enumeration (Exports and Top-Level Handlers)
**Goal**: Identify externally callable entry points and main dispatchers.

*   **List Exports**: `list_binary_exports(binary_name)`
    *   *Usage*: Catalog all exported functions. These are the primary entry points for DLLs/SOs.
    *   *Analysis*: Focus on exports that accept pointers/buffers, or that call into source pipelines (network/file/IPC reads).
*   **Find obvious top-level functions by name**: `get_binary_function_by_name(binary_name, names=["main","WinMain","wWinMain","ServiceMain","DllMain"], match="exact")`
    *   Treat these as control entry points even when there are no exports.

### 2.4 Sink-First Auditing (Dangerous Operations)
**Goal**: Identify high-impact sinks, then trace backwards to sources to establish exploitability.

*   **List Imports**: `list_binary_imports(binary_name)`
    *   *Usage*: List all imported functions.
    *   *Filter*: Look for high-risk categories:
        *   **Execution**: `system`, `exec`, `CreateProcess`, `ShellExecute`
        *   **Filesystem**: `fopen`, `CreateFile`, `ReadFile`, `WriteFile`
        *   **Network**: `socket`, `connect`, `send`, `recv`, `InternetOpen`
        *   **Memory**: `memcpy`, `strcpy` (buffer overflow risks), `VirtualAlloc` (shellcode injection risks)

### 2.5 Source-to-Sink Chaining (Exploit-Chain Oriented)
**Goal**: Build concrete candidate chains: Source → Transform/Parser → Validation → Sink.

1.  **Pick a source call site** (from 2.2) and capture its containing function.
2.  **Enumerate callees to find transforms/parsers**: `get_binary_function_callees(binary_name, function_address, depth=2, limit=200)`
3.  **Identify validation points**:
    *   In pseudocode, look for bounds checks, length clamps, allowlists, signature checks, schema checks.
4.  **Pivot to sinks**:
    *   If you suspect a sink, locate the import and xref it: `get_binary_cross_references(binary_name, address=SINK_IMPORT_ADDRESS)`
    *   Then check whether the sink function is reachable from your source pipeline using callers/callees and pseudocode evidence.

### 2.6 Data-Feature-Driven Localization (Strings, Magic Numbers, Byte Signatures)
**Goal**: When sources are hard to spot by imports (e.g., static linking, custom wrappers), use data features to jump into parsers and message handlers.

1.  **String searches inside one binary**: `search_string_symbol_in_binary(binary_name, search_string="...", match="contains")`
2.  **String searches across the whole project**: `search_strings_in_project(search_string="...", match="contains")`
3.  **Useful source-related strings to search**:
    *   Network/protocol markers: `"GET "`, `"POST "`, `"HTTP/"`, `"User-Agent"`, `"Content-Length"`, `"Host:"`, `"Cookie:"`, `"Authorization"`.
    *   IPC/RPC markers: `"\\\\.\\\\pipe\\\\"`, `"rpc"`, `"grpc"`, `"protobuf"`, `"dbus"`, `"com"`, `"named pipe"`.
    *   File/config markers: `".json"`, `".xml"`, `".ini"`, `".conf"`, `"config"`, `"/etc/"`, `"C:\\\\ProgramData\\\\"`, `"AppData"`.
4.  **Magic numbers / protocol constants**:
    *   `search_immediates_in_binary(binary_name, value=0x5A4D)` for `"MZ"`, `value=0x464C457F` for `\"\\x7FELF\"`, `value=0x04034B50` for ZIP `"PK\\x03\\x04"` (endianness may vary by use-site).
    *   For ASCII markers embedded in code/data, use `search_bytes_pattern_in_binary(binary_name, pattern="47 45 54 20")` for `"GET "` or other fixed signatures.
5.  **Pivot from a hit to code**:
    *   If you get a string address, use `get_binary_cross_references(binary_name, address=STRING_ADDRESS)` and analyze each referencing function in pseudocode.

## 3. Analysis Workflow Best Practices

1.  **Source-first, then chain**: Finding sources is the fastest way to build a real exploit chain. Enumerate network/file/env/IPC sources first, then connect to sinks.
2.  **Two complementary starting points**:
    *   **Outside-in**: Control Entry → Source → Parser → Validation → Sink.
    *   **Inside-out**: Sink → Callers → Upstream parsing → Source.
3.  **Prefer pseudocode for logic**: Use `get_binary_function_pseudocode_by_address` as the default view. Use disassembly only to resolve calling convention/argument ambiguity.
4.  **Record invariants**: For each source, record buffer size, length derivation, and whether the code trusts length fields.
5.  **Be explicit about assumptions**: If a reachability claim is not proven, label it as “hypothesis” and list what evidence is missing.

## 4. Reporting Standard

- **Write clear, concise, and well-structured reports following this template.**
- **Use user language in the report to avoid confusion.**

### 4.1 Report Template

```markdown
# Attack Surface Analysis Report: [Binary Name]

## 1. Executive Summary
*   **Target**: `[Binary Name]`
*   **Risk Level**: `[High/Medium/Low]`
*   **Summary**: Brief overview of the findings (e.g., "3 high-confidence sources (network, IPC), 2 reachable command-exec/file-write sinks, 1 candidate exploit chain with weak validation.")

## 2. Attack Surface Metrics
| Category | Count | Notes |
| :--- | :--- | :--- |
| **Control Entry Points (Exports/Handlers)** | `[N]` | `[e.g., 3 exported APIs, 1 message loop]` |
| **Sources (Untrusted Inputs)** | `[N]` | `[e.g., recv, ReadFile(config), getenv]` |
| **Sinks (High Impact)** | `[N]` | `[e.g., CreateProcess, WriteFile, strcpy]` |
| **Sensitive Strings** | `[N]` | `[e.g., 1 internal endpoint]` |

## 3. Source Inventory (Required)
| Source ID | Category | API / Mechanism | Evidence Location | Data Shape | Trust Boundary Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SRC-1` | `Network` | `recv` | `[Function] @ [Address]` | `[buffer,len]` | `[who controls it, checks]` |
| `SRC-2` | `IPC/RPC` | `Named pipe` | `[Function] @ [Address]` | `[message,len]` | `[authn/authz, framing]` |

## 4. Candidate Exploit Chains (Optional)
List each chain as: `Source → Parser/Transform → Validation → Sink`, and include at least one evidence snippet per stage.

Example:
*   `SRC-1 (recv) → parse_http_headers → no length clamp → SINK-2 (strcpy)`

## 5. Detailed Vulnerabilities

### Vulnerability #1: [Title, e.g., Unbounded Copy in Exported Function]
*   **Severity**: `[Critical/High/Medium/Low]`
*   **Location**: `[Function Name] @ [Address]`
*   **Description**: Detailed explanation of the vulnerability.
*   **Evidence**:
    > [Relevant pseudocode, do not make assumptions]

### Vulnerability #2: ...

## 6. Conclusion & Next Steps
Final assessment and recommended immediate actions.
```

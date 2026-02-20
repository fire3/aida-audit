# Flare-Emu Integration Analysis for AIDA Backend

## 1. Introduction
The goal is to integrate `flare_emu` functionality into the AIDA backend, enabling emulation-based analysis without a direct runtime dependency on IDA Pro. This involves creating a `flare_emu` backend that consumes data from the AIDA database (SQLite) instead of querying IDA API directly.

## 2. Current State
Currently, `flare_emu` relies on the `AnalysisHelper` interface to abstract the underlying disassembler. `flare_emu_ida.py` implements this for IDA Pro using `idaapi`, `idautils`, and `idc`. The AIDA export process (`ida_exporter.py`) exports metadata, functions, strings, imports/exports, and flat disassembly text to a SQLite database.

## 3. Gap Analysis
To implement an `AidaAnalysisHelper` that fully supports `flare_emu`, the following data is missing from the current AIDA database export:

### 3.1 Binary Content
`flare_emu` needs to read actual bytes from memory to initialize the Unicorn emulator (`get_bytes`, `getSegmentDefinedSize`).
*   **Current Export**: Only exports segment/section metadata (addresses, permissions) and entropy.
*   **Requirement**: Need to export the actual byte content of segments.

### 3.2 Control Flow Graph (CFG)
`flare_emu` relies heavily on function control flow graphs (`getFlowChart`, `getBlockByAddr`, `getStartBB`, `isTerminatingBB`) to explore paths and emulate ranges.
*   **Current Export**: Only exports call edges (function-to-function). No basic block information.
*   **Requirement**: Need to export Basic Blocks (start/end addresses, type) and their connectivity (successors/predecessors).

### 3.3 Structured Instruction Data
`flare_emu` needs precise instruction details (`getMnem`, `getOperand`, `getOpndType`, `getOpndValue`, `getSpDelta`, `getInsnSize`).
*   **Current Export**: Only exports flat disassembly text lines in `disasm_chunks`. Parsing these is brittle and insufficient for operand types and values.
*   **Requirement**: Need to export structured instruction data, including mnemonics, operand types, values, and stack pointer deltas.

### 3.4 Processor State
`flare_emu` checks for processor modes (e.g., `isThumbMode`).
*   **Current Export**: Basic architecture info in metadata.
*   **Requirement**: Need to export segment register values or processor mode info if applicable (crucial for ARM).

## 4. Proposed Changes

### 4.1 Database Schema Updates (`binary_database.py`)
Add the following tables:
*   `segments`: Add `content` BLOB column (or a separate `segment_content` table to keep main table light).
*   `basic_blocks`:
    *   `id` (integer, unique within function or global)
    *   `function_va` (FK to functions)
    *   `start_va`
    *   `end_va`
    *   `type` (normal, ret, noret, etc.)
*   `basic_block_successors`:
    *   `src_block_start_va`
    *   `dst_block_start_va`
*   `instructions`:
    *   `address` (PK)
    *   `mnemonic`
    *   `size`
    *   `sp_delta`
*   `instruction_operands`:
    *   `address` (FK to instructions)
    *   `op_index`
    *   `type` (reg, imm, mem, etc.)
    *   `value` (for immediate)
    *   `text` (representation)

### 4.2 IDA Exporter Updates (`ida_exporter.py`)
Implement new export methods:
*   `export_segment_content()`: Read bytes from segments and store in DB.
*   `export_cfg()`: Iterate functions, retrieve `idaapi.FlowChart`, export blocks and edges.
*   `export_instructions()`: Iterate instructions, use `idc.get_operand_type`, `idc.get_operand_value`, `idaapi.get_sp_delta` to export details.

### 4.3 `flare_emu_aida.py` Design
Create `AidaAnalysisHelper` class inheriting from `flare_emu.AnalysisHelper`.
*   Initialize with a `BinaryDatabase` connection.
*   Implement all required methods by querying the SQLite database.
*   Cache CFG and instruction data to improve performance.

## 5. Implementation Plan
1.  **Modify `binary_database.py`**: Add new tables and insertion methods.
2.  **Modify `ida_exporter.py`**: Implement data extraction for new tables.
3.  **Create `flare_emu_aida.py`**: Implement the `AidaAnalysisHelper`.
4.  **Testing**: Verify exports with a sample binary and test `flare_emu` features using the new helper.

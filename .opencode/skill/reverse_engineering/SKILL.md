---
name: reverse-engineering 
description: 基于MCP服务的逆向分析技能指南
license: MIT
compatibility: opencode
---

# IDA Project MCP 逆向分析技能指南 (Reverse Engineering Skills Guide)

本文档旨在指导用户（以及 AI 模型）如何利用 IDA Project MCP 提供的工具集高效地进行逆向分析。我们将分析流程分解为常见的“技能模式”，每种模式对应一组特定的工具调用序列。

## 1. 核心概念 (Core Concepts)

- **Binary Name (binary_name)**: 这里的 binary_name 通常指 IDA 数据库的文件名（不带后缀，或视具体加载情况而定），例如 `chilli`。在使用所有针对特定二进制的工具时都需要提供此参数。
- **Address**: 地址通常支持 十六进制字符串 (如 `"0x401000"`) 或 整数 (如 `4198400`)。
- **Context**: 分析不是孤立的，通常需要结合反汇编 (Disassembly)、伪代码 (Pseudocode) 和 引用关系 (Xrefs) 来理解。

## 2. 技能模式 (Skill Patterns)

### 2.1 探索与概览 (Exploration & Overview)

**场景**: 刚开始分析一个新的二进制文件，需要了解其基本结构、导出的功能以及引用的外部库。

*   **列出所有二进制文件**: `get_project_binaries()`
    *   *用途*: 确定当前有哪些分析目标可用。
*   **查看导出函数 (Public API)**: `list_binary_exports(binary_name)`
    *   *用途*: 了解该模块对外提供了什么功能（如果是 DLL/SO）。
*   **查看导入函数 (Dependencies)**: `list_binary_imports(binary_name)`
    *   *用途*: 了解该模块依赖哪些外部功能（如网络 `socket`, 文件 `CreateFile`, 加密 `Crypt` 等）。
*   **浏览内部函数**: `list_binary_functions(binary_name, limit=20)`
    *   *用途*: 获取函数列表，可以配合 `offset` 分页浏览。

### 2.2 字符串追踪 (String Analysis)

**场景**: 发现程序输出了特定的错误信息或日志，或者界面上显示了特定文本，希望找到处理这些文本的代码逻辑。

1.  **搜索字符串**: `search_strings(search_string="Error", match="contains")`
    *   *用途*: 在所有二进制中查找该字符串。如果知道在哪个 binary，也可以用 `search_string_symbol_in_binary`。
    *   *输出*: 得到字符串的 `address` (例如 `0x4050A0`)。
2.  **查找引用 (Xrefs)**: `get_string_xrefs(binary_name, string_address="0x4050A0")`
    *   *用途*: 找到是谁使用了这个字符串。
    *   *输出*: 得到引用该字符串的代码地址列表 (例如 `0x401200`).
3.  **定位代码**: `get_disassembly_context(binary_name, address="0x401200")`
    *   *用途*: 查看引用位置的汇编代码上下文，分析逻辑。

### 2.3 深入函数分析 (Deep Function Analysis)

**场景**: 已经定位到一个感兴趣的函数地址（例如通过字符串追踪或导出表），需要彻底理解其行为。

**重要原则**: 优先使用伪代码进行逻辑分析，只有在伪代码不准确或需要查看底层细节时，才使用反汇编。

1.  **首选伪代码 (Pseudocode First)**: `get_binary_function_pseudocode_by_address(binary_name, function_address)`
    *   *用途*: 阅读类似 C 语言的高级代码。这是理解函数逻辑、变量流向和控制结构的最快且最有效的方式。**务必先调用此工具。**
2.  **辅助分析 (Deep Dive)**: 结合引用关系理解函数上下文。
    *   **谁调用了我? (Callers)**: `get_binary_function_callers(binary_name, function_address)` -> 了解触发条件和参数来源。
    *   **我调用了谁? (Callees)**: `get_binary_function_callees(binary_name, function_address)` -> 了解该函数依赖的子功能。
3.  **查看反汇编 (Disassembly as Fallback)**: `get_binary_disassembly_context(binary_name, address)`
    *   *用途*: 仅当伪代码存在歧义、丢失细节，或者需要检查特定指令（如加密指令、花指令）时使用。
    *   *注意*: 不要一开始就阅读大量反汇编代码，效率极低。

### 2.4 API 行为审计 (API Auditing)

**场景**: 怀疑程序有恶意行为（如网络回连、文件窃取），希望审计敏感 API 的调用。

1.  **查找敏感导入**: `list_binary_imports(binary_name)` -> 筛选如 `InternetOpen`, `CreateFile`, `RegOpenKey` 等。
2.  **查找 API 引用**: `get_binary_cross_references(binary_name, address=IMPORT_ADDRESS)`
    *   *注意*: 导入函数的地址通常在 `.idata` 段。
3.  **分析调用点**:
    *   **步骤 A (推荐)**: 获取引用点所在函数的伪代码 `get_binary_function_pseudocode_by_address`，查看 API 是如何被调用的。
    *   **步骤 B (备选)**: 如果只需要看参数传递，使用 `get_binary_disassembly_context(binary_name, address=XREF_ADDRESS)` 查看调用前的指令（如 `PUSH` 或寄存器赋值）。

### 2.5 算法与常量识别 (Algorithm & Constant Identification)

**场景**: 识别加密算法或特定协议。

1.  **搜索魔数/常量**: `search_immediates_in_binary(binary_name, value="0x67452301")` (MD5 常量)
    *   *用途*: 快速定位加密算法的核心变换函数。这是定位标准算法（AES, DES, MD5, SHA等）最有效的方法。
2.  **搜索字节特征**: `search_bytes_pattern_in_binary(binary_name, pattern="55 8B EC")`
    *   *用途*: 查找特定的指令序列或文件头。
3.  **多二进制搜索**: 如果不确定在哪个模块，使用 `search_functions_in_project` 或 `search_exported_function_in_project` 进行跨模块搜索。

## 3. 常见问题与最佳实践 (FAQ & Best Practices)

*   **Pseudocode vs Disassembly**:
    *   **Golden Rule**: 始终以伪代码 (`get_binary_function_pseudocode_by_address`) 为主。
    *   **Why?**: 伪代码抽象了堆栈平衡、寄存器分配等底层细节，直接展示业务逻辑。
    *   **When Disassembly?**: 仅在处理混淆代码、内联汇编或编译器优化导致的伪代码错误时，才查阅反汇编。
*   **Context Window**:
    *   `get_binary_disassembly_context` 默认返回目标地址前后的代码行。如果需要看更长的代码，建议使用伪代码工具。
*   **Address Format**:
    *   工具能够智能处理 hex 字符串（带 `0x`）和十进制整数。建议统一使用 hex 字符串以保持一致性。
# BinaryDB 数据模型规范

BinaryDB 是 AIDA-CLI 用于存储二进制文件静态分析结果的 SQLite 数据库。由 IDA Pro 或 Ghidra 导出工具生成，包含函数、反汇编、伪代码、交叉引用等核心分析数据。

## 数据库文件

- **文件名**: `<project>.db`
- **位置**: 项目目录下
- **创建方式**: 通过 `ida_exporter.py` 或 `ghidra_importer.py` 导出

---

## 表结构总览

| 表名 | 用途 | 主键 |
|------|------|------|
| [metadata_json](#metadata_json) | 二进制文件元数据 | id |
| [segments](#segments) | 内存段信息 | seg_id |
| [sections](#sections) | 文件节区信息 | sec_id |
| [imports](#imports) | 导入表 | import_id |
| [exports](#exports) | 导出表 | export_id |
| [symbols](#symbols) | 符号表 | symbol_id |
| [functions](#functions) | 函数信息 | function_va |
| [functions_rtree](#functions_rtree) | 函数地址空间索引 | (虚拟表) |
| [pseudocode](#pseudocode) | 反编译伪代码 | function_va |
| [disasm_chunks](#disasm_chunks) | 反汇编块 | start_va |
| [data_items](#data_items) | 数据项 | address |
| [strings](#strings) | 字符串表 | string_id |
| [xrefs](#xrefs) | 交叉引用 | xref_id |
| [call_edges](#call_edges) | 函数调用图 | (复合主键) |
| [local_types](#local_types) | 本地类型定义 | type_id |
| [segment_content](#segment_content) | 段原始内容 | seg_id |
| [basic_blocks](#basic_blocks) | 函数基本块 | block_id |
| [basic_block_successors](#basic_block_successors) | 基本块控制流 | (复合主键) |
| [instructions](#instructions) | 指令反汇编 | address |
| [instruction_operands](#instruction_operands) | 指令操作数 | (复合主键) |

---

## 详细表定义

### metadata_json

存储二进制文件的整体元数据信息。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY, CHECK(id=1) | 固定为1，用于单行元数据 |
| content | TEXT | | 元数据JSON，包含文件哈希、架构、入口点等信息 |

---

### segments

内存段（Segment）信息，对应 PE 的段或 ELF 的程序头。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| seg_id | INTEGER | PRIMARY KEY AUTOINCREMENT | 段唯一标识 |
| name | TEXT | | 段名称（如 .text, .data） |
| start_va | INTEGER | | 起始虚拟地址 |
| end_va | INTEGER | | 结束虚拟地址 |
| perm_r | INTEGER | | 读权限标志 (0/1) |
| perm_w | INTEGER | | 写权限标志 (0/1) |
| perm_x | INTEGER | | 执行权限标志 (0/1) |
| file_offset | INTEGER | | 文件偏移 |
| type | TEXT | | 段类型（如 CODE, DATA） |

---

### sections

文件节区（Section）信息，对应 PE/ELF 的节区表。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| sec_id | INTEGER | PRIMARY KEY AUTOINCREMENT | 节区唯一标识 |
| name | TEXT | | 节区名称 |
| start_va | INTEGER | | 起始虚拟地址 |
| end_va | INTEGER | | 结束虚拟地址 |
| file_offset | INTEGER | | 文件偏移 |
| entropy | REAL | | 节区熵值（用于检测加壳） |
| type | TEXT | | 节区类型 |

---

### imports

导入表（Import Table），记录从共享库导入的函数。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| import_id | INTEGER | PRIMARY KEY AUTOINCREMENT | 导入项唯一标识 |
| library | TEXT | | 所属库名称（如 kernel32.dll） |
| name | TEXT | | 导入函数名称 |
| ordinal | INTEGER | | 导出序号 |
| address | INTEGER | | 加载后的实际地址 |
| thunk_address | INTEGER | | Thunk表地址 |

---

### exports

导出表（Export Table），记录二进制文件导出的符号。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| export_id | INTEGER | PRIMARY KEY AUTOINCREMENT | 导出项唯一标识 |
| name | TEXT | | 导出名称 |
| ordinal | INTEGER | | 导出序号 |
| address | INTEGER | | 导出地址 |
| forwarder | TEXT | | 转发器指向 |

---

### symbols

符号表（Symbol Table），记录所有已解析的符号。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| symbol_id | INTEGER | PRIMARY KEY AUTOINCREMENT | 符号唯一标识 |
| name | TEXT | | 原始符号名 |
| demangled_name | TEXT | | C++ 名称修饰还原后的名称 |
| kind | TEXT | | 符号类型（FUNCTION, OBJECT 等） |
| address | INTEGER | | 符号地址 |
| size | INTEGER | | 符号大小 |

---

### functions

函数信息表，存储所有已识别函数的元数据。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| function_va | INTEGER | PRIMARY KEY | 函数起始虚拟地址 |
| name | TEXT | | 函数名称 |
| demangled_name | TEXT | | C++ 名称还原后的名称 |
| start_va | INTEGER | | 函数起始地址（同 function_va） |
| end_va | INTEGER | | 函数结束地址 |
| size | INTEGER | | 函数大小（字节） |
| is_thunk | INTEGER | | 是否为 Thunk 函数（跳转到其他函数） |
| is_library | INTEGER | | 是否为库函数（已识别为系统API） |

---

### functions_rtree

R-Tree 虚拟表，用于高效进行函数地址范围查询。

```sql
CREATE VIRTUAL TABLE functions_rtree USING rtree(
    id,
    start_va,
    end_va
);
```

---

### pseudocode

存储函数的反编译伪代码。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| function_va | INTEGER | PRIMARY KEY | 函数地址（外键引用 functions.function_va） |
| content | TEXT | | 反编译生成的 C 语言风格伪代码 |

---

### disasm_chunks

反汇编块，存储函数的反汇编文本。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| start_va | INTEGER | PRIMARY KEY | 块起始地址 |
| end_va | INTEGER | | 块结束地址 |
| content | TEXT | | 反汇编文本（多行） |

---

### data_items

已识别数据项，记录常量、数组、全局变量等。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| address | INTEGER | PRIMARY KEY | 数据项地址 |
| size | INTEGER | | 数据大小（字节） |
| kind | TEXT | | 数据种类（CONSTANT, ARRAY, POINTER 等） |
| type_name | TEXT | | 类型名称（如 int, char[16]） |
| repr | TEXT | | 数据表示形式 |
| target_va | INTEGER | | 目标地址（如果是指针） |

---

### strings

从二进制中提取的字符串常量。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| string_id | INTEGER | PRIMARY KEY AUTOINCREMENT | 字符串唯一标识 |
| address | INTEGER | | 字符串在内存中的地址 |
| encoding | TEXT | | 字符编码（utf-8, ascii, utf-16le 等） |
| length | INTEGER | | 字符串长度 |
| string | TEXT | | 字符串内容 |
| section_name | TEXT | | 所属节区名称 |

---

### xrefs

交叉引用（Cross-References），记录指令间的引用关系。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| xref_id | INTEGER | PRIMARY KEY AUTOINCREMENT | 引用唯一标识 |
| from_va | INTEGER | | 源地址（引用发起方） |
| to_va | INTEGER | | 目标地址（被引用方） |
| from_function_va | INTEGER | | 源函数地址 |
| to_function_va | INTEGER | | 目标函数地址 |
| xref_type | TEXT | | 引用类型（JUMP, CALL, DATA 等） |
| operand_index | INTEGER | | 操作数索引（用于区分同一指令的多个引用） |

---

### call_edges

函数调用边，记录函数间的调用关系。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| caller_function_va | INTEGER | PRIMARY KEY | 调用者函数地址 |
| callee_function_va | INTEGER | PRIMARY KEY | 被调用者函数地址 |
| call_site_va | INTEGER | PRIMARY KEY | 调用点地址 |
| call_type | TEXT | | 调用类型（DIRECT, INDIRECT, tailcall） |

---

### local_types

本地类型定义，存储结构体、联合、枚举等用户自定义类型。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| type_id | INTEGER | PRIMARY KEY AUTOINCREMENT | 类型唯一标识 |
| name | TEXT | | 类型名称 |
| content | TEXT | | 类型定义内容（IDA/Ghidra 格式） |

---

### segment_content

段的原始二进制内容。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| seg_id | INTEGER | PRIMARY KEY | 段标识（外键引用 segments.seg_id） |
| content | BLOB | | 原始字节数据 |

---

### basic_blocks

函数的基本块（Basic Block）信息。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| block_id | INTEGER | PRIMARY KEY AUTOINCREMENT | 基本块唯一标识 |
| function_va | INTEGER | | 所属函数地址 |
| start_va | INTEGER | | 块起始地址 |
| end_va | INTEGER | | 块结束地址 |
| type | INTEGER | | 块类型（普通块、入口块、退出块等） |

---

### basic_block_successors

基本块的后继关系，用于构建控制流图。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| src_block_id | INTEGER | PRIMARY KEY | 源基本块ID |
| dst_block_id | INTEGER | PRIMARY KEY | 目标基本块ID |

---

### instructions

单条指令的反汇编信息。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| address | INTEGER | PRIMARY KEY | 指令地址 |
| mnemonic | TEXT | | 指令助记符（如 mov, add） |
| size | INTEGER | | 指令长度（字节） |
| sp_delta | INTEGER | | 栈指针变化量 |

---

### instruction_operands

指令操作数详情。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| address | INTEGER | PRIMARY KEY | 指令地址 |
| op_index | INTEGER | PRIMARY KEY | 操作数索引（从0开始） |
| type | INTEGER | | 操作数类型（寄存器、立即数、内存等） |
| value | TEXT | | 操作数值（结构化表示） |
| text | TEXT | | 操作数文本表示 |

---

## 数据访问

推荐使用 `DbLoader` 类访问 BinaryDB：

```python
from aida_cli.aida_emu.db_loader import DatabaseLoader

db = DatabaseLoader(project_path)
functions = db.load_functions()
imports = db.get_imports()
```

---

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| 1.0.0 | 2025-02 | 初始版本 |
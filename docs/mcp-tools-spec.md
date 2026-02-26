# MCP 工具接口规范

本文档描述 AIDA-CLI 通过 MCP（Model Context Protocol）提供的工具接口。

## 基础信息

- **MCP 端点**: `POST /mcp`
- **协议**: JSON-RPC 2.0
- **可用工具列表**: `GET /api/v1/mcp/tools`

### 请求格式

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "工具名称",
        "arguments": {
            "参数名": "参数值"
        }
    }
}
```

### 响应格式

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "content": [
            {
                "type": "text",
                "text": "工具返回结果（JSON 字符串）"
            }
        ]
    }
}
```

---

## 工具总览

### 项目级工具
| 工具名称 | 说明 |
|----------|------|
| get_project_overview | 获取项目概览 |
| get_project_binaries | 列出项目中的二进制文件 |

### 二进制元数据工具
| 工具名称 | 说明 |
|----------|------|
| get_binary_metadata | 获取二进制元数据 |
| list_binary_symbols | 列出符号 |
| resolve_address | 解析地址 |
| resolve_symbol | 解析符号名 |

### 代码分析工具
| 工具名称 | 说明 |
|----------|------|
| list_binary_functions | 列出函数 |
| get_binary_function_by_name | 按名称查找函数 |
| get_binary_function_by_address | 按地址查找函数 |
| get_binary_function_pseudocode_by_address | 获取函数伪代码 |
| get_binary_function_callees | 获取被调用函数 |
| get_binary_function_callers | 获取调用者函数 |
| get_binary_function_callsites | 获取调用点 |

### 反汇编工具
| 工具名称 | 说明 |
|----------|------|
| get_binary_disassembly_text | 获取地址范围反汇编 |
| get_binary_function_disassembly_text | 获取函数反汇编 |
| get_binary_disassembly_context | 获取地址上下文反汇编 |

### 数据检查工具
| 工具名称 | 说明 |
|----------|------|
| get_binary_decoded_data | 解码原始数据 |

### 字符串工具
| 工具名称 | 说明 |
|----------|------|
| list_binary_strings | 列出字符串 |
| search_string_symbol_in_binary | 在单文件中搜索字符串 |
| search_strings_in_project | 在项目中搜索字符串 |

### 导入导出工具
| 工具名称 | 说明 |
|----------|------|
| list_binary_imports | 列出导入表 |
| list_binary_exports | 列出导出表 |

### 交叉引用工具
| 工具名称 | 说明 |
|----------|------|
| get_binary_cross_references | 获取交叉引用 |

### 项目搜索工具
| 工具名称 | 说明 |
|----------|------|
| search_functions_in_project | 在项目中搜索函数 |
| search_exported_function_in_project | 在项目中搜索导出函数 |

### 审计工具 - 笔记
| 工具名称 | 说明 |
|----------|------|
| audit_create_note | 创建笔记 |
| audit_get_notes | 获取笔记列表 |
| audit_update_note | 更新笔记 |
| audit_delete_note | 删除笔记 |

### 审计工具 - 漏洞
| 工具名称 | 说明 |
|----------|------|
| audit_report_vulnerability | 报告漏洞 |
| audit_get_vulnerabilities | 获取漏洞列表 |
| audit_get_analysis_progress | 获取分析进度 |
| audit_report_vulnerability_verification | 更新漏洞验证状态 |

### 审计工具 - 计划与任务
| 工具名称 | 说明 |
|----------|------|
| audit_create_macro_plan | 创建审计计划 |
| audit_update_macro_plan | 更新审计计划 |
| audit_list_macro_plans | 列出审计计划 |
| audit_delete_macro_plan | 删除审计计划 |
| audit_create_agent_task | 创建审计任务 |
| audit_update_agent_task | 更新任务 |
| audit_list_agent_tasks | 列出审计任务 |
| audit_delete_agent_task | 删除审计任务 |
| audit_submit_agent_task_summary | 提交任务摘要 |
| audit_get_agent_task_summary | 获取任务摘要 |

---

## 未启用的工具

以下工具在代码中存在但未通过 `@mcp_tool` 装饰器注册，因此不可通过 MCP 调用：

| 工具名称 | 说明 | 状态 |
|----------|------|------|
| list_binary_sections | 列出节区 | 已注释 |
| list_binary_segments | 列出段 | 已注释 |
| get_binary_bytes | 获取原始字节 | 已注释 |
| search_immediates_in_binary | 搜索立即数 | 已注释 |
| search_bytes_pattern_in_binary | 搜索字节模式 | 已注释 |

---

## 详细工具定义

### get_project_overview

获取项目的高层概览信息。

**参数**: 无

**返回**:
```json
{
    "binaries_count": 5,
    "capabilities": {
        "disassembly": true,
        "decompilation": true,
        "xrefs": true
    }
}
```

---

### get_project_binaries

列出项目中的二进制文件。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| offset | int | 否 | 偏移量，默认 0 |
| limit | int | 否 | 限制数量，默认 50 |
| detail | bool | 否 | 是否返回详细信息，默认 false |
| filters | dict | 否 | 过滤条件 |

---

### get_binary_metadata

获取二进制文件的详细元数据。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |

**返回**: 包含架构、入口点、文件格式等信息的字典。

---

### list_binary_symbols

搜索和列出二进制中的符号。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| query | string | 否 | 搜索关键词 |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |

---

### resolve_address

解析内存地址的上下文信息。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| address | string/int | 是 | 内存地址，十六进制字符串（如 "0x401000"）或整数 |

**返回**:
```json
{
    "function": "main",
    "segment": ".text",
    "symbol": "main"
}
```

---

### resolve_symbol

将符号名解析为地址和详细信息。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| symbol_name | string | 是 | 符号名称 |

---

### list_binary_functions

列出二进制中的函数。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| query | string | 否 | 函数名搜索关键词 |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |
| filters | dict | 否 | 过滤条件 |

---

### get_binary_function_by_name

按名称查找函数。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| names | string/string[] | 是 | 函数名或函数名列表 |
| match | string | 否 | 匹配策略：exact, contains, regex |

---

### get_binary_function_by_address

按地址查找函数。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| addresses | string/int/int[] | 是 | 函数地址，支持单值或列表 |

---

### get_binary_function_pseudocode_by_address

反编译函数为 C 风格伪代码。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| addresses | string/int/int[] | 是 | 函数地址 |
| options | dict | 否 | 反编译选项：max_lines, start_line, end_line |

**返回**:
```json
[
    {
        "address": "0x401000",
        "pseudocode": "int main() {\n    ...",
        "total_lines": 45
    }
]
```

---

### get_binary_function_callees

获取函数调用的子函数。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| function_address | string/int | 是 | 函数地址 |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |

---

### get_binary_function_callers

获取调用该函数的函数。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| function_address | string/int | 是 | 函数地址 |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |

---

### get_binary_function_callsites

获取函数被调用的所有位置。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| function_address | string/int | 是 | 函数地址 |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |

---

### get_binary_cross_references

获取地址的交叉引用（入和出）。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| address | string/int | 是 | 内存地址 |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |
| detail | bool | 否 | 是否返回详细列表，默认 false |

**返回**:
```json
{
    "to": [...],
    "from": [...]
}
```

---

### get_binary_disassembly_text

获取地址范围的汇编代码。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| start_address | string/int | 是 | 起始地址 |
| end_address | string/int | 是 | 结束地址 |

---

### get_binary_function_disassembly_text

获取函数的完整汇编代码。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| function_address | string/int | 是 | 函数地址 |

---

### get_binary_disassembly_context

获取地址周围的汇编上下文。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| address | string/int | 是 | 中心地址 |
| context_lines | int | 否 | 上下文行数，默认 10 |

---

### get_binary_decoded_data

解码原始字节为结构化数据。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| address | string/int | 是 | 起始地址 |
| length | int | 是 | 字节数 |

---

### list_binary_strings

列出二进制中的字符串。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| query | string | 否 | 搜索关键词 |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |

---

### search_string_in_binary

在单文件中搜索字符串。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| search_string | string | 是 | 搜索字符串 |
| match | string | 否 | 匹配策略：contains, exact, regex |

---

### search_strings_in_project

在整个项目中搜索字符串。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| search_string | string | 是 | 搜索字符串 |
| match | string | 否 | 匹配策略 |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |

---

### list_binary_imports

列出导入表。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |

---

### list_binary_exports

列出导出表。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| query | string | 否 | 搜索关键词 |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |

---

### search_functions_in_project

在项目中搜索函数。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| function_name | string | 是 | 函数名 |
| match | string | 否 | 匹配策略：contains, exact, regex |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |

---

### search_exported_function_in_project

在项目中搜索导出函数。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| function_name | string | 是 | 导出函数名 |
| match | string | 否 | 匹配策略：exact, contains, regex |
| offset | int | 否 | 偏移量 |
| limit | int | 否 | 限制数量，默认 50 |

---

## 审计工具详细定义

### audit_create_note

创建分析笔记。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| content | string | 是 | 笔记内容 |
| note_type | string | 是 | 笔记类型：vulnerability, behavior, function_summary, data_structure, control_flow, crypto_usage, obfuscation, io_operation, general |
| title | string | 否 | 标题 |
| function_name | string | 否 | 关联函数名 |
| address | string/int | 否 | 关联地址 |
| tags | string | 否 | 标签（逗号分隔） |
| confidence | string | 否 | 置信度：high, medium, low, speculative，默认 medium |

---

### audit_get_notes

查询笔记。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 否 | 二进制文件名过滤 |
| query | string | 否 | 搜索关键词 |
| note_type | string | 否 | 笔记类型过滤 |
| tags | string | 否 | 标签过滤 |
| limit | int | 否 | 限制数量，默认 50 |

---

### audit_update_note

更新笔记。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| note_id | int | 是 | 笔记 ID |
| content | string | 否 | 新内容 |
| title | string | 否 | 新标题 |
| tags | string | 否 | 新标签 |

---

### audit_delete_note

删除笔记。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| note_id | int | 是 | 笔记 ID |

---

### audit_report_vulnerability

报告安全漏洞。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |
| severity | string | 是 | 严重程度：critical, high, medium, low, info |
| category | string | 是 | 漏洞类别：buffer_overflow, format_string, integer_overflow, use_after_free, double_free, memory_disclosure, crypto_weak, hardcoded_secret, injection, path_traversal, authentication, authorization, anti_debug, anti_vm, packing, other |
| title | string | 是 | 漏洞标题 |
| description | string | 是 | 漏洞描述 |
| function_name | string | 否 | 关联函数名 |
| address | string/int | 否 | 关联地址 |
| evidence | string | 否 | 证据/PoC |
| cvss | float | 否 | CVSS 评分 (0.0-10.0) |
| exploitability | string | 否 | 可利用性评估 |

---

### audit_get_vulnerabilities

查询漏洞。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 否 | 二进制文件名过滤 |
| severity | string | 否 | 严重程度过滤 |
| category | string | 否 | 漏洞类别过滤 |
| verification_status | string | 否 | 验证状态：unverified, confirmed, false_positive, needs_review, inconclusive |

---

### audit_get_analysis_progress

获取分析进度统计。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制文件名 |

---

### audit_report_vulnerability_verification

更新漏洞验证状态。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| id | int | 是 | 漏洞 ID |
| status | string | 是 | 验证状态：confirmed, rejected, needs_review, inconclusive |
| details | string | 否 | 详情说明 |

---

### audit_create_macro_plan

创建审计计划。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| title | string | 是 | 计划标题 |
| description | string | 是 | 计划描述 |

---

### audit_update_macro_plan

更新审计计划。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| plan_id | int | 是 | 计划 ID |
| notes | string | 否 | 备注内容 |

---

### audit_list_macro_plans

列出审计计划。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| status | string | 否 | 状态过滤：pending, in_progress, completed, failed |

---

### audit_delete_macro_plan

删除审计计划。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| plan_id | int | 是 | 计划 ID |

---

### audit_create_agent_task

创建审计任务。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| title | string | 是 | 任务标题 |
| description | string | 是 | 任务描述 |
| plan_id | int | 是 | 所属计划 ID |
| binary_name | string | 是 | 目标二进制文件 |
| task_type | string | 否 | 任务类型：ANALYSIS, VERIFICATION，默认 ANALYSIS |

---

### audit_update_agent_task

更新审计任务。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| task_id | int | 是 | 任务 ID |
| notes | string | 否 | 备注内容 |

---

### audit_list_agent_tasks

列出审计任务。

**参数**: 无

---

### audit_delete_agent_task

删除审计任务。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| task_id | int | 是 | 任务 ID |

---

### audit_submit_agent_task_summary

提交任务摘要。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| task_id | int | 是 | 任务 ID |
| summary | string | 是 | 摘要内容 |

---

### audit_get_agent_task_summary

获取任务摘要。

**参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| task_id | int | 是 | 任务 ID |

---

## 错误处理

MCP 工具调用失败时，返回的错误格式：

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "error": {
        "code": -32603,
        "message": "Internal error: ...",
        "data": {}
    }
}
```

常见错误码：
| 错误码 | 说明 |
|--------|------|
| -32600 | 无效请求 |
| -32602 | 无效参数 |
| -32603 | 内部错误 |
| -32000 | 服务器未初始化 |
| -32001 | 资源未找到 |
| -32002 | 不支持的操作 |
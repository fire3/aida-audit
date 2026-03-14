# REST API 规范

本文档描述 AIDA-AUDIT 服务提供的 REST API 接口。服务基于 FastAPI 构建，同时支持 REST 和 MCP（JSON-RPC 2.0）协议。

## 基础信息

- **Base URL**: `http://localhost:8000`
- **API 前缀**: `/api/v1`（通过 `api_router` 挂载）
- **响应格式**: JSON
- **认证**: 当前版本无认证

---

## 端点总览

### 配置接口
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/v1/config | 获取 LLM 配置 |
| POST | /api/v1/config | 更新 LLM 配置 |
| POST | /api/v1/config/validate | 验证 LLM 配置 |
| GET | /api/v1/config/user-prompt | 获取用户提示词 |
| POST | /api/v1/config/user-prompt | 更新用户提示词 |
| GET | /api/v1/config/report-language | 获取报告语言 |
| POST | /api/v1/config/report-language | 设置报告语言 |

### MCP 接口
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/v1/mcp/tools | 获取可用 MCP 工具列表 |

### 项目接口
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/v1/project | 获取项目概览 |
| GET | /api/v1/project/binaries | 列出项目中的二进制文件 |
| GET | /api/v1/project/search/exports | 搜索导出函数 |
| GET | /api/v1/project/search/functions | 搜索函数 |
| GET | /api/v1/project/search/strings | 搜索字符串 |

### 二进制分析接口
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/v1/binary/{binary_name} | 获取二进制元数据 |
| GET | /api/v1/binary/{binary_name}/sections | 列出节区 |
| GET | /api/v1/binary/{binary_name}/segments | 列出段 |
| GET | /api/v1/binary/{binary_name}/functions | 列出函数 |
| GET | /api/v1/binary/{binary_name}/symbols | 列出符号 |
| GET | /api/v1/binary/{binary_name}/strings | 列出字符串 |
| GET | /api/v1/binary/{binary_name}/imports | 列出导入表 |
| GET | /api/v1/binary/{binary_name}/exports | 列出导出表 |
| GET | /api/v1/binary/{binary_name}/disassembly | 获取反汇编 |
| GET | /api/v1/binary/{binary_name}/function/{address}/disassembly | 获取函数反汇编 |
| GET | /api/v1/binary/{binary_name}/address/{address}/disassembly | 获取地址上下文反汇编 |
| GET | /api/v1/binary/{binary_name}/function/{address}/pseudocode | 获取函数伪代码 |
| GET | /api/v1/binary/{binary_name}/bytes | 获取原始字节 |
| GET | /api/v1/binary/{binary_name}/address/{address} | 解析地址 |
| GET | /api/v1/binary/{binary_name}/function/{address}/callers | 获取调用者 |
| GET | /api/v1/binary/{binary_name}/function/{address}/callsites | 获取调用点 |
| GET | /api/v1/binary/{binary_name}/function/{address}/callees | 获取被调用函数 |
| GET | /api/v1/binary/{binary_name}/xrefs/to/{address} | 获取对地址的引用 |
| GET | /api/v1/binary/{binary_name}/xrefs/from/{address} | 获取地址发出的引用 |
| GET | /api/v1/binary/{binary_name}/xrefs/{address} | 获取所有引用 |
| GET | /api/v1/binary/{binary_name}/analysis-progress | 获取分析进度 |

### 笔记接口
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/v1/notes | 获取笔记列表 |
| POST | /api/v1/notes | 创建笔记 |
| PUT | /api/v1/notes/{note_id} | 更新笔记 |
| DELETE | /api/v1/notes/{note_id} | 删除笔记 |

### 漏洞接口
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/v1/findings | 获取漏洞列表 |
| POST | /api/v1/findings | 报告漏洞 |

### 审计接口
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/v1/audit/macro-plans | 获取审计计划 |
| POST | /api/v1/audit/macro-plans | 创建审计计划 |
| GET | /api/v1/audit/tasks | 获取审计任务 |
| POST | /api/v1/audit/tasks | 创建审计任务 |
| GET | /api/v1/audit/task/{task_id} | 获取任务详情 |
| GET | /api/v1/audit/logs | 获取审计日志 |
| GET | /api/v1/audit/messages | 获取审计消息 |
| GET | /api/v1/audit/stream/{session_id} | SSE 流式消息 |
| GET | /api/v1/audit/sessions | 获取会话列表 |
| GET | /api/v1/audit/notes | 获取审计笔记 |
| GET | /api/v1/audit/findings | 获取审计漏洞 |
| GET | /api/v1/audit/status | 获取审计状态 |
| GET | /api/v1/audit/schedule | 获取审计调度配置 |
| POST | /api/v1/audit/schedule | 更新审计调度配置 |
| POST | /api/v1/audit/start | 启动审计服务 |
| POST | /api/v1/audit/stop | 停止审计服务 |

---

## 详细接口定义

### 配置接口

#### 获取 LLM 配置

```
GET /api/v1/config
```

响应：
```json
{
    "base_url": "https://api.openai.com/v1",
    "api_key": "sk-****abcd",
    "model": "gpt-4o"
}
```

#### 更新 LLM 配置

```
POST /api/v1/config
```

请求体：
```json
{
    "base_url": "https://api.openai.com/v1",
    "api_key": "sk-xxxx",
    "model": "gpt-4o"
}
```

#### 验证 LLM 配置

```
POST /api/v1/config/validate
```

请求体：
```json
{
    "base_url": "https://api.openai.com/v1",
    "api_key": "sk-xxxx",
    "model": "gpt-4o"
}
```

响应：
```json
{
    "valid": true,
    "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"]
}
```

#### 获取/设置用户提示词

```
GET /api/v1/config/user-prompt
POST /api/v1/config/user-prompt
```

POST 请求体：
```json
{
    "content": "自定义提示词内容..."
}
```

#### 获取/设置报告语言

```
GET /api/v1/config/report-language
POST /api/v1/config/report-language
```

POST 请求体：
```json
{
    "language": "en"
}
```

---

### 项目接口

#### 获取项目概览

```
GET /api/v1/project
```

#### 列出二进制文件

```
GET /api/v1/project/binaries?offset=0&limit=50&detail=true
```

查询参数：
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| offset | int | 0 | 偏移量 |
| limit | int | 50 | 限制数量 |
| detail | bool | false | 是否返回详细信息 |

#### 搜索导出函数

```
GET /api/v1/project/search/exports?function_name=main&match=exact&offset=0&limit=50
```

查询参数：
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| function_name | string | - | 函数名（必填） |
| match | string | "exact" | 匹配方式：exact, contains |
| offset | int | 0 | 偏移量 |
| limit | int | 50 | 限制数量 |

#### 搜索函数

```
GET /api/v1/project/search/functions?function_name=strcpy&match=contains
```

#### 搜索字符串

```
GET /api/v1/project/search/strings?query=password&match=contains
```

---

### 二进制分析接口

#### 获取二进制元数据

```
GET /api/v1/binary/{binary_name}
```

#### 列出节区

```
GET /api/v1/binary/{binary_name}/sections
```

#### 列出段

```
GET /api/v1/binary/{binary_name}/segments
```

#### 列出函数

```
GET /api/v1/binary/{binary_name}/functions?query=main&offset=0&limit=50
```

#### 列出符号

```
GET /api/v1/binary/{binary_name}/symbols?query=malloc&offset=0&limit=50
```

#### 列出字符串

```
GET /api/v1/binary/{binary_name}/strings?query=http&offset=0&limit=50
```

#### 列出导入表

```
GET /api/v1/binary/{binary_name}/imports?offset=0&limit=50
```

#### 列出导出表

```
GET /api/v1/binary/{binary_name}/exports?query=init&offset=0&limit=50
```

#### 获取反汇编

```
GET /api/v1/binary/{binary_name}/disassembly?start_address=0x401000&end_address=0x401100
```

#### 获取函数反汇编

```
GET /api/v1/binary/{binary_name}/function/0x401000/disassembly
```

#### 获取地址上下文反汇编

```
GET /api/v1/binary/{binary_name}/address/0x401000/disassembly?context_lines=10
```

#### 获取函数伪代码

```
GET /api/v1/binary/{binary_name}/function/0x401000/pseudocode?max_lines=100
```

查询参数：
| 参数 | 类型 | 说明 |
|------|------|------|
| max_lines | int | 最大行数 |
| start_line | int | 起始行 |
| end_line | int | 结束行 |

#### 获取原始字节

```
GET /api/v1/binary/{binary_name}/bytes?address=0x401000&length=256&format_type=hex
```

查询参数：
| 参数 | 类型 | 说明 |
|------|------|------|
| address | string | 地址（十六进制或十进制） |
| length | int | 字节数 |
| format_type | string | 格式：hex, bin, int |

#### 解析地址

```
GET /api/v1/binary/{binary_name}/address/0x401000
```

#### 获取调用者

```
GET /api/v1/binary/{binary_name}/function/0x401000/callers
```

#### 获取调用点

```
GET /api/v1/binary/{binary_name}/function/0x401000/callsites
```

#### 获取被调用函数

```
GET /api/v1/binary/{binary_name}/function/0x401000/callees
```

#### 获取交叉引用

```
GET /api/v1/binary/{binary_name}/xrefs/to/0x401000
GET /api/v1/binary/{binary_name}/xrefs/from/0x401000
GET /api/v1/binary/{binary_name}/xrefs/0x401000
```

---

### 笔记接口

#### 获取笔记

```
GET /api/v1/notes?binary_name=app.exe&note_type=finding&limit=50
```

#### 创建笔记

```
POST /api/v1/notes
```

请求体：
```json
{
    "binary_name": "app.exe",
    "title": "Buffer overflow found",
    "content": "详细描述...",
    "note_type": "finding",
    "function_name": "process_input",
    "address": 4198400,
    "tags": ["critical", "buffer"],
    "confidence": "high"
}
```

#### 更新笔记

```
PUT /api/v1/notes/{note_id}
```

请求体：
```json
{
    "title": "更新后的标题",
    "content": "更新后的内容",
    "tags": ["updated"]
}
```

#### 删除笔记

```
DELETE /api/v1/notes/{note_id}
```

---

### 漏洞接口

#### 获取漏洞

```
GET /api/v1/findings?binary_name=app.exe&severity=high
```

#### 报告漏洞

```
POST /api/v1/findings
```

请求体：
```json
{
    "binary_name": "app.exe",
    "title": "Stack Buffer Overflow",
    "severity": "high",
    "category": "buffer_overflow",
    "description": "在 process_input 函数中存在栈缓冲区溢出...",
    "function_name": "process_input",
    "address": 4198400,
    "evidence": "...",
    "cvss": 7.5,
    "exploitability": "high"
}
```

---

### 审计接口

#### 获取审计计划

```
GET /api/v1/audit/macro-plans?status=pending
```

#### 创建审计计划

```
POST /api/v1/audit/macro-plans
```

请求体：
```json
{
    "title": "安全审计计划",
    "description": "审计二进制文件的安全性"
}
```

#### 获取审计任务

```
GET /api/v1/audit/tasks
```

#### 创建审计任务

```
POST /api/v1/audit/tasks
```

请求体：
```json
{
    "title": "分析 main 函数",
    "description": "检查是否存在缓冲区溢出",
    "plan_id": 1,
    "binary_name": "app.exe",
    "task_type": "ANALYSIS"
}
```

#### 获取任务详情

```
GET /api/v1/audit/task/1
```

#### 获取审计日志

```
GET /api/v1/audit/logs?limit=50
```

#### 获取审计消息

```
GET /api/v1/audit/messages?session_id=xxx&limit=100
```

#### SSE 流式消息

```
GET /api/v1/audit/stream/{session_id}
```

返回 Server-Sent Events 流，用于实时显示审计过程。

#### 获取会话列表

```
GET /api/v1/audit/sessions
```

#### 获取审计状态

```
GET /api/v1/audit/status
```

响应示例：
```json
{
    "status": "running",
    "current_task": "Analyzing function main",
    "progress": 45
}
```

#### 获取/设置审计调度

```
GET /api/v1/audit/schedule
POST /api/v1/audit/schedule
```

POST 请求体：
```json
{
    "enabled": true,
    "periods": [
        {"start": "09:00", "stop": "18:00"}
    ]
}
```

#### 启动/停止审计

```
POST /api/v1/audit/start
POST /api/v1/audit/stop
```

---

## MCP 协议

除 REST API 外，服务还通过 `/mcp` 端点提供 MCP（JSON-RPC 2.0）协议支持。

### MCP 端点

```
POST /mcp
```

请求格式（JSON-RPC 2.0）：
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
}
```

响应格式：
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "tools": [...]
    }
}
```

可用 MCP 工具可通过 `GET /api/v1/mcp/tools` 获取。

---

## 错误响应

错误响应格式：
```json
{
    "detail": "错误描述"
}
```

常见 HTTP 状态码：
| 状态码 | 说明 |
|--------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 404 | 资源不存在 |
| 500 | 服务器内部错误 |
| 503 | 服务未初始化 |
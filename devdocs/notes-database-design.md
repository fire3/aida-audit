# AIDA 笔记数据库设计方案

## 1. 概述

本文档描述 AIDA-CLI 逆向分析平台的笔记数据库设计方案。该数据库用于存储 LLM 在 MCP 分析过程中创建的笔记和发现，支持与现有二进制数据库的关联查询。

### 1.1 设计目标

- 支持 LLM 在逆向分析过程中记录发现和推理
- 与导出数据库通过 `binary_name`/`function_name`/`address` 关联
- 支持多客户端并发读写（MCP + REST API）

### 1.2 数据库位置

- **路径**: `<export_dir>/../project_notes.db`
- **初始化时机**: `aida-cli export` 过程中自动创建
- **连接模式**: SQLite WAL 模式（支持并发读写）

---

## 2. 数据库表结构

### 2.1 表概览

| 表名 | 用途 | 主键 |
|------|------|------|
| `notes` | 笔记主表 | note_id |
| `tags` | 标签定义 | tag_id |
| `note_tags` | 笔记标签关联 | (note_id, tag_id) |
| `vulnerabilities` | 安全发现记录 | id |

### 2.2 详细表定义

#### 2.2.1 notes（笔记主表）

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| note_id | INTEGER | PRIMARY KEY | 笔记唯一标识 |
| binary_name | TEXT | NOT NULL | 二进制名称（必填关联） |
| function_name | TEXT | NULL | 关联的函数名 |
| address | INTEGER | NULL | 虚拟地址（VA） |
| note_type | TEXT | NOT NULL | 笔记类型 |
| content | TEXT | NOT NULL | 笔记内容 |
| confidence | TEXT | DEFAULT 'medium' | 可信度：high/medium/low/speculative |
| tags | TEXT | NULL | JSON 格式的标签数组 |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

#### 2.2.2 tags（标签表）

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| tag_id | INTEGER | PRIMARY KEY | 标签唯一标识 |
| name | TEXT | UNIQUE | 标签名称 |

#### 2.2.3 note_tags（笔记-标签关联表）

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| note_id | INTEGER | REFERENCES notes(note_id) | 笔记ID |
| tag_id | INTEGER | REFERENCES tags(tag_id) | 标签ID |
| PRIMARY KEY | (note_id, tag_id) | | 联合主键 |

#### 2.2.4 vulnerabilities（安全发现表）

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY | 发现唯一标识 |
| binary_name | TEXT | NOT NULL | 二进制名称 |
| function_name | TEXT | NULL | 关联函数 |
| address | INTEGER | NULL | 虚拟地址 |
| severity | TEXT | NOT NULL | 严重程度：critical/high/medium/low/info |
| category | TEXT | NOT NULL | 漏洞类别 |
| description | TEXT | NOT NULL | 发现描述 |
| evidence | TEXT | NULL | 证据/代码片段 |
| cvss | REAL | NULL | CVSS 评分 |
| exploitability | TEXT | NULL | 可利用性评估 |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| verification_status | TEXT | DEFAULT 'unverified' | 验证状态 |
| verification_details | TEXT | NULL | 验证详情 |

### 2.3 索引设计

```sql
CREATE INDEX idx_notes_binary ON notes(binary_name);
CREATE INDEX idx_notes_type ON notes(note_type);
CREATE INDEX idx_notes_func ON notes(function_name);
CREATE INDEX idx_vulnerabilities_binary ON vulnerabilities(binary_name);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_category ON vulnerabilities(category);
```

---

## 3. 枚举值定义

### 3.1 笔记类型（note_type）

| 类型值 | 描述 | 示例 |
|--------|------|------|
| `vulnerability` | 安全漏洞/缺陷 | 格式化字符串漏洞、缓冲区溢出 |
| `behavior` | 行为分析 | 网络通信、文件操作行为 |
| `function_summary` | 函数总结 | SSL 握手函数逻辑分析 |
| `data_structure` | 数据结构分析 | 自定义链表、结构体布局 |
| `control_flow` | 控制流分析 | 跳转指令、间接调用 |
| `crypto_usage` | 密码学使用 | AES/DES 加密调用 |
| `obfuscation` | 混淆/反分析 | 反调试、花指令 |
| `io_operation` | 输入输出操作 | 文件/注册表/套接字操作 |
| `general` | 通用笔记 | 其他分析记录 |

### 3.2 漏洞类别（finding.category）

| 类别值 | 描述 |
|--------|------|
| `buffer_overflow` | 缓冲区溢出 |
| `format_string` | 格式化字符串 |
| `integer_overflow` | 整数溢出 |
| `use_after_free` | UAF 漏洞 |
| `double_free` | 双重释放 |
| `memory_disclosure` | 内存泄露 |
| `crypto_weak` | 弱密码学 |
| `hardcoded_secret` | 硬编码密钥 |
| `injection` | 代码注入 |
| `path_traversal` | 路径遍历 |
| `authentication` | 认证问题 |
| `authorization` | 授权问题 |
| `anti_debug` | 反调试技术 |
| `anti_vm` | 反虚拟机技术 |
| `packing` | 加壳/混淆 |
| `other` | 其他 |

### 3.3 严重程度（severity）

| 等级 | 描述 |
|------|------|
| `critical` | 远程代码执行等严重漏洞 |
| `high` | 本地提权、信息泄露等 |
| `medium` | 拒绝服务、条件竞争等 |
| `low` | 信息披露、轻微问题 |
| `info` | 信息性发现，非漏洞 |

### 3.4 可信度（confidence）

| 等级 | 描述 |
|------|------|
| `high` | 已确认，经过验证 |
| `medium` | 高概率，需要进一步确认 |
| `low` | 可能存在，需人工确认 |
| `speculative` | 推测性发现 |

### 3.5 预定义标签（tags）

| 标签名 | 描述 |
|--------|------|
| `security` | 安全相关 |
| `performance` | 性能相关 |
| `reliability` | 可靠性相关 |
| `priority-high` | 高优先级 |
| `priority-medium` | 中优先级 |
| `priority-low` | 低优先级 |
| `confirmed` | 已确认 |
| `suspected` | 可疑 |
| `needs-review` | 需要审查 |
| `anti-debug` | 反调试 |
| `anti-vm` | 反虚拟机 |
| `obfuscation` | 混淆 |
| `network` | 网络相关 |
| `file-io` | 文件 IO |
| `process` | 进程相关 |
| `crypto` | 密码学相关 |

---

## 4. MCP 工具接口

### 4.1 工具列表

| 工具名 | 功能 | 读写类型 |
|--------|------|----------|
| `create_note` | 创建笔记 | 写 |
| `get_notes` | 查询笔记 | 读 |
| `update_note` | 更新笔记 | 写 |
| `delete_note` | 删除笔记 | 写 |
| `mark_finding` | 标记安全发现 | 写 |
| `get_findings` | 查询安全发现 | 读 |
| `get_analysis_progress` | 获取分析进度 | 读 |

### 4.2 工具详细定义

#### 4.2.1 create_note

创建一条笔记。

**参数**:
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制名称 |
| content | string | 是 | 笔记内容 |
| note_type | string | 是 | 笔记类型 |
| function_name | string | 否 | 关联的函数名 |
| address | integer | 否 | 虚拟地址（十六进制或十进制） |
| tags | string | 否 | 逗号分隔的标签列表 |
| confidence | string | 否 | 可信度，默认为 medium |

**返回值**:
```json
{
  "note_id": 123
}
```

#### 4.2.2 get_notes

查询笔记列表。

**参数**:
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| binary_name | string | 否 | 二进制名称过滤 |
| query | string | 否 | 内容搜索关键词 |
| note_type | string | 否 | 笔记类型过滤 |
| tags | string | 否 | 逗号分隔的标签过滤 |
| limit | integer | 否 | 返回数量限制，默认 50 |

**返回值**:
笔记对象数组，每项包含 note_id, binary_name, function_name, address, note_type, content, confidence, tags, created_at, updated_at。

#### 4.2.3 update_note

更新笔记内容或标签。

**参数**:
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| note_id | integer | 是 | 要更新的笔记 ID |
| content | string | 否 | 新的笔记内容 |
| tags | string | 否 | 新的标签列表（逗号分隔） |

**返回值**:
```json
{
  "success": true
}
```

#### 4.2.4 delete_note

删除笔记。

**参数**:
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| note_id | integer | 是 | 要删除的笔记 ID |

**返回值**:
```json
{
  "success": true
}
```

#### 4.2.5 mark_finding

标记一个安全发现。

**参数**:
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制名称 |
| address | integer | 否 | 虚拟地址 |
| function_name | string | 否 | 关联函数名 |
| severity | string | 是 | 严重程度 |
| category | string | 是 | 漏洞类别 |
| description | string | 是 | 发现描述 |
| evidence | string | 否 | 证据代码片段 |
| cvss | number | 否 | CVSS 评分 |

**返回值**:
```json
{
  "id": 45,
  "note_id": 123
}
```

#### 4.2.6 get_findings

查询安全发现列表。

**参数**:
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| binary_name | string | 否 | 二进制名称过滤 |
| severity | string | 否 | 严重程度过滤 |
| category | string | 否 | 漏洞类别过滤 |

**返回值**:
发现对象数组，每项包含 id, note_id, binary_name, function_name, address, severity, category, description, cvss, created_at。

#### 4.2.7 get_analysis_progress

获取指定二进制的分析进度统计。

**参数**:
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| binary_name | string | 是 | 二进制名称 |

**返回值**:
```json
{
  "binary_name": "httpd",
  "total_notes": 15,
  "notes_by_type": {
    "vulnerability": 3,
    "function_summary": 5,
    "behavior": 4,
    "general": 3
  },
  "findings_count": 3,
  "findings_by_severity": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0,
    "info": 0
  }
}
```

---

## 5. 实现架构

### 5.1 文件结构

```
backend/aida_cli/
├── notes_database.py      # 笔记数据库类（CRUD 操作）
├── notes_mcp_tools.py     # MCP 工具函数实现
├── export_cmd.py          # 修改：添加数据库初始化
├── mcp_service.py         # 修改：注册笔记工具
└── server_cmd.py          # 修改：服务启动配置
```

### 5.2 类设计

```
NotesDatabase
├── create_schema()                    # 创建数据库 schema
├── create_note(...) -> int            # 创建笔记
├── get_notes(...) -> list             # 查询笔记
├── update_note(...) -> bool           # 更新笔记
├── delete_note(...) -> bool           # 删除笔记
├── create_finding(...) -> int         # 创建安全发现
├── get_findings(...) -> list          # 查询安全发现
└── get_statistics(...) -> dict        # 获取统计信息
```

### 5.3 并发处理

- **数据库连接模式**: WAL（Write-Ahead Logging）
- **忙等待超时**: 30 秒

---

## 6. 版本历史

| 版本 | 日期 | 描述 |
|------|------|------|
| 1.1 | 2026-02-15 | 移除会话相关表，简化设计 |
| 1.0 | 2026-02-15 | 初始设计 |
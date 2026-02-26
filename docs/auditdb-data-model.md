# AuditDB 数据模型规范

AuditDB 是 AIDA-CLI 用于存储安全审计工作数据的 SQLite 数据库。用于记录审计计划、任务、笔记、漏洞发现和审计会话等。

## 数据库文件

- **文件名**: `audit.db`
- **位置**: 项目目录下
- **创建方式**: 首次访问时自动创建（通过 `AuditDatabase` 类）

---

## 表结构总览

| 表名 | 用途 | 主键 |
|------|------|------|
| [tags](#tags) | 标签定义 | tag_id |
| [notes](#notes) | 审计笔记 | note_id |
| [note_tags](#note_tags) | 笔记-标签关联 | (复合主键) |
| [vulnerabilities](#vulnerabilities) | 漏洞记录 | id |
| [plans](#plans) | 审计计划 | id |
| [tasks](#tasks) | 审计任务 | id |
| [audit_logs](#audit_logs) | 审计日志 | id |
| [audit_messages](#audit_messages) | 审计会话消息 | id |
| [system_config](#system_config) | 系统配置 | key |

---

## 详细表定义

### tags

标签定义，用于对笔记进行分类。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| tag_id | INTEGER | PRIMARY KEY AUTOINCREMENT | 标签唯一标识 |
| name | TEXT | UNIQUE, NOT NULL | 标签名称 |

---

### notes

审计笔记，记录分析过程中的发现和注释。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| note_id | INTEGER | PRIMARY KEY AUTOINCREMENT | 笔记唯一标识 |
| binary_name | TEXT | NOT NULL | 所属二进制文件名 |
| title | TEXT | | 笔记标题 |
| function_name | TEXT | | 关联函数名 |
| address | INTEGER | | 关联地址 |
| note_type | TEXT | NOT NULL | 笔记类型 |
| content | TEXT | NOT NULL | 笔记内容 |
| confidence | TEXT | DEFAULT 'medium' | 置信度 |
| tags | TEXT | | 标签列表（JSON数组） |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

#### note_type 取值

| 值 | 说明 |
|----|------|
| vulnerability | 漏洞相关 |
| behavior | 行为分析 |
| function_summary | 函数总结 |
| data_structure | 数据结构 |
| control_flow | 控制流 |
| crypto_usage | 加密使用 |
| obfuscation | 代码混淆 |
| io_operation | IO操作 |
| general | 通用 |

#### confidence 取值

| 值 | 说明 |
|----|------|
| high | 高置信度 |
| medium | 中置信度 |
| low | 低置信度 |
| speculative | 推测性 |

---

### note_tags

笔记与标签的多对多关联表。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| note_id | INTEGER | PRIMARY KEY | 笔记ID（外键） |
| tag_id | INTEGER | PRIMARY KEY | 标签ID（外键） |

---

### vulnerabilities

漏洞记录表，记录安全审计中发现的漏洞。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 漏洞唯一标识 |
| binary_name | TEXT | NOT NULL | 所属二进制文件名 |
| title | TEXT | | 漏洞标题 |
| function_name | TEXT | | 关联函数名 |
| address | INTEGER | | 关联地址 |
| severity | TEXT | NOT NULL | 严重程度 |
| category | TEXT | NOT NULL | 漏洞类别 |
| description | TEXT | NOT NULL | 漏洞描述 |
| evidence | TEXT | | 漏洞证据/PoC |
| cvss | REAL | | CVSS评分 |
| exploitability | TEXT | | 可利用性评估 |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| verification_status | TEXT | DEFAULT 'unverified' | 验证状态 |
| verification_details | TEXT | | 验证详情 |

#### severity 取值

| 值 | 说明 | 建议处理 |
|----|------|----------|
| critical | 严重 | 立即处理 |
| high | 高 | 优先处理 |
| medium | 中 | 计划处理 |
| low | 低 | 后续处理 |
| info | 信息 | 记录即可 |

#### category 取值

| 值 | 说明 |
|----|------|
| buffer_overflow | 缓冲区溢出 |
| format_string | 格式化字符串 |
| integer_overflow | 整数溢出 |
| use_after_free | Use-After-Free |
| double_free | 双重释放 |
| memory_disclosure | 内存泄露 |
| crypto_weak | 弱加密 |
| hardcoded_secret | 硬编码密钥 |
| injection | 注入类 |
| path_traversal | 路径遍历 |
| authentication | 认证问题 |
| authorization | 授权问题 |
| anti_debug | 反调试 |
| anti_vm | 反虚拟机 |
| packing | 加壳/混淆 |
| other | 其他 |

#### verification_status 取值

| 值 | 说明 |
|----|------|
| unverified | 未验证 |
| confirmed | 已确认 |
| false_positive | 误报 |
| mitigated | 已缓解 |

---

### plans

审计计划表，用于组织和管理审计任务。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 计划唯一标识 |
| title | TEXT | NOT NULL | 计划标题 |
| description | TEXT | | 计划描述 |
| status | TEXT | DEFAULT 'pending' | 计划状态 |
| created_at | INTEGER | | 创建时间戳 |
| updated_at | INTEGER | | 更新时间戳 |
| notes | TEXT | | 备注 |

#### status 取值

| 值 | 说明 |
|----|------|
| pending | 待处理 |
| in_progress | 进行中 |
| completed | 已完成 |
| cancelled | 已取消 |

---

### tasks

审计任务表， Plans 下的具体执行任务。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 任务唯一标识 |
| plan_id | INTEGER | | 所属计划ID（外键） |
| title | TEXT | NOT NULL | 任务标题 |
| description | TEXT | | 任务描述 |
| status | TEXT | DEFAULT 'pending' | 任务状态 |
| created_at | INTEGER | | 创建时间戳 |
| updated_at | INTEGER | | 更新时间戳 |
| binary_name | TEXT | | 目标二进制文件 |
| task_type | TEXT | DEFAULT 'ANALYSIS' | 任务类型 |
| summary | TEXT | | 任务摘要 |
| notes | TEXT | | 备注 |

#### task_type 取值

| 值 | 说明 |
|----|------|
| ANALYSIS | 分析任务 |
| VERIFICATION | 验证任务 |
| DOCUMENTATION | 文档任务 |
| REVIEW | 审查任务 |

---

### audit_logs

审计日志，记录任务执行过程中的重要事件。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 日志唯一标识 |
| plan_id | INTEGER | | 关联计划ID |
| task_id | INTEGER | | 关联任务ID |
| message | TEXT | NOT NULL | 日志消息 |
| timestamp | INTEGER | | 时间戳 |

---

### audit_messages

审计会话消息，存储 AI 审计代理的对话历史。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 消息唯一标识 |
| session_id | TEXT | NOT NULL | 会话ID |
| role | TEXT | NOT NULL | 消息角色 |
| content | TEXT | NOT NULL | 消息内容 |
| timestamp | INTEGER | | 时间戳 |

#### role 取值

| 值 | 说明 |
|----|------|
| system | 系统消息 |
| user | 用户消息 |
| assistant | AI助手消息 |

---

### system_config

系统配置表，存储应用级配置。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| key | TEXT | PRIMARY KEY | 配置键 |
| value | TEXT | | 配置值 |
| updated_at | INTEGER | | 更新时间戳 |

---

## 数据访问

推荐使用 `AuditDatabase` 类访问 AuditDB：

```python
from aida_cli.audit_database import AuditDatabase

audit_db = AuditDatabase(project_path)

# 添加漏洞记录
vuln_id = audit_db.add_vulnerability(
    binary_name="app.exe",
    title="Stack Buffer Overflow",
    severity="high",
    category="buffer_overflow",
    description="..."
)

# 添加笔记
note_id = audit_db.add_note(
    binary_name="app.exe",
    note_type="function_summary",
    content="..."
)
```

---

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| 1.0.0 | 2025-02 | 初始版本 |
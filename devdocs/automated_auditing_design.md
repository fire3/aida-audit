# Automated Code Auditing System Design with OpenCode & MCP

## 1. Overview
This document outlines the design for an automated code auditing system driven by `aida-cli`, utilizing `opencode` as the AI agent runtime and MCP (Model Context Protocol) for tool interaction. The system aims to overcome the stateless nature of AI sessions by providing a persistent infrastructure for planning, progress tracking, memory management, and result recording.

## 2. Architecture

The system consists of three main layers:

1.  **Controller (Driver)**: A Python-based orchestration layer within `aida-cli`. It manages the lifecycle of the `opencode` server, initializes sessions, and monitors execution.
2.  **Agent Environment**: The `opencode` Server instance running with a specific configuration, connected to MCP servers.
3.  **State Management**: A persistent storage layer (SQLite) that holds the audit plan, progress logs, long-term memory, and findings. This state is exposed to the Agent via MCP tools.

### High-Level Data Flow

```
[Controller] -> (Start/Manage) -> [OpenCode Server]
                                     ^
                                     | (MCP Protocol)
                                     v
[MCP Server (AIDA)] <-> [State DB (SQLite)]
       ^
       | (Tools: Reverse Engineering)
       | (Tools: Audit Management)
[Target Binary/Code]
```

## 3. Components

### 3.1. Controller (The "Driver")
A new command `aida-cli audit <target>` will be implemented.
- **Responsibilities**:
    - Start/Stop `opencode` server.
    - Initialize the Audit State Database for the target.
    - Create/Load the System Prompt (`AGENTS.md`).
    - Start an `opencode` session via HTTP API.
    - Monitor session health and intervene if the agent gets stuck (e.g., timeout, loop detection).
    - Parse final reports.

### 3.2. State Management (Audit Database)
A SQLite database (`audit.db`) separate from the project data, or integrated into `project.db`, containing:
- **Plans**: `id`, `title`, `description`, `status` (pending, in_progress, completed, failed), `dependencies`.
- **Progress**: `id`, `timestamp`, `message`, `step_id`.
- **Memory**: `key`, `value` (JSON), `scope` (global/session).
- **Findings**: (Deprecated, use Vulnerabilities in `vulnerabilities` table).
- **Vulnerabilities**: `id`, `binary_name`, `severity`, `category`, `description`, `evidence`, `status` (unverified, confirmed, etc).

### 3.3. MCP Tools (Audit Management)
In addition to existing reverse engineering tools, we introduce **Audit Management Tools** to allow the AI to manage its own work:

- `audit_plan_add(title, description)`: Add a new task to the plan.
- `audit_plan_list(status?)`: List current tasks.
- `audit_plan_update(id, status, notes)`: Mark a task as complete or in progress.
- `audit_memory_set(key, value)`: Store a fact or context for later retrieval.
- `audit_memory_get(key)`: Retrieve stored information.
- `audit_log_progress(message)`: Log a checkpoint or decision.

### 3.4. Prompts (AGENTS.md)
A comprehensive system prompt that defines the "Auditor Persona".
- **Goal**: "You are an expert Security Auditor. Your goal is to systematically analyze the target binary/code for vulnerabilities."
- **Workflow**:
    1.  Check `audit_plan_list` to see what needs to be done.
    2.  If empty, use `audit_plan_add` to create an initial analysis plan (e.g., "Identify entry points", "Analyze main loop", "Check for CWE-78").
    3.  Execute the next pending task using RE tools (e.g., `get_function`, `decompile`).
    4.  Record findings using `audit_report_vulnerability`.
    5.  Update task status with `audit_plan_update`.
    6.  Repeat.
- **Constraints**: "Always update your plan. Do not rely on internal context for long-term memory; use `audit_memory` tools."

## 4. Workflow Example

1.  **Initialization**:
    User runs `aida-cli audit ./target_binary`.
    Controller initializes DB, starts `opencode serve`.

2.  **Session Start**:
    Controller sends initial message: "Begin audit of target_binary. Check your plan."

3.  **Agent Loop (Autonomous)**:
    - Agent calls `audit_plan_list()` -> Returns `[]`.
    - Agent thinks: "I need to start by mapping the binary."
    - Agent calls `audit_plan_add("Initial Recon", "List functions and identify main")`.
    - Agent calls `audit_plan_update(1, "in_progress")`.
    - Agent calls `list_functions()`.
    - Agent calls `audit_memory_set("entry_point", "main_0x401000")`.
    - Agent calls `audit_plan_update(1, "completed")`.

4.  **Monitoring**:
    Controller polls `opencode` API for status. If idle for too long, it might prompt "Are you stuck?".

5.  **Completion**:
    Agent marks all critical tasks as completed and generates a summary.

## 5. Implementation Plan

1.  **Define Schema**: Create `audit_db.py` with tables for `plans`, `memories`, `logs`.
2.  **Implement MCP Tools**: Add `audit_mcp_tools.py` exposing the DB operations.
3.  **Create Driver**: Implement `audit_cmd.py` to interface with `opencode`.
4.  **Draft Prompt**: Create `templates/AGENTS.md`.


import sqlite3
import json
import os
import time
from typing import List, Dict, Optional, Any

NOTE_TYPES = [
    "vulnerability",
    "behavior",
    "function_summary",
    "data_structure",
    "control_flow",
    "crypto_usage",
    "obfuscation",
    "io_operation",
    "general"
]

VULNERABILITY_CATEGORIES = [
    "buffer_overflow",
    "format_string",
    "integer_overflow",
    "use_after_free",
    "double_free",
    "memory_disclosure",
    "crypto_weak",
    "hardcoded_secret",
    "injection",
    "path_traversal",
    "authentication",
    "authorization",
    "anti_debug",
    "anti_vm",
    "packing",
    "other"
]

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

CONFIDENCE_LEVELS = ["high", "medium", "low", "speculative"]

PREDEFINED_TAGS = [
    "security", "performance", "reliability",
    "priority-high", "priority-medium", "priority-low",
    "confirmed", "suspected", "needs-review",
    "anti-debug", "anti-vm", "obfuscation",
    "network", "file-io", "process", "crypto"
]


class AuditDatabase:
    def __init__(self, db_path: str, logger=None):
        self.db_path = db_path
        self.logger = logger
        self.conn: Optional[sqlite3.Connection] = None

    def log(self, msg: str):
        if self.logger:
            self.logger.log(msg)
        else:
            print(f"[AuditDB] {msg}")

    def connect(self):
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            
        is_new = not os.path.exists(self.db_path)
        
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.create_schema()
        
        if is_new:
            self.log(f"Created audit database: {self.db_path}")
        self.log(f"Connected to audit database: {self.db_path}")

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None
            self.log("Audit database connection closed.")

    def commit(self):
        if self.conn:
            self.conn.commit()

    def create_schema(self):
        cursor = self.conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tags (
                tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                binary_name TEXT NOT NULL,
                title TEXT,
                function_name TEXT,
                address INTEGER,
                note_type TEXT NOT NULL,
                content TEXT NOT NULL,
                confidence TEXT DEFAULT 'medium',
                tags TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS note_tags (
                note_id INTEGER NOT NULL REFERENCES notes(note_id),
                tag_id INTEGER NOT NULL REFERENCES tags(tag_id),
                PRIMARY KEY (note_id, tag_id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                binary_name TEXT NOT NULL,
                title TEXT,
                function_name TEXT,
                address INTEGER,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT,
                cvss REAL,
                exploitability TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                verification_status TEXT DEFAULT 'unverified',
                verification_details TEXT
            )
        """)

        # New Plan Table (Macro Planning)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending',
                created_at INTEGER,
                updated_at INTEGER,
                notes TEXT
            )
        """)

        # New Task Table (Agent Execution Tasks)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plan_id INTEGER,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending',
                created_at INTEGER,
                updated_at INTEGER,
                binary_name TEXT,
                task_type TEXT DEFAULT 'agent_task',
                summary TEXT,
                notes TEXT,
                FOREIGN KEY(plan_id) REFERENCES plans(id)
            )
        """)

        # Updated Audit Logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plan_id INTEGER,
                task_id INTEGER,
                message TEXT NOT NULL,
                timestamp INTEGER,
                FOREIGN KEY(plan_id) REFERENCES plans(id),
                FOREIGN KEY(task_id) REFERENCES tasks(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp INTEGER
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at INTEGER
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notes_binary ON notes(binary_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notes_type ON notes(note_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notes_func ON notes(function_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_binary ON vulnerabilities(binary_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_category ON vulnerabilities(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_plans_status ON plans(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_plan ON tasks(plan_id)")

        self._ensure_tags(cursor)
        # self._ensure_columns(cursor) # Skipped as we are redesigning
        self.commit()
        self.log("Audit schema created/updated successfully.")

    def _ensure_tags(self, cursor):
        for tag in PREDEFINED_TAGS:
            cursor.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))

    def get_config(self, key: str, default: str = "") -> str:
        if not self.conn:
            return default
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM system_config WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else default

    def set_config(self, key: str, value: str):
        if not self.conn:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO system_config (key, value, updated_at) 
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """, (key, value, int(time.time())))
        self.conn.commit()

    def _parse_tags(self, tags_input: Optional[str]) -> List[str]:
        if not tags_input:
            return []
        if isinstance(tags_input, str):
            return [t.strip() for t in tags_input.split(",") if t.strip()]
        if isinstance(tags_input, list):
            return tags_input
        return []

    # ========== Plan Operations (Macro) ==========
    def create_plan(self, title: str, description: str) -> int:
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO plans (title, description, status, created_at, updated_at) VALUES (?, ?, 'pending', ?, ?)",
            (title, description, timestamp, timestamp)
        )
        self.commit()
        return cursor.lastrowid

    def update_plan_status(self, plan_id: int, status: str, notes: Optional[str] = None) -> bool:
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        if notes:
            cursor.execute(
                "UPDATE plans SET status = ?, updated_at = ?, notes = ? WHERE id = ?",
                (status, timestamp, notes, plan_id)
            )
        else:
            cursor.execute(
                "UPDATE plans SET status = ?, updated_at = ? WHERE id = ?",
                (status, timestamp, plan_id)
            )
        self.commit()
        return cursor.rowcount > 0

    def delete_plan(self, plan_id: int) -> bool:
        cursor = self.conn.cursor()
        
        # Delete related tasks
        cursor.execute("SELECT id FROM tasks WHERE plan_id = ?", (plan_id,))
        tasks = cursor.fetchall()
        for task in tasks:
            self.delete_task(task[0])
            
        # Delete related logs
        cursor.execute("DELETE FROM audit_logs WHERE plan_id = ?", (plan_id,))
        
        # Delete the plan
        cursor.execute("DELETE FROM plans WHERE id = ?", (plan_id,))
        
        self.commit()
        return cursor.rowcount > 0

    def get_plans(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT id, title, description, status, created_at, updated_at, notes FROM plans"
        conditions = []
        params = []
        
        if status:
            conditions.append("status = ?")
            params.append(status)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        columns = [column[0] for column in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    def get_plan(self, plan_id: int) -> Optional[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, title, description, status, created_at, updated_at, notes FROM plans WHERE id = ?", (plan_id,))
        row = cursor.fetchone()
        if row:
            columns = [column[0] for column in cursor.description]
            return dict(zip(columns, row))
        return None

    # ========== Task Operations (Micro) ==========
    def create_task(self, plan_id: int, title: str, description: str, binary_name: str, task_type: str = 'agent_task') -> int:
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO tasks (plan_id, title, description, status, created_at, updated_at, binary_name, task_type) VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)",
            (plan_id, title, description, timestamp, timestamp, binary_name, task_type)
        )
        self.commit()
        return cursor.lastrowid

    def update_task_status(self, task_id: int, status: str, notes: Optional[str] = None) -> bool:
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        if notes:
            cursor.execute(
                "UPDATE tasks SET status = ?, updated_at = ?, notes = ? WHERE id = ?",
                (status, timestamp, notes, task_id)
            )
        else:
            cursor.execute(
                "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                (status, timestamp, task_id)
            )
        self.commit()
        return cursor.rowcount > 0

    def update_task_summary(self, task_id: int, summary: str) -> bool:
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE tasks SET summary = ?, updated_at = ? WHERE id = ?",
            (summary, timestamp, task_id)
        )
        self.commit()
        return cursor.rowcount > 0

    def delete_task(self, task_id: int) -> bool:
        cursor = self.conn.cursor()
        
        # Delete related logs
        cursor.execute("DELETE FROM audit_logs WHERE task_id = ?", (task_id,))
        
        # Delete the task
        cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        
        self.commit()
        return cursor.rowcount > 0

    def get_tasks(self, plan_id: Optional[int] = None, status: Optional[str] = None, task_type: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT id, plan_id, title, description, status, created_at, updated_at, binary_name, task_type, summary, notes FROM tasks"
        conditions = []
        params = []
        
        if plan_id:
            conditions.append("plan_id = ?")
            params.append(plan_id)
        
        if status:
            conditions.append("status = ?")
            params.append(status)
            
        if task_type:
            conditions.append("task_type = ?")
            params.append(task_type)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        columns = [column[0] for column in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    def get_task(self, task_id: int) -> Optional[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, plan_id, title, description, status, created_at, updated_at, binary_name, task_type, summary, notes FROM tasks WHERE id = ?", (task_id,))
        row = cursor.fetchone()
        if row:
            columns = [column[0] for column in cursor.description]
            return dict(zip(columns, row))
        return None

    def reset_in_progress_tasks(self) -> int:
        """Reset all in_progress tasks to pending status."""
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE tasks SET status = 'pending', updated_at = ? WHERE status = 'in_progress'",
            (timestamp,)
        )
        count = cursor.rowcount
        self.commit()
        return count

    # ========== Log Operations ==========
    def log_progress(self, message: str, plan_id: Optional[int] = None, task_id: Optional[int] = None):
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO audit_logs (plan_id, task_id, message, timestamp) VALUES (?, ?, ?, ?)",
            (plan_id, task_id, message, timestamp)
        )
        self.commit()

    def get_logs(self, limit: int = 50, plan_id: Optional[int] = None, task_id: Optional[int] = None) -> List[Dict[str, Any]]:
        query = "SELECT id, plan_id, task_id, message, timestamp FROM audit_logs"
        conditions = []
        params = []
        
        if plan_id:
            conditions.append("plan_id = ?")
            params.append(plan_id)
            
        if task_id:
            conditions.append("task_id = ?")
            params.append(task_id)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        columns = [column[0] for column in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    # ========== Chat Session Operations ==========
    def add_message(self, session_id: str, role: str, content: str):
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO audit_messages (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
            (session_id, role, content, timestamp)
        )
        self.commit()

    def get_sessions(self) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT session_id, MIN(timestamp) as start_time, COUNT(*) as message_count 
            FROM audit_messages 
            GROUP BY session_id 
            ORDER BY start_time DESC
        """)
        columns = [column[0] for column in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    def get_messages(self, session_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        query = "SELECT id, session_id, role, content, timestamp FROM audit_messages"
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        
        query += " ORDER BY timestamp ASC, id ASC LIMIT ?"
        params.append(limit)
        
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        columns = [column[0] for column in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    # ========== Note Operations ==========
    def add_note(self, binary_name: str, note_type: str, content: str, 
                 function_name: Optional[str] = None, address: Optional[int] = None,
                 confidence: str = 'medium', tags: Optional[List[str]] = None,
                 title: Optional[str] = None) -> int:
        
        if note_type not in NOTE_TYPES:
            raise ValueError(f"Invalid note type. Must be one of {NOTE_TYPES}")
            
        timestamp = int(time.time()) # Actually schema uses DATETIME DEFAULT CURRENT_TIMESTAMP, but python sqlite adapter might expect something else or we can let DB handle it. 
        # But here we used DEFAULT CURRENT_TIMESTAMP in schema, so we can omit created_at/updated_at or pass them.
        # Let's rely on DB for timestamps or pass them if we want consistency.
        # The schema says DATETIME, so it expects a string or date object.
        # However, previous implementation might have been mixed.
        # Let's just insert the fields we have.
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO notes (binary_name, title, function_name, address, note_type, content, confidence, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (binary_name, title, function_name, address, note_type, content, confidence, json.dumps(tags) if tags else None))
        
        note_id = cursor.lastrowid
        
        # Handle tags relation if we want to search by tags efficiently
        if tags:
            for tag in tags:
                # Find tag_id
                cursor.execute("SELECT tag_id FROM tags WHERE name = ?", (tag,))
                row = cursor.fetchone()
                if row:
                    tag_id = row[0]
                    cursor.execute("INSERT OR IGNORE INTO note_tags (note_id, tag_id) VALUES (?, ?)", (note_id, tag_id))
        
        self.commit()
        return note_id

    def get_notes(self, binary_name: Optional[str] = None, note_type: Optional[str] = None, 
                  tags: Optional[List[str]] = None, limit: int = 100) -> List[Dict[str, Any]]:
        
        query = "SELECT note_id, binary_name, function_name, address, note_type, content, confidence, tags, created_at, updated_at, title FROM notes"
        conditions = []
        params = []
        
        if binary_name:
            conditions.append("binary_name = ?")
            params.append(binary_name)
            
        if note_type:
            conditions.append("note_type = ?")
            params.append(note_type)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        
        results = []
        for row in cursor.fetchall():
            note = {
                "id": row[0],
                "binary_name": row[1],
                "function_name": row[2],
                "address": row[3],
                "note_type": row[4],
                "content": row[5],
                "confidence": row[6],
                "tags": json.loads(row[7]) if row[7] else [],
                "created_at": row[8],
                "updated_at": row[9],
                "title": row[10]
            }

            if tags:
                filter_tags = set(self._parse_tags(tags))
                note_tags = set(note["tags"])
                if not filter_tags.intersection(note_tags):
                    continue

            results.append(note)

        return results

    def update_note(self, note_id: int, content: Optional[str] = None, title: Optional[str] = None, tags: Optional[List[str]] = None) -> bool:
        cursor = self.conn.cursor()
        
        updates = []
        params = []
        
        if content is not None:
            updates.append("content = ?")
            params.append(content)
            
        if title is not None:
            updates.append("title = ?")
            params.append(title)
            
        if tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(tags))
            
        if not updates:
            return False
            
        updates.append("updated_at = CURRENT_TIMESTAMP")
        
        query = f"UPDATE notes SET {', '.join(updates)} WHERE note_id = ?"
        params.append(note_id)
        
        cursor.execute(query, params)
        
        if tags is not None:
            # Update tags relation
            cursor.execute("DELETE FROM note_tags WHERE note_id = ?", (note_id,))
            for tag in tags:
                cursor.execute("SELECT tag_id FROM tags WHERE name = ?", (tag,))
                row = cursor.fetchone()
                if row:
                    tag_id = row[0]
                    cursor.execute("INSERT OR IGNORE INTO note_tags (note_id, tag_id) VALUES (?, ?)", (note_id, tag_id))
        
        self.commit()
        return cursor.rowcount > 0

    def delete_note(self, note_id: int) -> bool:
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM note_tags WHERE note_id = ?", (note_id,))
        cursor.execute("DELETE FROM notes WHERE note_id = ?", (note_id,))
        self.commit()
        return cursor.rowcount > 0

    # ========== Vulnerability Operations ==========
    def add_vulnerability(self, binary_name: str, severity: str, category: str, 
                          description: str, title: Optional[str] = None,
                          function_name: Optional[str] = None, address: Optional[int] = None,
                          evidence: Optional[str] = None, cvss: Optional[float] = None,
                          exploitability: Optional[str] = None) -> int:
        
        if severity not in SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity. Must be one of {SEVERITY_LEVELS}")
            
        if category not in VULNERABILITY_CATEGORIES:
            raise ValueError(f"Invalid category. Must be one of {VULNERABILITY_CATEGORIES}")

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO vulnerabilities (
                binary_name, title, function_name, address, severity, category, 
                description, evidence, cvss, exploitability
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (binary_name, title, function_name, address, severity, category, description, evidence, cvss, exploitability))
        
        self.commit()
        return cursor.lastrowid

    def update_vulnerability_verification(self, vuln_id: int, status: str, details: str) -> bool:
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE vulnerabilities SET verification_status = ?, verification_details = ? WHERE id = ?",
            (status, details, vuln_id)
        )
        self.commit()
        return cursor.rowcount > 0

    def get_vulnerabilities(self, binary_name: Optional[str] = None, 
                            severity: Optional[str] = None,
                            category: Optional[str] = None,
                            verification_status: Optional[str] = None) -> List[Dict[str, Any]]:
        
        sql = """
            SELECT id, binary_name, function_name, address, severity, category, 
                   description, evidence, cvss, exploitability, created_at, title,
                   verification_status, verification_details
            FROM vulnerabilities
        """
        conditions = []
        params = []
        
        if binary_name:
            conditions.append("binary_name = ?")
            params.append(binary_name)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if category:
            conditions.append("category = ?")
            params.append(category)
        if verification_status:
            conditions.append("verification_status = ?")
            params.append(verification_status)
            
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
            
        sql += " ORDER BY severity, created_at DESC"
        
        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        return [
            {
                "id": row[0],
                "binary_name": row[1],
                "function_name": row[2],
                "address": row[3],
                "severity": row[4],
                "category": row[5],
                "description": row[6],
                "evidence": row[7],
                "cvss": row[8],
                "exploitability": row[9],
                "created_at": row[10],
                "title": row[11],
                "verification_status": row[12] or 'unverified',
                "verification_details": row[13]
            }
            for row in rows
        ]

    def get_analysis_progress(self, binary_name: str) -> Dict[str, Any]:
        cursor = self.conn.cursor()
        
        # Count notes
        cursor.execute("SELECT COUNT(*) FROM notes WHERE binary_name = ?", (binary_name,))
        row = cursor.fetchone()
        total_notes = row[0] if row else 0
        
        # Count notes by type
        cursor.execute("SELECT note_type, COUNT(*) FROM notes WHERE binary_name = ? GROUP BY note_type", (binary_name,))
        notes_by_type = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Count findings (vulnerabilities)
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE binary_name = ?", (binary_name,))
        row = cursor.fetchone()
        findings_count = row[0] if row else 0
        
        # Count findings by severity
        cursor.execute("SELECT severity, COUNT(*) FROM vulnerabilities WHERE binary_name = ? GROUP BY severity", (binary_name,))
        findings_by_severity = {row[0]: row[1] for row in cursor.fetchall()}
        
        return {
            "binary_name": binary_name,
            "total_notes": total_notes,
            "notes_by_type": notes_by_type,
            "findings_count": findings_count,
            "findings_by_severity": findings_by_severity
        }

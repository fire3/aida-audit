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

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_id INTEGER,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending',
                created_at INTEGER,
                updated_at INTEGER,
                FOREIGN KEY(parent_id) REFERENCES audit_plans(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plan_id INTEGER,
                message TEXT NOT NULL,
                timestamp INTEGER,
                FOREIGN KEY(plan_id) REFERENCES audit_plans(id)
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
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_plans_status ON audit_plans(status)")

        self._ensure_tags(cursor)
        self._ensure_columns(cursor)
        self.commit()
        self.log("Audit schema created successfully.")

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

    def _ensure_columns(self, cursor):
        # Check if parent_id exists in audit_plans
        cursor.execute("PRAGMA table_info(audit_plans)")
        columns = [row[1] for row in cursor.fetchall()]
        if "parent_id" not in columns:
            self.log("Migrating schema: Adding parent_id to audit_plans")
            cursor.execute("ALTER TABLE audit_plans ADD COLUMN parent_id INTEGER REFERENCES audit_plans(id)")
        
        if "plan_type" not in columns:
            self.log("Migrating schema: Adding plan_type to audit_plans")
            cursor.execute("ALTER TABLE audit_plans ADD COLUMN plan_type TEXT DEFAULT 'agent_plan'")

        if "binary_name" not in columns:
            self.log("Migrating schema: Adding binary_name to audit_plans")
            cursor.execute("ALTER TABLE audit_plans ADD COLUMN binary_name TEXT")

        if "summary" not in columns:
            self.log("Migrating schema: Adding summary to audit_plans")
            cursor.execute("ALTER TABLE audit_plans ADD COLUMN summary TEXT")

        # Check notes table
        cursor.execute("PRAGMA table_info(notes)")
        note_columns = [row[1] for row in cursor.fetchall()]
        if "title" not in note_columns:
            self.log("Migrating schema: Adding title to notes")
            cursor.execute("ALTER TABLE notes ADD COLUMN title TEXT")

        # Check vulnerabilities table (formerly findings)
        # Since we renamed the table in create_schema, we should check if the old table exists and migrate data if necessary?
        # For this dev environment, we assume we can just use the new table. 
        # But if the user has existing data, we might want to be careful.
        # Given the instruction "Backend comprehensive modification", creating new structure is priority.
        # We will assume new table 'vulnerabilities' is used.
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        vuln_columns = [row[1] for row in cursor.fetchall()]
        
        # If table doesn't exist (because create_schema used IF NOT EXISTS and maybe old db didn't have it), it would be created.
        # If it exists, check columns.
        if vuln_columns:
            if "verification_status" not in vuln_columns:
                 self.log("Migrating schema: Adding verification_status to vulnerabilities")
                 cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN verification_status TEXT DEFAULT 'unverified'")
            if "verification_details" not in vuln_columns:
                 self.log("Migrating schema: Adding verification_details to vulnerabilities")
                 cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN verification_details TEXT")

    def _ensure_tags(self, cursor=None):
        pass  # Placeholder to ensure non-identity replacement if needed, though logically identical context
        if cursor is None:
            cursor = self.conn.cursor()
        for tag in PREDEFINED_TAGS:
            try:
                cursor.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
            except Exception:
                pass

    def _parse_tags(self, tags_input: Optional[str]) -> List[str]:
        if not tags_input:
            return []
        if isinstance(tags_input, str):
            return [t.strip() for t in tags_input.split(",") if t.strip()]
        if isinstance(tags_input, list):
            return tags_input
        return []

    def _ensure_tag_ids(self, tags: List[str], cursor=None) -> List[int]:
        if cursor is None:
            cursor = self.conn.cursor()
        tag_ids = []
        for tag in tags:
            cursor.execute("SELECT tag_id FROM tags WHERE name = ?", (tag,))
            row = cursor.fetchone()
            if row:
                tag_ids.append(row[0])
            else:
                cursor.execute("INSERT INTO tags (name) VALUES (?)", (tag,))
                tag_ids.append(cursor.lastrowid)
        return tag_ids

    # ========== Plan Operations ==========
    def add_plan(self, title: str, description: str, parent_id: Optional[int] = None, plan_type: str = 'agent_plan', binary_name: Optional[str] = None) -> int:
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO audit_plans (title, description, status, created_at, updated_at, parent_id, plan_type, binary_name) VALUES (?, ?, 'pending', ?, ?, ?, ?, ?)",
            (title, description, timestamp, timestamp, parent_id, plan_type, binary_name)
        )
        self.commit()
        return cursor.lastrowid

    def update_plan_summary(self, plan_id: int, summary: str) -> bool:
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE audit_plans SET summary = ?, updated_at = ? WHERE id = ?",
            (summary, timestamp, plan_id)
        )
        self.commit()
        return cursor.rowcount > 0

    def update_plan_status(self, plan_id: int, status: str, notes: Optional[str] = None) -> bool:
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        if notes:
            cursor.execute(
                "UPDATE audit_plans SET status = ?, updated_at = ?, notes = ? WHERE id = ?",
                (status, timestamp, notes, plan_id)
            )
        else:
            cursor.execute(
                "UPDATE audit_plans SET status = ?, updated_at = ? WHERE id = ?",
                (status, timestamp, plan_id)
            )
        self.commit()
        return cursor.rowcount > 0

    def delete_plan(self, plan_id: int) -> bool:
        cursor = self.conn.cursor()
        
        # Recursively delete children
        cursor.execute("SELECT id FROM audit_plans WHERE parent_id = ?", (plan_id,))
        children = cursor.fetchall()
        for child in children:
            self.delete_plan(child[0])
            
        # Delete related logs
        cursor.execute("DELETE FROM audit_logs WHERE plan_id = ?", (plan_id,))
        
        # Delete the plan
        cursor.execute("DELETE FROM audit_plans WHERE id = ?", (plan_id,))
        
        self.commit()
        return cursor.rowcount > 0

    def reset_in_progress_plans(self) -> int:
        """Reset all in_progress plans to pending status."""
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE audit_plans SET status = 'pending', updated_at = ? WHERE status = 'in_progress'",
            (timestamp,)
        )
        self.commit()
        return cursor.rowcount

    def get_plans(self, status: Optional[str] = None, plan_type: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT id, parent_id, title, description, status, created_at, updated_at, plan_type, binary_name, summary FROM audit_plans"
        conditions = []
        params = []
        
        if status:
            conditions.append("status = ?")
            params.append(status)
        
        if plan_type:
            conditions.append("plan_type = ?")
            params.append(plan_type)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        columns = [column[0] for column in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    # ========== Log Operations ==========
    def log_progress(self, message: str, plan_id: Optional[int] = None):
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO audit_logs (plan_id, message, timestamp) VALUES (?, ?, ?)",
            (plan_id, message, timestamp)
        )
        self.commit()

    def get_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, plan_id, message, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        columns = [column[0] for column in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    # ========== Message Operations ==========
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
    def create_note(
        self,
        binary_name: str,
        content: str,
        note_type: str,
        title: Optional[str] = None,
        function_name: Optional[str] = None,
        address: Optional[int] = None,
        tags: Optional[str] = None,
        confidence: str = "medium"
    ) -> int:
        if note_type not in NOTE_TYPES:
            note_type = "general"
        if confidence not in CONFIDENCE_LEVELS:
            confidence = "medium"
        
        # If title is not provided, try to generate it from content
        if not title:
            # Use first line or first 50 chars
            first_line = content.split('\n')[0].strip()
            title = first_line[:50] + "..." if len(first_line) > 50 else first_line

        parsed_tags = self._parse_tags(tags)
        tags_json = json.dumps(parsed_tags) if parsed_tags else None

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO notes (binary_name, title, function_name, address, note_type, content, confidence, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (binary_name, title, function_name, address, note_type, content, confidence, tags_json))

        note_id = cursor.lastrowid

        if parsed_tags:
            tag_ids = self._ensure_tag_ids(parsed_tags, cursor)
            for tag_id in tag_ids:
                try:
                    cursor.execute("INSERT OR IGNORE INTO note_tags (note_id, tag_id) VALUES (?, ?)",
                                        (note_id, tag_id))
                except Exception:
                    pass

        self.commit()
        self.log(f"Created note {note_id} for {binary_name}")
        return note_id

    def get_notes(
        self,
        binary_name: Optional[str] = None,
        query: Optional[str] = None,
        note_type: Optional[str] = None,
        tags: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        conditions = []
        params = []

        if binary_name:
            conditions.append("binary_name = ?")
            params.append(binary_name)

        if note_type:
            conditions.append("note_type = ?")
            params.append(note_type)

        if query:
            conditions.append("content LIKE ?")
            params.append(f"%{query}%")

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        sql = f"""
            SELECT note_id, binary_name, function_name, address, note_type, content,
                   confidence, tags, created_at, updated_at, title
            FROM notes
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT ?
        """
        params.append(limit)

        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        results = []
        for row in rows:
            note = {
                "note_id": row[0],
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

    def update_note(
        self,
        note_id: int,
        content: Optional[str] = None,
        title: Optional[str] = None,
        tags: Optional[str] = None
    ) -> bool:
        updates = []
        params = []
        
        cursor = self.conn.cursor()

        if content is not None:
            updates.append("content = ?")
            params.append(content)

        if title is not None:
            updates.append("title = ?")
            params.append(title)

        if tags is not None:
            parsed_tags = self._parse_tags(tags)
            tags_json = json.dumps(parsed_tags) if parsed_tags else None
            updates.append("tags = ?")
            params.append(tags_json)
            updates.append("updated_at = CURRENT_TIMESTAMP")

            cursor.execute("DELETE FROM note_tags WHERE note_id = ?", (note_id,))
            if parsed_tags:
                tag_ids = self._ensure_tag_ids(parsed_tags, cursor)
                for tag_id in tag_ids:
                    try:
                        cursor.execute("INSERT OR IGNORE INTO note_tags (note_id, tag_id) VALUES (?, ?)",
                                            (note_id, tag_id))
                    except Exception:
                        pass
        elif content is not None:
            updates.append("updated_at = CURRENT_TIMESTAMP")

        if not updates:
            return False

        params.append(note_id)
        cursor.execute(f"""
            UPDATE notes SET {', '.join(updates)} WHERE note_id = ?
        """, params)
        self.conn.commit()
        return cursor.rowcount > 0

    def delete_note(self, note_id: int) -> bool:
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM note_tags WHERE note_id = ?", (note_id,))
        # Decoupled: findings (vulnerabilities) are no longer deleted when a note is deleted
        cursor.execute("DELETE FROM notes WHERE note_id = ?", (note_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    # ========== Vulnerability Operations ==========
    def create_vulnerability(
        self,
        binary_name: str,
        severity: str,
        category: str,
        title: str,
        description: str,
        function_name: Optional[str] = None,
        address: Optional[int] = None,
        evidence: Optional[str] = None,
        cvss: Optional[float] = None,
        exploitability: Optional[str] = None
    ) -> int:
        if severity not in SEVERITY_LEVELS:
            severity = "info"
        if category not in VULNERABILITY_CATEGORIES:
            category = "other"

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO vulnerabilities (binary_name, title, function_name, address, severity, category, description, evidence, cvss, exploitability)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (binary_name, title, function_name, address, severity, category, description, evidence, cvss, exploitability))

        vulnerability_id = cursor.lastrowid
        self.commit()
        self.log(f"Created vulnerability {vulnerability_id} for {binary_name}")
        return vulnerability_id

    def update_vulnerability_verification(
        self,
        vulnerability_id: int,
        status: str,
        details: Optional[str] = None
    ) -> bool:
        cursor = self.conn.cursor()
        if details:
            cursor.execute(
                "UPDATE vulnerabilities SET verification_status = ?, verification_details = ? WHERE id = ?",
                (status, details, vulnerability_id)
            )
        else:
            cursor.execute(
                "UPDATE vulnerabilities SET verification_status = ? WHERE id = ?",
                (status, vulnerability_id)
            )
        self.commit()
        return cursor.rowcount > 0

    def get_vulnerabilities(
        self,
        binary_name: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        verification_status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        conditions = []
        params = []

        if binary_name:
            conditions.append("v.binary_name = ?")
            params.append(binary_name)

        if severity:
            conditions.append("v.severity = ?")
            params.append(severity)

        if category:
            conditions.append("v.category = ?")
            params.append(category)

        if verification_status:
            conditions.append("v.verification_status = ?")
            params.append(verification_status)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        sql = f"""
            SELECT v.id, v.binary_name, v.function_name, v.address,
                   v.severity, v.category, v.description, v.evidence, v.cvss,
                   v.exploitability, v.created_at, v.title, v.verification_status, v.verification_details
            FROM vulnerabilities v
            WHERE {where_clause}
            ORDER BY
                CASE v.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                END,
                v.created_at DESC
        """

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

    def get_statistics(self, binary_name: str) -> Dict[str, Any]:
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM notes WHERE binary_name = ?
        """, (binary_name,))
        total_notes = cursor.fetchone()[0]

        cursor.execute("""
            SELECT note_type, COUNT(*) FROM notes WHERE binary_name = ? GROUP BY note_type
        """, (binary_name,))
        notes_by_type = dict(cursor.fetchall())

        cursor.execute("""
            SELECT COUNT(*) FROM vulnerabilities WHERE binary_name = ?
        """, (binary_name,))
        vulnerabilities_count = cursor.fetchone()[0]

        cursor.execute("""
            SELECT severity, COUNT(*) FROM vulnerabilities WHERE binary_name = ? GROUP BY severity
        """, (binary_name,))
        vulnerabilities_by_severity = dict(cursor.fetchall())

        return {
            "binary_name": binary_name,
            "total_notes": total_notes,
            "notes_by_type": notes_by_type,
            "vulnerabilities_count": vulnerabilities_count,
            "vulnerabilities_by_severity": vulnerabilities_by_severity
        }


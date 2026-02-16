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

FINDING_CATEGORIES = [
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
        if not os.path.exists(os.path.dirname(self.db_path)):
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
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
            CREATE TABLE IF NOT EXISTS findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                note_id INTEGER UNIQUE REFERENCES notes(note_id),
                binary_name TEXT NOT NULL,
                function_name TEXT,
                address INTEGER,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT,
                cvss REAL,
                exploitability TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending',
                created_at INTEGER,
                updated_at INTEGER
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
            CREATE TABLE IF NOT EXISTS audit_memory (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER
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
            CREATE TABLE IF NOT EXISTS finding_plans (
                finding_id INTEGER NOT NULL REFERENCES findings(finding_id),
                plan_id INTEGER NOT NULL REFERENCES audit_plans(id),
                linked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (finding_id, plan_id)
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notes_binary ON notes(binary_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notes_type ON notes(note_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notes_func ON notes(function_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_binary ON findings(binary_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_plans_status ON audit_plans(status)")

        self._ensure_tags(cursor)
        self.commit()
        self.log("Audit schema created successfully.")

    def _ensure_tags(self, cursor=None):
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
    def add_plan(self, title: str, description: str) -> int:
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO audit_plans (title, description, status, created_at, updated_at) VALUES (?, ?, 'pending', ?, ?)",
            (title, description, timestamp, timestamp)
        )
        self.commit()
        return cursor.lastrowid

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

    def get_plans(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT id, title, description, status, created_at, updated_at FROM audit_plans"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        
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

    # ========== Memory Operations ==========
    def set_memory(self, key: str, value: Any):
        timestamp = int(time.time())
        json_value = json.dumps(value)
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO audit_memory (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, json_value, timestamp)
        )
        self.commit()

    def get_memory(self, key: str) -> Optional[Any]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM audit_memory WHERE key = ?", (key,))
        row = cursor.fetchone()
        if row:
            return json.loads(row[0])
        return None

    def get_all_memories(self) -> Dict[str, Any]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT key, value FROM audit_memory")
        result = {}
        for row in cursor.fetchall():
            result[row[0]] = json.loads(row[1])
        return result

    # ========== Message Operations ==========
    def add_message(self, session_id: str, role: str, content: str):
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO audit_messages (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
            (session_id, role, content, timestamp)
        )
        self.commit()

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
        function_name: Optional[str] = None,
        address: Optional[int] = None,
        tags: Optional[str] = None,
        confidence: str = "medium"
    ) -> int:
        if note_type not in NOTE_TYPES:
            note_type = "general"
        if confidence not in CONFIDENCE_LEVELS:
            confidence = "medium"

        parsed_tags = self._parse_tags(tags)
        tags_json = json.dumps(parsed_tags) if parsed_tags else None

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO notes (binary_name, function_name, address, note_type, content, confidence, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (binary_name, function_name, address, note_type, content, confidence, tags_json))

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
                   confidence, tags, created_at, updated_at
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
                "updated_at": row[9]
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
        tags: Optional[str] = None
    ) -> bool:
        updates = []
        params = []
        
        cursor = self.conn.cursor()

        if content is not None:
            updates.append("content = ?")
            params.append(content)

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
        cursor.execute("DELETE FROM findings WHERE note_id = ?", (note_id,))
        cursor.execute("DELETE FROM notes WHERE note_id = ?", (note_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    # ========== Finding Operations ==========
    def create_finding(
        self,
        binary_name: str,
        severity: str,
        category: str,
        description: str,
        function_name: Optional[str] = None,
        address: Optional[int] = None,
        evidence: Optional[str] = None,
        cvss: Optional[float] = None,
        exploitability: Optional[str] = None
    ) -> int:
        if severity not in SEVERITY_LEVELS:
            severity = "info"
        if category not in FINDING_CATEGORIES:
            category = "other"

        note_id = self.create_note(
            binary_name=binary_name,
            content=description,
            note_type="vulnerability",
            function_name=function_name,
            address=address,
            confidence="high"
        )
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO findings (note_id, binary_name, function_name, address, severity, category, description, evidence, cvss, exploitability)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (note_id, binary_name, function_name, address, severity, category, description, evidence, cvss, exploitability))

        finding_id = cursor.lastrowid
        self.commit()
        self.log(f"Created finding {finding_id} for {binary_name}")
        return finding_id

    def get_findings(
        self,
        binary_name: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        conditions = []
        params = []

        if binary_name:
            conditions.append("f.binary_name = ?")
            params.append(binary_name)

        if severity:
            conditions.append("f.severity = ?")
            params.append(severity)

        if category:
            conditions.append("f.category = ?")
            params.append(category)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        sql = f"""
            SELECT f.finding_id, f.note_id, f.binary_name, f.function_name, f.address,
                   f.severity, f.category, f.description, f.evidence, f.cvss,
                   f.exploitability, f.created_at
            FROM findings f
            WHERE {where_clause}
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                END,
                f.created_at DESC
        """

        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        return [
            {
                "finding_id": row[0],
                "note_id": row[1],
                "binary_name": row[2],
                "function_name": row[3],
                "address": row[4],
                "severity": row[5],
                "category": row[6],
                "description": row[7],
                "evidence": row[8],
                "cvss": row[9],
                "exploitability": row[10],
                "created_at": row[11]
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
            SELECT COUNT(*) FROM findings WHERE binary_name = ?
        """, (binary_name,))
        findings_count = cursor.fetchone()[0]

        cursor.execute("""
            SELECT severity, COUNT(*) FROM findings WHERE binary_name = ? GROUP BY severity
        """, (binary_name,))
        findings_by_severity = dict(cursor.fetchall())

        return {
            "binary_name": binary_name,
            "total_notes": total_notes,
            "notes_by_type": notes_by_type,
            "findings_count": findings_count,
            "findings_by_severity": findings_by_severity
        }

    # ========== Finding-Plan Link Operations ==========
    def link_finding_to_plan(self, finding_id: int, plan_id: int) -> bool:
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO finding_plans (finding_id, plan_id) VALUES (?, ?)",
                (finding_id, plan_id)
            )
            self.commit()
            return cursor.rowcount > 0
        except Exception:
            return False

    def unlink_finding_from_plan(self, finding_id: int, plan_id: int) -> bool:
        cursor = self.conn.cursor()
        cursor.execute(
            "DELETE FROM finding_plans WHERE finding_id = ? AND plan_id = ?",
            (finding_id, plan_id)
        )
        self.commit()
        return cursor.rowcount > 0

    def get_plan_findings(self, plan_id: int) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT f.finding_id, f.note_id, f.binary_name, f.function_name, f.address,
                   f.severity, f.category, f.description, f.evidence, f.cvss,
                   f.exploitability, f.created_at, fp.linked_at
            FROM findings f
            INNER JOIN finding_plans fp ON f.finding_id = fp.finding_id
            WHERE fp.plan_id = ?
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                END
        """, (plan_id,))
        rows = cursor.fetchall()

        return [
            {
                "finding_id": row[0],
                "note_id": row[1],
                "binary_name": row[2],
                "function_name": row[3],
                "address": row[4],
                "severity": row[5],
                "category": row[6],
                "description": row[7],
                "evidence": row[8],
                "cvss": row[9],
                "exploitability": row[10],
                "created_at": row[11],
                "linked_at": row[12]
            }
            for row in rows
        ]

    def get_finding_plans(self, finding_id: int) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT p.id, p.title, p.description, p.status, fp.linked_at
            FROM audit_plans p
            INNER JOIN finding_plans fp ON p.id = fp.plan_id
            WHERE fp.finding_id = ?
        """, (finding_id,))
        rows = cursor.fetchall()

        return [
            {
                "plan_id": row[0],
                "title": row[1],
                "description": row[2],
                "status": row[3],
                "linked_at": row[4]
            }
            for row in rows
        ]
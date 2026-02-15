import sqlite3
import json
import os
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


class NotesDatabase:
    def __init__(self, db_path: str, logger=None):
        self.db_path = db_path
        self.logger = logger
        self.conn: Optional[sqlite3.Connection] = None

    def log(self, msg: str):
        if self.logger:
            self.logger.log(msg)
        else:
            print(f"[NotesDB] {msg}")

    def connect(self):
        is_new = not os.path.exists(self.db_path)
        
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        
        if is_new:
            self.create_schema()
            self.log(f"Created notes database: {self.db_path}")
        self.log(f"Connected to notes database: {self.db_path}")

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None
            self.log("Notes database connection closed.")

    def commit(self):
        if self.conn:
            self.conn.commit()

    def create_schema(self):
        self.log("Creating notes schema...")
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
            CREATE INDEX IF NOT EXISTS idx_notes_binary ON notes(binary_name)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_notes_type ON notes(note_type)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_notes_func ON notes(function_name)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_binary ON findings(binary_name)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)
        """)

        self._ensure_tags(cursor)
        self.conn.commit()
        self.log("Notes schema created successfully.")

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

        self.conn.commit()
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
        self.conn.commit()
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

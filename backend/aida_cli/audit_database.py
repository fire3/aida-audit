import sqlite3
import json
import os
import time
from typing import List, Dict, Optional, Any

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
            
        if not os.path.exists(self.db_path):
            self.log(f"Creating new audit database: {self.db_path}")

        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.create_schema()
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
            CREATE TABLE IF NOT EXISTS audit_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending', -- pending, in_progress, completed, failed
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
                value TEXT NOT NULL, -- JSON string
                updated_at INTEGER
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL, -- user, assistant, system
                content TEXT NOT NULL,
                timestamp INTEGER
            )
        """)
        self.commit()

    # Plan Operations
    def add_plan(self, title: str, description: str) -> int:
        timestamp = int(time.time())
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO audit_plans (title, description, status, created_at, updated_at) VALUES (?, ?, 'pending', ?, ?)",
            (title, description, timestamp, timestamp)
        )
        self.commit()
        return cursor.lastrowid

    def update_plan_status(self, plan_id: int, status: str) -> bool:
        timestamp = int(time.time())
        cursor = self.conn.cursor()
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

    # Log Operations
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

    # Memory Operations
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

    # Message Operations
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

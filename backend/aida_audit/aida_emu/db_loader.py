import sqlite3
import json
from typing import Optional, List, Dict, Any, Tuple


class DbLoader:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None

    def connect(self) -> "DbLoader":
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        return self

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def load_metadata(self) -> Dict[str, Any]:
        self.cursor.execute("SELECT content FROM metadata_json WHERE id = 1")
        row = self.cursor.fetchone()
        if row:
            return json.loads(row["content"])
        return {}

    def load_segments(self) -> List[Dict[str, Any]]:
        self.cursor.execute("""
            SELECT seg_id, name, start_va, end_va, perm_r, perm_w, perm_x, type
            FROM segments
            ORDER BY start_va
        """)
        return [
            {
                "seg_id": row["seg_id"],
                "name": row["name"],
                "start_va": row["start_va"],
                "end_va": row["end_va"],
                "perm_r": bool(row["perm_r"]),
                "perm_w": bool(row["perm_w"]),
                "perm_x": bool(row["perm_x"]),
                "type": row["type"],
                "size": row["end_va"] - row["start_va"],
            }
            for row in self.cursor.fetchall()
        ]

    def load_segment_content(self, seg_id: int) -> Optional[bytes]:
        self.cursor.execute("SELECT content FROM segment_content WHERE seg_id = ?", (seg_id,))
        row = self.cursor.fetchone()
        return row["content"] if row else None

    def load_function(self, va: int) -> Optional[Dict[str, Any]]:
        self.cursor.execute("""
            SELECT function_va, name, demangled_name, start_va, end_va, size, is_thunk, is_library
            FROM functions WHERE function_va = ?
        """, (va,))
        row = self.cursor.fetchone()
        if not row:
            self.cursor.execute("""
                SELECT function_va, name, demangled_name, start_va, end_va, size, is_thunk, is_library
                FROM functions WHERE ? >= start_va AND ? < end_va
            """, (va, va))
            row = self.cursor.fetchone()
        
        if row:
            return {
                "va": row["function_va"],
                "name": row["name"],
                "demangled_name": row["demangled_name"],
                "start_va": row["start_va"],
                "end_va": row["end_va"],
                "size": row["size"],
                "is_thunk": bool(row["is_thunk"]),
                "is_library": bool(row["is_library"]),
            }
        return None
    
    def find_function(self, name: str) -> Optional[Dict[str, Any]]:
        self.cursor.execute("""
            SELECT function_va, name, demangled_name, start_va, end_va, size, is_thunk, is_library
            FROM functions WHERE name = ? OR demangled_name = ?
        """, (name, name))
        row = self.cursor.fetchone()
        if row:
            return {
                "va": row["function_va"],
                "name": row["name"],
                "demangled_name": row["demangled_name"],
                "start_va": row["start_va"],
                "end_va": row["end_va"],
                "size": row["size"],
                "is_thunk": bool(row["is_thunk"]),
                "is_library": bool(row["is_library"]),
            }
        return None
    
    def find_functions(self, pattern: str) -> List[Dict[str, Any]]:
        self.cursor.execute("""
            SELECT function_va, name, demangled_name, start_va, end_va, size, is_thunk, is_library
            FROM functions WHERE name LIKE ? OR demangled_name LIKE ?
        """, (f"%{pattern}%", f"%{pattern}%"))
        return [
            {
                "va": row["function_va"],
                "name": row["name"],
                "demangled_name": row["demangled_name"],
                "start_va": row["start_va"],
                "end_va": row["end_va"],
                "size": row["size"],
                "is_thunk": bool(row["is_thunk"]),
                "is_library": bool(row["is_library"]),
            }
            for row in self.cursor.fetchall()
        ]

    def load_functions(self) -> List[Dict[str, Any]]:
        self.cursor.execute("""
            SELECT function_va, name, demangled_name, start_va, end_va, size, is_thunk, is_library
            FROM functions ORDER BY start_va
        """)
        return [
            {
                "va": row["function_va"],
                "name": row["name"],
                "demangled_name": row["demangled_name"],
                "start_va": row["start_va"],
                "end_va": row["end_va"],
                "size": row["size"],
                "is_thunk": bool(row["is_thunk"]),
                "is_library": bool(row["is_library"]),
            }
            for row in self.cursor.fetchall()
        ]

    def load_instructions(self, start_va: int, end_va: int) -> List[Dict[str, Any]]:
        self.cursor.execute("""
            SELECT address, mnemonic, size, sp_delta
            FROM instructions
            WHERE address >= ? AND address < ?
            ORDER BY address
        """, (start_va, end_va))
        
        instructions = []
        for row in self.cursor.fetchall():
            addr = row["address"]
            self.cursor.execute("""
                SELECT op_index, type, value, text
                FROM instruction_operands
                WHERE address = ?
                ORDER BY op_index
            """, (addr,))
            
            operands = [
                {
                    "index": op_row["op_index"],
                    "type": op_row["type"],
                    "value": op_row["value"],
                    "text": op_row["text"],
                }
                for op_row in self.cursor.fetchall()
            ]
            
            instructions.append({
                "address": addr,
                "mnemonic": row["mnemonic"],
                "size": row["size"],
                "sp_delta": row["sp_delta"],
                "operands": operands,
            })
        
        return instructions

    def load_instruction_at(self, va: int) -> Optional[Dict[str, Any]]:
        self.cursor.execute("""
            SELECT address, mnemonic, size, sp_delta
            FROM instructions WHERE address = ?
        """, (va,))
        row = self.cursor.fetchone()
        if not row:
            return None
        
        self.cursor.execute("""
            SELECT op_index, type, value, text
            FROM instruction_operands
            WHERE address = ?
            ORDER BY op_index
        """, (va,))
        
        operands = [
            {
                "index": op_row["op_index"],
                "type": op_row["type"],
                "value": op_row["value"],
                "text": op_row["text"],
            }
            for op_row in self.cursor.fetchall()
        ]
        
        return {
            "address": row["address"],
            "mnemonic": row["mnemonic"],
            "size": row["size"],
            "sp_delta": row["sp_delta"],
            "operands": operands,
        }

    def load_instructions_before(self, va: int, n: int = 10) -> List[Dict[str, Any]]:
        self.cursor.execute("""
            SELECT address, mnemonic, size, sp_delta
            FROM instructions
            WHERE address < ? AND address >= (
                SELECT COALESCE(MAX(address), 0) FROM instructions 
                WHERE address < ? AND address >= (
                    SELECT COALESCE(MIN(address), 0) FROM instructions
                )
            )
            ORDER BY address DESC
            LIMIT ?
        """, (va, va, n))
        
        results = list(self.cursor.fetchall())
        results.reverse()
        
        instructions = []
        for row in results:
            addr = row["address"]
            self.cursor.execute("""
                SELECT op_index, type, value, text
                FROM instruction_operands
                WHERE address = ?
                ORDER BY op_index
            """, (addr,))
            
            operands = [
                {
                    "index": op_row["op_index"],
                    "type": op_row["type"],
                    "value": op_row["value"],
                    "text": op_row["text"],
                }
                for op_row in self.cursor.fetchall()
            ]
            
            instructions.append({
                "address": addr,
                "mnemonic": row["mnemonic"],
                "size": row["size"],
                "sp_delta": row["sp_delta"],
                "operands": operands,
            })
        
        return instructions

    def get_function_end(self, func_va: int) -> Optional[int]:
        self.cursor.execute("SELECT end_va FROM functions WHERE function_va = ?", (func_va,))
        row = self.cursor.fetchone()
        return row["end_va"] if row else None

    def load_basic_blocks(self, func_va: int) -> List[Dict[str, Any]]:
        self.cursor.execute("""
            SELECT block_id, start_va, end_va, type
            FROM basic_blocks
            WHERE function_va = ?
            ORDER BY start_va
        """, (func_va,))
        return [
            {
                "block_id": row["block_id"],
                "start_va": row["start_va"],
                "end_va": row["end_va"],
                "type": row["type"],
            }
            for row in self.cursor.fetchall()
        ]

    def load_call_targets(self, func_va: int) -> List[int]:
        self.cursor.execute("""
            SELECT callee_function_va
            FROM call_edges
            WHERE caller_function_va = ?
        """, (func_va,))
        return [row["callee_function_va"] for row in self.cursor.fetchall()]

    def get_segment_by_va(self, va: int) -> Optional[Dict[str, Any]]:
        self.cursor.execute("""
            SELECT seg_id, name, start_va, end_va, perm_r, perm_w, perm_x, type
            FROM segments
            WHERE ? >= start_va AND ? < end_va
        """, (va, va))
        row = self.cursor.fetchone()
        if row:
            return {
                "seg_id": row["seg_id"],
                "name": row["name"],
                "start_va": row["start_va"],
                "end_va": row["end_va"],
                "perm_r": bool(row["perm_r"]),
                "perm_w": bool(row["perm_w"]),
                "perm_x": bool(row["perm_x"]),
                "type": row["type"],
            }
        return None

    def get_imports(self) -> List[Dict[str, Any]]:
        self.cursor.execute("""
            SELECT name, library, ordinal, address
            FROM imports
            ORDER BY ordinal
        """)
        return [
            {
                "name": row["name"],
                "library": row["library"],
                "ordinal": row["ordinal"],
                "address": row["address"] or 0,
            }
            for row in self.cursor.fetchall()
        ]
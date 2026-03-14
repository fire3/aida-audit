from typing import Optional, Dict, Any, List, Tuple
import struct


def hex_dump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{base + i:08x}  {hex_part:<{width*3}}  {ascii_part}")
    return '\n'.join(lines)


def parse_hex_string(hex_str: str) -> bytes:
    hex_str = hex_str.replace(" ", "").replace("\n", "")
    return bytes.fromhex(hex_str)


def align_address(addr: int, align: int = 0x1000) -> int:
    return (addr + align - 1) & ~(align - 1)


def is_aligned(addr: int, align: int = 0x1000) -> bool:
    return (addr & (align - 1)) == 0


def pack_ptr(value: int, size: int = 8, endian: str = "little") -> bytes:
    return struct.pack("<" if endian == "little" else ">", 
                       {1: "B", 2: "H", 4: "I", 8: "Q"}[size], value)


def unpack_ptr(data: bytes, size: int = 8, endian: str = "little") -> int:
    fmt = "<" if endian == "little" else ">"
    fmt += {1: "B", 2: "H", 4: "I", 8: "Q"}[size]
    return struct.unpack(fmt, data)[0]


def format_instruction(insn: Dict[str, Any]) -> str:
    addr = insn.get("address", 0)
    mnem = insn.get("mnemonic", "")
    ops = insn.get("operands", [])
    
    ops_str = ", ".join(op.get("text", "") for op in ops)
    return f"{addr:08x}:  {mnem:8s} {ops_str}"


def find_function_by_name(db, name: str) -> Optional[Dict[str, Any]]:
    if hasattr(db, 'cursor'):
        db.cursor.execute("""
            SELECT function_va, name, demangled_name, start_va, end_va, size
            FROM functions WHERE name = ? OR demangled_name = ?
        """, (name, name))
        row = db.cursor.fetchone()
        if row:
            return {
                "va": row[0],
                "name": row[1],
                "demangled_name": row[2],
                "start_va": row[3],
                "end_va": row[4],
                "size": row[5],
            }
    return None


def find_address_by_name(db, name: str) -> Optional[int]:
    if hasattr(db, 'cursor'):
        db.cursor.execute("""
            SELECT address FROM symbols WHERE name = ? OR demangled_name = ?
        """, (name, name))
        row = db.cursor.fetchone()
        if row:
            return row[0]
    return None


def find_string(db, search: str) -> List[Dict[str, Any]]:
    results = []
    if hasattr(db, 'cursor'):
        db.cursor.execute("""
            SELECT address, string, length, encoding
            FROM strings WHERE string LIKE ?
        """, (f"%{search}%",))
        for row in db.cursor.fetchall():
            results.append({
                "address": row[0],
                "string": row[1],
                "length": row[2],
                "encoding": row[3],
            })
    return results


def get_pointer_size(arch: str) -> int:
    if arch in ("x86_64", "arm64", "sparc64"):
        return 8
    return 4


def get_stack_alignment(arch: str) -> int:
    if arch in ("x86_64", "arm64"):
        return 16
    return 8


def get_default_registers(arch: str) -> Dict[str, int]:
    if arch == "x86_64":
        return {
            "rax": 0, "rbx": 0, "rcx": 0, "rdx": 0,
            "rsi": 0, "rdi": 0, "rbp": 0, "rsp": 0,
            "r8": 0, "r9": 0, "r10": 0, "r11": 0,
            "r12": 0, "r13": 0, "r14": 0, "r15": 0,
            "rip": 0, "rflags": 0,
        }
    elif arch == "x86_32":
        return {
            "eax": 0, "ebx": 0, "ecx": 0, "edx": 0,
            "esi": 0, "edi": 0, "ebp": 0, "esp": 0,
            "eip": 0, "eflags": 0,
        }
    elif arch == "arm64":
        return {f"x{i}": 0 for i in range(32)}
    elif arch == "arm":
        return {f"r{i}": 0 for i in range(15)}
    elif arch in ("mips", "mipsel"):
        return {"$sp": 0, "$ra": 0, "$gp": 0}
    return {}


def resolve_ida_type(arch: str, type_id: int) -> str:
    type_map = {
        1: "byte",
        2: "word", 
        3: "dword",
        4: "qword",
        5: "float",
        6: "double",
        7: "ptr",
    }
    return type_map.get(type_id, "unknown")


def calculate_checksum(data: bytes, algorithm: str = "md5") -> str:
    import hashlib
    if algorithm == "md5":
        return hashlib.md5(data).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    return ""


class InstructionCache:
    def __init__(self, db=None):
        self.db = db
        self._cache: Dict[int, Dict[str, Any]] = {}

    def get(self, va: int) -> Optional[Dict[str, Any]]:
        if va in self._cache:
            return self._cache[va]
        
        if self.db:
            insn = self.db.load_instruction_at(va)
            if insn:
                self._cache[va] = insn
                return insn
        return None

    def get_range(self, start: int, end: int) -> List[Dict[str, Any]]:
        if self.db:
            return self.db.load_instructions(start, end)
        return []

    def invalidate(self, va: int):
        if va in self._cache:
            del self._cache[va]

    def clear(self):
        self._cache.clear()


class EmulationContext:
    def __init__(self, emu):
        self.emu = emu
        self.pc = emu.get_pc()
        self.sp = emu.get_sp()
        self.regs_snapshot = emu.regs.get_all_gprs()

    def restore(self):
        for name, value in self.regs_snapshot.items():
            try:
                self.emu.set_reg(name, value)
            except:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.restore()
        return False
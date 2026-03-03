import json
import mmap
import os
import re
import sqlite3
import struct


def _clamp_limit(limit, default=50, max_limit=500):
    if limit is None:
        return default
    try:
        limit = int(limit)
    except Exception:
        return default
    if limit <= 0:
        return default
    return min(limit, max_limit)


def _clamp_offset(offset):
    if offset is None:
        return 0
    try:
        offset = int(offset)
    except Exception:
        return 0
    return max(0, offset)


def _parse_address(address):
    if address is None:
        raise ValueError("address_required")
    if isinstance(address, int):
        return address
    if not isinstance(address, str):
        raise ValueError("address_invalid")
    s = address.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if not s:
        raise ValueError("address_invalid")
    return int(s, 16)


def _parse_int_value(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        if not s:
            raise ValueError("value_invalid")
        if s.startswith("-0x"):
            return -int(s[3:], 16)
        if s.startswith("0x"):
            return int(s[2:], 16)
        return int(s, 10)
    raise ValueError("value_invalid")


def _read_elf_segments(path):
    with open(path, "rb") as f:
        ident = f.read(16)
        if len(ident) < 16 or ident[:4] != b"\x7fELF":
            return None
        ei_class = ident[4]
        ei_data = ident[5]
        if ei_class not in (1, 2) or ei_data not in (1, 2):
            return None
        endian = "<" if ei_data == 1 else ">"
        if ei_class == 1:
            hdr = f.read(36)
            if len(hdr) < 36:
                return None
            (
                _e_type,
                _e_machine,
                _e_version,
                _e_entry,
                e_phoff,
                _e_shoff,
                _e_flags,
                _e_ehsize,
                e_phentsize,
                e_phnum,
                _e_shentsize,
                _e_shnum,
                _e_shstrndx,
            ) = struct.unpack(endian + "HHIIIIIHHHHHH", hdr)
        else:
            hdr = f.read(48)
            if len(hdr) < 48:
                return None
            (
                _e_type,
                _e_machine,
                _e_version,
                _e_entry,
                e_phoff,
                _e_shoff,
                _e_flags,
                _e_ehsize,
                e_phentsize,
                e_phnum,
                _e_shentsize,
                _e_shnum,
                _e_shstrndx,
            ) = struct.unpack(endian + "HHIQQQIHHHHHH", hdr)
        if not e_phoff or not e_phnum or not e_phentsize:
            return []
        f.seek(e_phoff, os.SEEK_SET)
        segs = []
        for _ in range(int(e_phnum)):
            ph = f.read(int(e_phentsize))
            if len(ph) < int(e_phentsize):
                break
            if ei_class == 1:
                p_type, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_flags, _p_align = struct.unpack(
                    endian + "IIIIIIII", ph[:32]
                )
            else:
                p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = struct.unpack(
                    endian + "IIQQQQQQ", ph[:56]
                )
            if p_type == 1 and p_filesz:
                segs.append((int(p_offset), int(p_filesz), int(p_vaddr)))
        return segs


def _file_offset_to_va_elf(segments, file_off):
    if not segments:
        return None
    for off, size, vaddr in segments:
        if file_off >= off and file_off < off + size:
            return vaddr + (file_off - off)
    return None


def _format_address(value):
    if value is None:
        return None
    try:
        v = int(value)
    except Exception:
        return None
    if v < 0:
        v &= (1 << 64) - 1
    return hex(v)


class BinaryDbQuery:
    def __init__(self, db_path, binary_path=None, binary_id=None, display_name=None):
        self.db_path = os.path.abspath(db_path)
        self.binary_path = os.path.abspath(binary_path) if binary_path else None
        self.binary_id = binary_id or os.path.basename(self.db_path)
        self.display_name = display_name or os.path.basename(self.db_path)
        self._conn = None

    def close(self):
        # No-op in this stateless version
        pass

    def _get_conn(self):
        # Create a new connection for each query to ensure thread safety
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _table_exists(self, name):
        conn = self._get_conn()
        try:
            cur = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (name,))
            return cur.fetchone() is not None
        finally:
            conn.close()

    def _fetchall(self, sql, params=()):
        conn = self._get_conn()
        try:
            cur = conn.execute(sql, params)
            return cur.fetchall()
        finally:
            conn.close()

    def _fetchone(self, sql, params=()):
        conn = self._get_conn()
        try:
            cur = conn.execute(sql, params)
            return cur.fetchone()
        finally:
            conn.close()

    def _count(self, sql, params=()):
        row = self._fetchone(sql, params)
        if not row:
            return 0
        try:
            return int(list(row)[0])
        except Exception:
            return 0

    def _maybe_parse_json(self, value):
        if not isinstance(value, str):
            return value
        s = value.strip()
        if not s:
            return value
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                return json.loads(s)
            except Exception:
                return value
        return value

    def get_metadata_dict(self):
        if self._table_exists("metadata_json"):
            row = self._fetchone("SELECT content FROM metadata_json WHERE id=1")
            content = row["content"] if row else None
            if not content:
                return {}
            try:
                meta = json.loads(content) if isinstance(content, str) else content
            except Exception:
                return {}
            return meta if isinstance(meta, dict) else {}

        if self._table_exists("metadata"):
            rows = self._fetchall("SELECT key, value FROM metadata")
            out = {}
            for r in rows:
                k = str(r["key"])
                out[k] = self._maybe_parse_json(r["value"])
            libs = out.get("libraries")
            if isinstance(libs, str):
                try:
                    out["libraries"] = json.loads(libs)
                except Exception:
                    pass
            return out

        return {}

    def get_capabilities(self):
        has_pseudo = self._table_exists("pseudocode") and self._count("SELECT COUNT(1) FROM pseudocode") > 0
        has_disasm = self._table_exists("disasm_chunks") and self._count("SELECT COUNT(1) FROM disasm_chunks") > 0
        has_xrefs = self._table_exists("xrefs")
        has_callgraph = self._table_exists("call_edges")
        can_bytes = bool(self.binary_path and os.path.exists(self.binary_path) and self._table_exists("segments"))
        return {
            "decompile": bool(has_pseudo),
            "disassemble": bool(has_disasm),
            "xrefs": bool(has_xrefs),
            "callgraph": bool(has_callgraph),
            "bytes": bool(can_bytes),
            "aob_search": bool(can_bytes),
            "type_system": bool(self._table_exists("local_types")),
            "demangle": bool(self._table_exists("symbols")),
            "patching": False,
        }

    def get_summary(self):
        meta = self.get_metadata_dict() or {}
        counts = meta.get("counts") if isinstance(meta, dict) else None
        if not isinstance(counts, dict):
            counts = {}
        return {
            "binary_name": self.display_name,
            "sha256": (meta.get("hashes") or {}).get("sha256") if isinstance(meta, dict) else None,
            "arch": meta.get("arch") if isinstance(meta, dict) else None,
            "file_format": meta.get("format") if isinstance(meta, dict) else None,
            "size": meta.get("size") if isinstance(meta, dict) else None,
            "created_at": meta.get("created_at") if isinstance(meta, dict) else None,
            "function_count": counts.get("functions"),
            "role": meta.get("role") if isinstance(meta, dict) else None,
        }

    def get_extended_metadata(self):
        meta = self.get_metadata_dict() or {}
        if not isinstance(meta, dict):
            meta = {}

        counts = meta.get("counts")
        if not isinstance(counts, dict):
            counts = {}

        def _ensure_count(key, table, where=None, params=()):
            if counts.get(key) is not None:
                return
            if not self._table_exists(table):
                return
            q = f"SELECT COUNT(1) FROM {table}"
            if where:
                q += f" WHERE {where}"
            counts[key] = self._count(q, params)

        _ensure_count("functions", "functions")
        _ensure_count("user_functions", "functions", "is_library=0")
        _ensure_count("library_functions", "functions", "is_library=1")
        _ensure_count("imports", "imports")
        _ensure_count("exports", "exports")
        _ensure_count("strings", "strings")
        _ensure_count("segments", "segments")
        _ensure_count("symbols", "symbols")

        meta["counts"] = counts
        if meta.get("binary_name") is None:
            meta["binary_name"] = self.display_name
        return meta


    def list_sections(self):
        if not self._table_exists("sections"):
            return []
        rows = self._fetchall(
            "SELECT name, start_va, end_va, file_offset, entropy, type FROM sections ORDER BY start_va ASC"
        )
        out = []
        for r in rows:
            out.append(
                {
                    "name": r["name"],
                    "start_address": _format_address(r["start_va"]),
                    "end_address": _format_address(r["end_va"]),
                    "size": int(r["end_va"] - r["start_va"]) if r["start_va"] is not None and r["end_va"] is not None else None,
                    "file_offset": r["file_offset"],
                    "entropy": r["entropy"],
                    "type": r["type"],
                }
            )
        return out

    def list_segments(self):
        if not self._table_exists("segments"):
            return []
        rows = self._fetchall(
            "SELECT name, start_va, end_va, perm_r, perm_w, perm_x, file_offset, type FROM segments ORDER BY start_va ASC"
        )
        out = []
        for r in rows:
            perms = ""
            perms += "r" if r["perm_r"] else "-"
            perms += "w" if r["perm_w"] else "-"
            perms += "x" if r["perm_x"] else "-"
            out.append(
                {
                    "name": r["name"],
                    "start_address": _format_address(r["start_va"]),
                    "end_address": _format_address(r["end_va"]),
                    "size": int(r["end_va"] - r["start_va"]) if r["start_va"] is not None and r["end_va"] is not None else None,
                    "permissions": perms,
                    "file_offset": r["file_offset"],
                    "type": r["type"],
                }
            )
        return out

    def list_imports(self, offset=None, limit=None):
        if not self._table_exists("imports"):
            return []
        offset = _clamp_offset(offset)
        limit = _clamp_limit(limit)
        rows = self._fetchall(
            "SELECT library, name, ordinal, address, thunk_address FROM imports ORDER BY library ASC, name ASC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        out = []
        for r in rows:
            out.append(
                {
                    "library": r["library"],
                    "name": r["name"],
                    "ordinal": r["ordinal"],
                    "address": _format_address(r["address"]),
                    "thunk_address": _format_address(r["thunk_address"]),
                }
            )
        return out

    def list_exports(self, query=None, name=None, offset=None, limit=None):
        if not self._table_exists("exports"):
            return []
        offset = _clamp_offset(offset)
        limit = _clamp_limit(limit)
        
        wh = []
        params = []
        if query:
            sub_wh = ["name LIKE ?"]
            sub_params = [f"%{query}%"]
            
            # Try to parse as address or ordinal
            try:
                q_str = query.strip()
                if q_str.lower().startswith("0x"):
                    val = int(q_str, 16)
                    sub_wh.append("address = ?")
                    sub_params.append(val)
                elif q_str.isdigit():
                    val = int(q_str)
                    sub_wh.append("ordinal = ?")
                    sub_params.append(val)
                    # Also try as decimal address if plausible? 
                    # Usually addresses are hex, ordinals are decimal.
                    # But keeping it simple: digit -> ordinal.
            except Exception:
                pass
                
            wh.append(f"({' OR '.join(sub_wh)})")
            params.extend(sub_params)

        if name:
            wh.append("name = ?")
            params.append(name)
            
        where = ("WHERE " + " AND ".join(wh)) if wh else ""
        
        rows = self._fetchall(
            f"SELECT name, ordinal, address, forwarder FROM exports {where} ORDER BY name ASC LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]),
        )
        out = []
        for r in rows:
            out.append(
                {
                    "name": r["name"],
                    "ordinal": r["ordinal"],
                    "address": _format_address(r["address"]),
                    "forwarder": r["forwarder"],
                }
            )
        return out

    def list_symbols(self, query=None, offset=None, limit=None):
        if not self._table_exists("symbols"):
            return []
        offset = _clamp_offset(offset)
        limit = _clamp_limit(limit)
        params = []
        where = ""
        if query:
            where = "WHERE name LIKE ? OR demangled_name LIKE ?"
            q = f"%{query}%"
            params.extend([q, q])
        rows = self._fetchall(
            f"SELECT name, demangled_name, kind, address, size FROM symbols {where} ORDER BY address ASC LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]),
        )
        out = []
        for r in rows:
            out.append(
                {
                    "name": r["name"],
                    "demangled_name": r["demangled_name"],
                    "kind": r["kind"],
                    "address": _format_address(r["address"]),
                    "size": r["size"],
                }
            )
        return out

    def _functions_have_rtree(self):
        return self._table_exists("functions_rtree")

    def get_function_containing(self, va):
        if not self._table_exists("functions"):
            return None
        if self._functions_have_rtree():
            row = self._fetchone(
                "SELECT f.function_va, f.name, f.demangled_name, f.start_va, f.end_va, f.size, f.is_thunk, f.is_library "
                "FROM functions_rtree r JOIN functions f ON f.function_va=r.function_va "
                "WHERE r.start_va <= ? AND r.end_va > ? LIMIT 1",
                (va, va),
            )
        else:
            row = self._fetchone(
                "SELECT function_va, name, demangled_name, start_va, end_va, size, is_thunk, is_library "
                "FROM functions WHERE start_va <= ? AND end_va > ? LIMIT 1",
                (va, va),
            )
        if not row:
            return None
        return {
            "address": _format_address(row["function_va"]),
            "name": row["name"],
            "demangled_name": row["demangled_name"],
            "start_address": _format_address(row["start_va"]),
            "end_address": _format_address(row["end_va"]),
            "size": row["size"],
            "is_thunk": bool(row["is_thunk"]),
            "is_library": bool(row["is_library"]),
        }

    def list_functions(self, query=None, offset=None, limit=None, filters=None):
        if not self._table_exists("functions"):
            return []
        offset = _clamp_offset(offset)
        limit = _clamp_limit(limit)
        filters = filters or {}
        wh = []
        params = []
        if query:
            wh.append("(name LIKE ? OR demangled_name LIKE ?)")
            q = f"%{query}%"
            params.extend([q, q])
        if "is_thunk" in filters and filters["is_thunk"] is not None:
            wh.append("is_thunk=?")
            params.append(1 if filters["is_thunk"] else 0)
        if "is_library" in filters and filters["is_library"] is not None:
            wh.append("is_library=?")
            params.append(1 if filters["is_library"] else 0)

        has_decompile = filters.get("has_decompile")
        if has_decompile is True and self._table_exists("pseudocode"):
            wh.append("function_va IN (SELECT function_va FROM pseudocode)")
        if has_decompile is False and self._table_exists("pseudocode"):
            wh.append("function_va NOT IN (SELECT function_va FROM pseudocode)")

        where = ("WHERE " + " AND ".join(wh)) if wh else ""
        rows = self._fetchall(
            f"SELECT function_va, name, demangled_name, start_va, end_va, size, is_thunk, is_library "
            f"FROM functions {where} ORDER BY start_va ASC LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]),
        )
        out = []
        for r in rows:
            out.append(
                {
                    "name": r["name"],
                    "demangled_name": r["demangled_name"],
                    "address": _format_address(r["function_va"]),
                    "start_address": _format_address(r["start_va"]),
                    "end_address": _format_address(r["end_va"]),
                    "size": r["size"],
                    "is_thunk": bool(r["is_thunk"]),
                    "is_library": bool(r["is_library"]),
                }
            )
        return out

    def get_functions_by_name(self, names, match="exact"):
        if not self._table_exists("functions"):
            return []
        if isinstance(names, str):
            names = [names]
        names = [n for n in names if isinstance(n, str) and n]
        if not names:
            return []
        match = (match or "exact").lower()
        out = []
        if match in ("exact", "prefix", "contains"):
            for n in names:
                if match == "exact":
                    rows = self._fetchall(
                        "SELECT function_va, name, demangled_name, start_va, end_va, size FROM functions WHERE name=? OR demangled_name=?",
                        (n, n),
                    )
                elif match == "prefix":
                    rows = self._fetchall(
                        "SELECT function_va, name, demangled_name, start_va, end_va, size FROM functions WHERE name LIKE ? OR demangled_name LIKE ?",
                        (f"{n}%", f"{n}%"),
                    )
                else:
                    rows = self._fetchall(
                        "SELECT function_va, name, demangled_name, start_va, end_va, size FROM functions WHERE name LIKE ? OR demangled_name LIKE ?",
                        (f"%{n}%", f"%{n}%"),
                    )
                for r in rows:
                    out.append(
                        {
                            "name": r["name"],
                            "demangled_name": r["demangled_name"],
                            "address": _format_address(r["function_va"]),
                            "start_address": _format_address(r["start_va"]),
                            "end_address": _format_address(r["end_va"]),
                            "size": r["size"],
                        }
                    )
            return out

        if match == "regex":
            regs = []
            for n in names:
                try:
                    regs.append(re.compile(n))
                except Exception:
                    continue
            if not regs:
                return []
            rows = self._fetchall("SELECT function_va, name, demangled_name, start_va, end_va, size FROM functions")
            for r in rows:
                cand = r["name"] or ""
                cand2 = r["demangled_name"] or ""
                if any(rx.search(cand) or rx.search(cand2) for rx in regs):
                    out.append(
                        {
                            "name": r["name"],
                            "demangled_name": r["demangled_name"],
                            "address": _format_address(r["function_va"]),
                            "start_address": _format_address(r["start_va"]),
                            "end_address": _format_address(r["end_va"]),
                            "size": r["size"],
                        }
                    )
            return out

        return []

    def get_functions_by_address(self, addresses):
        if isinstance(addresses, (str, int)):
            addresses = [addresses]
        out = []
        for a in addresses or []:
            try:
                va = _parse_address(a)
            except Exception:
                continue
            f = self.get_function_containing(va)
            if f:
                out.append(f)
        return out

    def get_pseudocode_by_address(self, addresses, options=None):
        if not self._table_exists("pseudocode"):
            return []
        options = options or {}
        max_lines = options.get("max_lines")
        start_line = options.get("start_line")
        end_line = options.get("end_line")

        try:
            max_lines = int(max_lines) if max_lines is not None else None
        except Exception:
            max_lines = None
        if max_lines is not None and max_lines <= 0:
            max_lines = None

        try:
            start_line = int(start_line) if start_line is not None else 1
            if start_line < 1:
                start_line = 1
        except Exception:
            start_line = 1

        try:
            end_line = int(end_line) if end_line is not None else None
        except Exception:
            end_line = None

        if isinstance(addresses, (str, int)):
            addresses = [addresses]
        out = []
        for a in addresses or []:
            try:
                va = _parse_address(a)
            except Exception:
                continue
            f = self.get_function_containing(va) or {}
            row = self._fetchone("SELECT content FROM pseudocode WHERE function_va=?", (va,))
            if not row and f.get("address"):
                row = self._fetchone("SELECT content FROM pseudocode WHERE function_va=?", (_parse_address(f["address"]),))
            content = row["content"] if row else None
            
            total_lines = 0
            if isinstance(content, str):
                lines = content.splitlines()
                total_lines = len(lines)
                
                # Apply range filtering if start_line/end_line are specified
                # Note: start_line is 1-based, python slice is 0-based
                slice_start = start_line - 1
                slice_end = end_line if end_line is not None else None
                
                # If max_lines is set, it overrides end_line if end_line is not set or implies a larger range
                if max_lines is not None:
                    if slice_end is None:
                        slice_end = slice_start + max_lines
                    else:
                        slice_end = min(slice_end, slice_start + max_lines)
                
                content = "\n".join(lines[slice_start:slice_end])

            out.append(
                {
                    "function_address": f.get("address") or _format_address(va),
                    "name": f.get("name"),
                    "pseudocode": content or "",
                    "total_lines": total_lines,
                }
            )
        return out

    def _get_disasm_chunks(self, start_va, end_va):
        if not self._table_exists("disasm_chunks"):
            return []
        rows = self._fetchall(
            "SELECT start_va, end_va, content FROM disasm_chunks WHERE end_va > ? AND start_va < ? ORDER BY start_va ASC",
            (start_va, end_va),
        )
        return [{"start_va": r["start_va"], "end_va": r["end_va"], "content": r["content"]} for r in rows]

    def get_disassembly_text(self, start_address, end_address):
        start_va = _parse_address(start_address)
        end_va = _parse_address(end_address)
        if end_va <= start_va:
            raise ValueError("range_invalid")
        chunks = self._get_disasm_chunks(start_va, end_va)
        lines = []
        for c in chunks:
            content = c.get("content") or ""
            for line in content.splitlines():
                m = re.match(r"^\s*(0x[0-9a-fA-F]+)\s*:\s*(.*)$", line)
                if not m:
                    continue
                try:
                    va = _parse_address(m.group(1))
                except Exception:
                    continue
                if start_va <= va < end_va:
                    lines.append(f"{_format_address(va)}: {m.group(2)}")
        return "\n".join(lines)

    def get_function_disassembly_text(self, function_address):
        fva = _parse_address(function_address)
        frow = self._fetchone("SELECT start_va, end_va FROM functions WHERE function_va=?", (fva,))
        if not frow:
            f = self.get_function_containing(fva)
            if not f:
                raise LookupError("function_not_found")
            start_va = _parse_address(f["start_address"])
            end_va = _parse_address(f["end_address"])
        else:
            start_va = int(frow["start_va"])
            end_va = int(frow["end_va"])
        return self.get_disassembly_text(_format_address(start_va), _format_address(end_va))

    def get_disassembly_context(self, address, context_lines=10):
        target_va = _parse_address(address)
        # Search range: +/- 4KB should be enough for context
        search_range = 4096
        start_search = max(0, target_va - search_range)
        end_search = target_va + search_range
        
        chunks = self._get_disasm_chunks(start_search, end_search)
        all_lines = []
        for c in chunks:
            content = c.get("content") or ""
            for line in content.splitlines():
                m = re.match(r"^\s*(0x[0-9a-fA-F]+)\s*:", line)
                if m:
                    try:
                        va = int(m.group(1), 16)
                        all_lines.append((va, line))
                    except:
                        pass
        
        all_lines.sort(key=lambda x: x[0])
        
        # Find best index (exact or nearest preceding)
        best_idx = -1
        for i, (va, line) in enumerate(all_lines):
            if va == target_va:
                best_idx = i
                break
            if va < target_va:
                best_idx = i
            else:
                break
                
        if best_idx == -1:
            return ""
            
        start_idx = max(0, best_idx - context_lines)
        end_idx = min(len(all_lines), best_idx + context_lines + 1)
        
        return "\n".join(line for _, line in all_lines[start_idx:end_idx])

    def list_strings(self, query=None, min_length=None, encodings=None, offset=None, limit=None):
        if not self._table_exists("strings"):
            return []
        offset = _clamp_offset(offset)
        limit = _clamp_limit(limit)
        wh = []
        params = []
        if query:
            wh.append("string LIKE ?")
            params.append(f"%{query}%")
        if min_length is not None:
            try:
                ml = int(min_length)
            except Exception:
                ml = None
            if ml is not None and ml > 0:
                wh.append("length >= ?")
                params.append(ml)
        if encodings:
            if isinstance(encodings, str):
                encodings = [encodings]
            encodings = [e for e in encodings if isinstance(e, str) and e]
            if encodings:
                wh.append("encoding IN (" + ",".join(["?"] * len(encodings)) + ")")
                params.extend(encodings)
        where = ("WHERE " + " AND ".join(wh)) if wh else ""
        rows = self._fetchall(
            f"SELECT address, string, encoding, length, section_name FROM strings {where} ORDER BY address ASC LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]),
        )
        out = []
        for r in rows:
            out.append(
                {
                    "address": _format_address(r["address"]),
                    "string": r["string"],
                    "encoding": r["encoding"],
                    "length": r["length"],
                    "section": r["section_name"],
                }
            )
        return out

    def get_string_xrefs(self, string_address, offset=None, limit=None):
        if not self._table_exists("xrefs"):
            return []
        va = _parse_address(string_address)
        offset = _clamp_offset(offset)
        limit = _clamp_limit(limit)
        rows = self._fetchall(
            "SELECT from_va, from_function_va, xref_type, operand_index FROM xrefs WHERE to_va=? ORDER BY from_va ASC LIMIT ? OFFSET ?",
            (va, limit, offset),
        )
        out = []
        for r in rows:
            out.append(
                {
                    "from_address": _format_address(r["from_va"]),
                    "from_function": _format_address(r["from_function_va"]),
                    "xref_type": r["xref_type"],
                    "operand_index": r["operand_index"],
                }
            )
        return out

    def get_xrefs_to_address(self, address, offset=None, limit=None, filters=None, summary=False):
        if not self._table_exists("xrefs"):
            return []
        va = _parse_address(address)
        offset = _clamp_offset(offset)
        limit = _clamp_limit(limit)
        filters = filters or {}
        wh = ["to_va=?"]
        params = [va]
        if filters.get("code_only"):
            wh.append("xref_type IN ('call','jmp')")
        if filters.get("data_only"):
            wh.append("xref_type NOT IN ('call','jmp')")
        where = " AND ".join(wh)
        
        if summary:
            # Summary mode: Group by from_function_va
            query = f"""
                SELECT from_function_va, COUNT(*) as count, MAX(from_va) as last_from_va
                FROM xrefs 
                WHERE {where} 
                GROUP BY from_function_va 
                ORDER BY count DESC, from_function_va ASC 
                LIMIT ? OFFSET ?
            """
            rows = self._fetchall(query, tuple(params + [limit, offset]))
            out = []
            for r in rows:
                from_func_va = r["from_function_va"]
                func_name = None
                if from_func_va and self._table_exists("functions"):
                    f_row = self._fetchone("SELECT name FROM functions WHERE function_va=?", (from_func_va,))
                    if f_row:
                        func_name = f_row["name"]
                out.append({
                    "from_function": _format_address(from_func_va) if from_func_va else None,
                    "from_function_name": func_name,
                    "count": r["count"],
                    "last_from_address": _format_address(r["last_from_va"])
                })
            return out
        else:
            # Detailed mode
            rows = self._fetchall(
                f"SELECT from_va, from_function_va, xref_type, operand_index FROM xrefs WHERE {where} ORDER BY from_va ASC LIMIT ? OFFSET ?",
                tuple(params + [limit, offset]),
            )
            out = []
            for r in rows:
                from_func_va = r["from_function_va"]
                func_name = None
                if from_func_va and self._table_exists("functions"):
                    f_row = self._fetchone("SELECT name FROM functions WHERE function_va=?", (from_func_va,))
                    if f_row:
                        func_name = f_row["name"]

                out.append(
                    {
                        "from_address": _format_address(r["from_va"]),
                        "from_function": _format_address(from_func_va),
                        "from_function_name": func_name,
                        "xref_type": r["xref_type"],
                        "operand_index": r["operand_index"],
                    }
                )
            return out

    def get_xrefs_from_address(self, address, offset=None, limit=None, summary=False):
        if not self._table_exists("xrefs"):
            return []
        va = _parse_address(address)
        offset = _clamp_offset(offset)
        limit = _clamp_limit(limit)
        
        if summary:
             # Summary mode: Group by to_function_va (if code) or just count?
             # For outgoing xrefs, we might want to see "what functions does this address call?"
             # So grouping by to_function_va makes sense for code refs.
             # For data refs, it might be accessing a global variable.
             
             # Let's try to group by to_function_va first, and if null, group by to_va?
             # Or simpler: just group by to_function_va where it exists.
             # But if it's a data ref, to_function_va might be null or point to the function containing the data?
             # In IDA/Binary Ninja, 'to_function_va' usually means the function that starts at 'to_va' or contains it?
             # In this schema, 'to_function_va' likely means the function being called.
             
             query = f"""
                SELECT to_function_va, COUNT(*) as count, MAX(to_va) as last_to_va, MAX(xref_type) as last_type
                FROM xrefs 
                WHERE from_va=? 
                GROUP BY to_function_va 
                ORDER BY count DESC, to_function_va ASC 
                LIMIT ? OFFSET ?
            """
             rows = self._fetchall(query, (va, limit, offset))
             out = []
             for r in rows:
                to_func_va = r["to_function_va"]
                func_name = None
                if to_func_va and self._table_exists("functions"):
                    f_row = self._fetchone("SELECT name FROM functions WHERE function_va=?", (to_func_va,))
                    if f_row:
                        func_name = f_row["name"]
                
                # If to_function_va is None, it might be a data reference to a global variable
                # In that case, we might want to show the variable name/address instead of function
                # But for now, let's stick to the schema.
                
                out.append({
                    "to_function": _format_address(to_func_va) if to_func_va else None,
                    "to_function_name": func_name,
                    "count": r["count"],
                    "last_to_address": _format_address(r["last_to_va"]),
                    "last_type": r["last_type"]
                })
             return out
        else:
            rows = self._fetchall(
                "SELECT to_va, to_function_va, xref_type FROM xrefs WHERE from_va=? ORDER BY to_va ASC LIMIT ? OFFSET ?",
                (va, limit, offset),
            )
            out = []
            for r in rows:
                out.append(
                    {
                        "to_address": _format_address(r["to_va"]),
                        "to_function": _format_address(r["to_function_va"]),
                        "xref_type": r["xref_type"],
                    }
                )
            return out

    def get_callees(self, function_address, offset=0, limit=50, depth=1):
        if not self._table_exists("call_edges"):
            return {"results": [], "has_more": False, "next_offset": None}
        limit = _clamp_limit(limit, default=50, max_limit=500)
        offset = _clamp_offset(offset)
        depth = max(1, int(depth))
        start = _parse_address(function_address)
        q = [(start, 0)]
        seen_funcs = {start}
        results = []
        while q and len(results) < limit:
            fva, d = q.pop(0)
            rows = self._fetchall(
                "SELECT call_site_va, callee_function_va, call_type FROM call_edges WHERE caller_function_va=? ORDER BY call_site_va ASC",
                (fva,),
            )
            for r in rows:
                callee = r["callee_function_va"]
                name_row = None
                if self._table_exists("functions"):
                    name_row = self._fetchone("SELECT name FROM functions WHERE function_va=?", (callee,))
                results.append(
                    {
                        "call_site_address": _format_address(r["call_site_va"]),
                        "callee_address": _format_address(callee),
                        "callee_name": name_row["name"] if name_row else None,
                        "call_type": r["call_type"],
                    }
                )
                if d + 1 < depth and callee not in seen_funcs:
                    seen_funcs.add(callee)
                    q.append((callee, d + 1))
                if len(results) >= limit:
                    break
        has_more = len(results) > limit
        if has_more:
            results = results[:limit]
        next_offset = offset + len(results) if has_more else None
        return {"results": results, "has_more": has_more, "next_offset": next_offset}

    def get_callers(self, function_address, depth=1, limit=None):
        if not self._table_exists("call_edges"):
            return []
        depth = 1 if depth is None else max(1, int(depth))
        limit = _clamp_limit(limit, default=200, max_limit=2000)
        start = _parse_address(function_address)
        q = [(start, 0)]
        seen_funcs = {start}
        results = []
        while q and len(results) < limit:
            fva, d = q.pop(0)
            rows = self._fetchall(
                "SELECT call_site_va, caller_function_va FROM call_edges WHERE callee_function_va=? ORDER BY call_site_va ASC",
                (fva,),
            )
            for r in rows:
                caller = r["caller_function_va"]
                name_row = None
                if self._table_exists("functions"):
                    name_row = self._fetchone("SELECT name FROM functions WHERE function_va=?", (caller,))
                results.append(
                    {
                        "call_site_address": _format_address(r["call_site_va"]),
                        "caller_address": _format_address(caller),
                        "caller_name": name_row["name"] if name_row else None,
                    }
                )
                if d + 1 < depth and caller not in seen_funcs:
                    seen_funcs.add(caller)
                    q.append((caller, d + 1))
                if len(results) >= limit:
                    break
        return results

    def get_caller_functions(self, function_address, offset=0, limit=50):
        if not self._table_exists("call_edges"):
            return {"results": [], "has_more": False, "next_offset": None}
        limit = _clamp_limit(limit, default=50, max_limit=500)
        offset = _clamp_offset(offset)
        start = _parse_address(function_address)
        
        # Check if more results exist by fetching limit + 1
        query = """
            SELECT caller_function_va, COUNT(*) as call_count 
            FROM call_edges 
            WHERE callee_function_va=? 
            GROUP BY caller_function_va 
            ORDER BY call_count DESC, caller_function_va ASC 
            LIMIT ? OFFSET ?
        """
        rows = self._fetchall(query, (start, limit + 1, offset))
        
        has_more = len(rows) > limit
        if has_more:
            rows = rows[:limit]
            
        results = []
        for r in rows:
            caller = r["caller_function_va"]
            name_row = None
            if self._table_exists("functions"):
                name_row = self._fetchone("SELECT name FROM functions WHERE function_va=?", (caller,))
            results.append({
                "caller_address": _format_address(caller),
                "caller_name": name_row["name"] if name_row else None,
                "call_count": r["call_count"]
            })
            
        return {
            "results": results,
            "has_more": has_more,
            "next_offset": offset + limit if has_more else None
        }

    def get_call_sites(self, function_address, offset=0, limit=50):
        if not self._table_exists("call_edges"):
            return {"results": [], "has_more": False, "next_offset": None}
        limit = _clamp_limit(limit, default=50, max_limit=500)
        offset = _clamp_offset(offset)
        start = _parse_address(function_address)
        
        query = """
            SELECT call_site_va, caller_function_va 
            FROM call_edges 
            WHERE callee_function_va=? 
            ORDER BY call_site_va ASC 
            LIMIT ? OFFSET ?
        """
        rows = self._fetchall(query, (start, limit + 1, offset))
        
        has_more = len(rows) > limit
        if has_more:
            rows = rows[:limit]
            
        results = []
        for r in rows:
            caller = r["caller_function_va"]
            name_row = None
            if self._table_exists("functions"):
                name_row = self._fetchone("SELECT name FROM functions WHERE function_va=?", (caller,))
            results.append({
                "call_site_address": _format_address(r["call_site_va"]),
                "caller_address": _format_address(caller),
                "caller_name": name_row["name"] if name_row else None,
            })
            
        return {
            "results": results,
            "has_more": has_more,
            "next_offset": offset + limit if has_more else None
        }

    def resolve_address(self, address):
        va = _parse_address(address)
        seg = None
        sec = None
        if self._table_exists("segments"):
            r = self._fetchone(
                "SELECT name, start_va, end_va, perm_r, perm_w, perm_x, file_offset, type FROM segments WHERE start_va <= ? AND end_va > ? LIMIT 1",
                (va, va),
            )
            if r:
                seg = {
                    "name": r["name"],
                    "start_address": _format_address(r["start_va"]),
                    "end_address": _format_address(r["end_va"]),
                    "file_offset": r["file_offset"],
                    "type": r["type"],
                }
        if self._table_exists("sections"):
            r = self._fetchone(
                "SELECT name, start_va, end_va, file_offset, entropy, type FROM sections WHERE start_va <= ? AND end_va > ? LIMIT 1",
                (va, va),
            )
            if r:
                sec = {
                    "name": r["name"],
                    "start_address": _format_address(r["start_va"]),
                    "end_address": _format_address(r["end_va"]),
                    "file_offset": r["file_offset"],
                    "entropy": r["entropy"],
                    "type": r["type"],
                }

        sym = None
        if self._table_exists("symbols"):
            r = self._fetchone(
                "SELECT name, demangled_name, kind, size FROM symbols WHERE address=? LIMIT 1",
                (va,),
            )
            if r:
                sym = {
                    "name": r["name"],
                    "demangled_name": r["demangled_name"],
                    "kind": r["kind"],
                    "address": _format_address(va),
                    "size": r["size"],
                }

        sref = None
        if self._table_exists("strings"):
            r = self._fetchone("SELECT string, encoding, length, section_name FROM strings WHERE address=? LIMIT 1", (va,))
            if r:
                sref = {
                    "address": _format_address(va),
                    "string": r["string"],
                    "encoding": r["encoding"],
                    "length": r["length"],
                    "section": r["section_name"],
                }

        data_item = None
        if self._table_exists("data_items"):
            r = self._fetchone(
                "SELECT address, size, kind, type_name, repr, target_va FROM data_items WHERE address=? LIMIT 1", (va,)
            )
            if r:
                data_item = {
                    "address": _format_address(r["address"]),
                    "size": r["size"],
                    "kind": r["kind"],
                    "type_name": r["type_name"],
                    "repr": r["repr"],
                    "target_address": _format_address(r["target_va"]),
                }

        func = self.get_function_containing(va)
        is_code = bool(func)
        is_data = bool(data_item) and not is_code
        return {
            "address": _format_address(va),
            "function": func,
            "symbol": sym,
            "segment": seg,
            "section": sec,
            "string_ref": sref,
            "data_item": data_item,
            "is_code": is_code,
            "is_data": is_data,
        }

    def resolve_symbol(self, symbol_name):
        out = []
        
        # 1. Search in functions
        if self._table_exists("functions"):
            rows = self._fetchall(
                "SELECT function_va, name, demangled_name, start_va, end_va, size, is_thunk, is_library "
                "FROM functions WHERE name=? OR demangled_name=?",
                (symbol_name, symbol_name)
            )
            for r in rows:
                out.append({
                    "category": "function",
                    "name": r["name"],
                    "demangled_name": r["demangled_name"],
                    "address": _format_address(r["function_va"]),
                    "size": r["size"],
                    "is_thunk": bool(r["is_thunk"]),
                    "is_library": bool(r["is_library"]),
                })

        # 2. Search in symbols
        if self._table_exists("symbols"):
            rows = self._fetchall(
                "SELECT name, demangled_name, kind, address, size FROM symbols WHERE name=? OR demangled_name=?",
                (symbol_name, symbol_name)
            )
            for r in rows:
                # Check if we already have this address as a function
                addr_str = _format_address(r["address"])
                existing = next((x for x in out if x["address"] == addr_str and x["category"] == "function"), None)
                
                if existing:
                    existing["symbol_kind"] = r["kind"]
                else:
                    item = {
                        "category": "global_variable" if r["kind"] and "data" in r["kind"].lower() else "symbol",
                        "name": r["name"],
                        "demangled_name": r["demangled_name"],
                        "address": addr_str,
                        "size": r["size"],
                        "kind": r["kind"],
                    }
                    
                    # Try to fetch data definition if available
                    if self._table_exists("data_items"):
                        d_row = self._fetchone("SELECT type_name, repr FROM data_items WHERE address=?", (r["address"],))
                        if d_row:
                            item["data_type"] = d_row["type_name"]
                            item["value_repr"] = d_row["repr"]
                    
                    out.append(item)
        
        return out

    def get_decoded_data(self, address, length):
        va = _parse_address(address)
        try:
            length = int(length)
        except Exception:
            length = 1
        length = max(1, min(4096, length))
        
        if self._table_exists("data_items"):
            rows = self._fetchall(
                "SELECT address, size, kind, type_name, repr, target_va FROM data_items WHERE address >= ? AND address < ? ORDER BY address ASC",
                (va, va + length),
            )
            out = []
            for r in rows:
                out.append(
                    {
                        "address": _format_address(r["address"]),
                        "size": r["size"],
                        "kind": r["kind"],
                        "type_name": r["type_name"],
                        "repr": r["repr"],
                        "target_address": _format_address(r["target_va"]),
                    }
                )
            if out:
                return out
        
        if self._table_exists("disasm_chunks"):
            rows = self._fetchall(
                "SELECT start_va, end_va, content FROM disasm_chunks WHERE end_va > ? AND start_va < ? ORDER BY start_va ASC",
                (va, va + length),
            )
            for chunk in rows:
                content = chunk.get("content") or ""
                for line in content.splitlines():
                    m = re.match(r"^\s*(0x[0-9a-fA-F]+)\s*:\s*(.*)$", line)
                    if not m:
                        continue
                    try:
                        insn_va = _parse_address(m.group(1))
                    except Exception:
                        continue
                    if va <= insn_va < va + length:
                        return [
                            {
                                "address": _format_address(insn_va),
                                "size": 0,
                                "kind": "instruction",
                                "type_name": None,
                                "repr": m.group(2),
                                "target_address": None,
                            }
                        ]
        return []

    def _va_to_file_offset(self, va):
        if not (self.binary_path and os.path.exists(self.binary_path)):
            return None
        if not self._table_exists("segments"):
            return None
        r = self._fetchone(
            "SELECT start_va, end_va, file_offset FROM segments WHERE start_va <= ? AND end_va > ? AND file_offset IS NOT NULL LIMIT 1",
            (va, va),
        )
        if not r:
            return None
        base_off = r["file_offset"]
        if base_off is None:
            return None
        return int(base_off) + int(va - r["start_va"])

    def _file_offset_to_va(self, file_offset):
        if not self._table_exists("segments"):
            return None
        rows = self._fetchall(
            "SELECT start_va, end_va, file_offset FROM segments WHERE file_offset IS NOT NULL ORDER BY start_va ASC"
        )
        for r in rows:
            start_va = int(r["start_va"])
            end_va = int(r["end_va"])
            off0 = int(r["file_offset"])
            length = end_va - start_va
            if off0 <= file_offset < off0 + length:
                return start_va + (file_offset - off0)
        return None

    def get_bytes(self, address, length, format_type="x1"):
        if not (self.binary_path and os.path.exists(self.binary_path)):
            raise RuntimeError("binary_path_missing")
        va = _parse_address(address)
        try:
            length = int(length)
        except Exception:
            length = 16
        length = max(1, min(4096, length))
        file_off = self._va_to_file_offset(va)
        if file_off is None:
            raise LookupError("address_unmapped")
        with open(self.binary_path, "rb") as f:
            f.seek(file_off, os.SEEK_SET)
            data = f.read(length)
        return self._format_bytes_output(va, data, format_type)

    def _format_bytes_output(self, base_va, data, format_type):
        ft = (format_type or "x1").lower()
        if ft == "c":
            chars = []
            for b in data:
                if 32 <= b < 127:
                    chars.append(chr(b))
                else:
                    chars.append(".")
            return "".join(chars)

        m = re.match(r"^([xdu])(\d+)$", ft)
        if not m:
            m = re.match(r"^([x])(\d+)$", "x1")
        kind = m.group(1)
        width = int(m.group(2))
        if width not in (1, 2, 4, 8):
            width = 1

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            parts = []
            for j in range(0, len(chunk), width):
                cell = chunk[j : j + width]
                if len(cell) < width:
                    break
                if kind == "x":
                    parts.append(cell[::-1].hex())
                else:
                    v = int.from_bytes(cell, byteorder="little", signed=(kind == "d"))
                    parts.append(str(v))
            lines.append(f"{_format_address(base_va + i)}: " + " ".join(parts))
        return "\n".join(lines)

    def search_bytes_pattern(self, pattern, offset=None, limit=None):
        if not (self.binary_path and os.path.exists(self.binary_path)):
            raise RuntimeError("binary_path_missing")
        if not isinstance(pattern, str) or not pattern.strip():
            raise ValueError("pattern_invalid")
        offset = _clamp_offset(offset)
        limit = _clamp_limit(limit, default=50, max_limit=500)
        segments = _read_elf_segments(self.binary_path)
        if segments is None:
            raise RuntimeError("elf_parse_failed")
        tokens = [t for t in pattern.strip().split() if t]
        pat = []
        mask = []
        for t in tokens:
            if t in ("??", "?"):
                pat.append(0)
                mask.append(0)
                continue
            if re.fullmatch(r"[0-9a-fA-F]{2}", t) is None:
                raise ValueError("pattern_invalid")
            pat.append(int(t, 16))
            mask.append(0xFF)
        if not pat:
            raise ValueError("pattern_invalid")
        pat_b = bytes(pat)
        mask_b = bytes(mask)

        results = []
        matched = 0
        with open(self.binary_path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                i = 0
                while i + len(pat_b) <= len(mm) and len(results) < limit:
                    window = mm[i : i + len(pat_b)]
                    ok = True
                    for j in range(len(pat_b)):
                        if mask_b[j] and window[j] != pat_b[j]:
                            ok = False
                            break
                    if ok:
                        va = _file_offset_to_va_elf(segments, i)
                        if va is not None:
                            if matched >= offset:
                                results.append(_format_address(va))
                            matched += 1
                        i += 1
                    else:
                        i += 1
            finally:
                mm.close()
        return results[:limit]

    def search_immediates(self, value, width=None, offset=None, limit=None):
        offset = _clamp_offset(offset)
        limit = _clamp_limit(limit, default=50, max_limit=500)
        if not (self.binary_path and os.path.exists(self.binary_path)):
            raise RuntimeError("binary_path_missing")
        segments = _read_elf_segments(self.binary_path)
        if segments is None:
            raise RuntimeError("elf_parse_failed")
        v = _parse_int_value(value)
        widths = [width] if width is not None else [1, 2, 4, 8]
        widths = [int(w) for w in widths if int(w) in (1, 2, 4, 8)]
        if not widths:
            raise ValueError("width_invalid")

        hits = []
        matched = 0
        with open(self.binary_path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                raw_hits = []
                for w in widths:
                    try:
                        if v < 0:
                            b = int(v).to_bytes(w, byteorder="little", signed=True)
                        else:
                            b = int(v).to_bytes(w, byteorder="little", signed=False)
                    except Exception:
                        continue
                    start = 0
                    while True:
                        idx = mm.find(b, start)
                        if idx == -1:
                            break
                        raw_hits.append((idx, w))
                        start = idx + 1
                raw_hits.sort(key=lambda x: x[0])
                for file_off, w in raw_hits:
                    va = _file_offset_to_va_elf(segments, file_off)
                    if va is None:
                        continue
                    if matched >= offset:
                        hits.append(
                            {
                                "address": _format_address(va),
                                "file_offset": file_off,
                                "width": w,
                                "value": hex(int(v) & ((1 << (w * 8)) - 1)) if v >= 0 else hex(int(v)),
                                "function_address": None,
                                "instruction": None,
                            }
                        )
                        if len(hits) >= limit:
                            break
                    matched += 1
                    if len(hits) >= limit:
                        break
            finally:
                mm.close()
        return hits


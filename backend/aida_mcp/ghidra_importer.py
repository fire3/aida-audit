import json
import os

from .binary_database import BinaryDatabase


def _load_json(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_json_lines(path):
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def _to_int(value, default=None):
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def import_ghidra_export(export_dir, output_db, logger=None):
    export_dir = os.path.abspath(export_dir)
    output_db = os.path.abspath(output_db)

    db = BinaryDatabase(output_db, logger)
    db.connect()
    db.create_schema()

    meta = _load_json(os.path.join(export_dir, "metadata.json"))
    if isinstance(meta, dict):
        db.insert_metadata_json(json.dumps(meta))

    segments = _load_json_lines(os.path.join(export_dir, "segments.jsonl"))
    if segments:
        rows = []
        for s in segments:
            rows.append(
                (
                    s.get("name"),
                    _to_int(s.get("start_va")),
                    _to_int(s.get("end_va")),
                    _to_int(s.get("perm_r"), 0),
                    _to_int(s.get("perm_w"), 0),
                    _to_int(s.get("perm_x"), 0),
                    _to_int(s.get("file_offset")),
                    s.get("type"),
                )
            )
        db.insert_segments(rows)

    sections = _load_json_lines(os.path.join(export_dir, "sections.jsonl"))
    if sections:
        rows = []
        for s in sections:
            rows.append(
                (
                    s.get("name"),
                    _to_int(s.get("start_va")),
                    _to_int(s.get("end_va")),
                    _to_int(s.get("file_offset")),
                    s.get("entropy"),
                    s.get("type"),
                )
            )
        db.insert_sections(rows)

    imports = _load_json_lines(os.path.join(export_dir, "imports.jsonl"))
    if imports:
        rows = []
        for s in imports:
            rows.append(
                (
                    s.get("library"),
                    s.get("name"),
                    _to_int(s.get("ordinal")),
                    _to_int(s.get("address")),
                    _to_int(s.get("thunk_address")),
                )
            )
        db.insert_imports(rows)

    exports = _load_json_lines(os.path.join(export_dir, "exports.jsonl"))
    if exports:
        rows = []
        for s in exports:
            rows.append(
                (
                    s.get("name"),
                    _to_int(s.get("ordinal")),
                    _to_int(s.get("address")),
                    s.get("forwarder"),
                )
            )
        db.insert_exports(rows)

    symbols = _load_json_lines(os.path.join(export_dir, "symbols.jsonl"))
    if symbols:
        rows = []
        for s in symbols:
            rows.append(
                (
                    s.get("name"),
                    s.get("demangled_name"),
                    s.get("kind"),
                    _to_int(s.get("address")),
                    _to_int(s.get("size"), 0),
                )
            )
        db.insert_symbols(rows)

    functions = _load_json_lines(os.path.join(export_dir, "functions.jsonl"))
    if functions:
        rows = []
        rtree = []
        for s in functions:
            fva = _to_int(s.get("function_va"))
            start = _to_int(s.get("start_va"))
            end = _to_int(s.get("end_va"))
            rows.append(
                (
                    fva,
                    s.get("name"),
                    s.get("demangled_name"),
                    start,
                    end,
                    _to_int(s.get("size"), 0),
                    1 if s.get("is_thunk") else 0,
                    1 if s.get("is_library") else 0,
                )
            )
            if fva is not None and start is not None and end is not None:
                rtree.append((fva, start, end))
        db.insert_functions(rows, rtree)

    strings = _load_json_lines(os.path.join(export_dir, "strings.jsonl"))
    if strings:
        rows = []
        for s in strings:
            rows.append(
                (
                    _to_int(s.get("address")),
                    s.get("encoding"),
                    _to_int(s.get("length")),
                    s.get("string"),
                    s.get("section_name"),
                )
            )
        db.insert_strings(rows)

    disasm_chunks = _load_json_lines(os.path.join(export_dir, "disasm_chunks.jsonl"))
    if disasm_chunks:
        rows = []
        for s in disasm_chunks:
            rows.append(
                (
                    _to_int(s.get("start_va")),
                    _to_int(s.get("end_va")),
                    s.get("content"),
                )
            )
        db.insert_disasm_chunks(rows)

    pseudocode = _load_json_lines(os.path.join(export_dir, "pseudocode.jsonl"))
    if pseudocode:
        rows = []
        for s in pseudocode:
            rows.append(
                (
                    _to_int(s.get("function_va")),
                    s.get("content"),
                )
            )
        db.insert_pseudocode(rows)

    xrefs = _load_json_lines(os.path.join(export_dir, "xrefs.jsonl"))
    if xrefs:
        rows = []
        for s in xrefs:
            rows.append(
                (
                    _to_int(s.get("from_va")),
                    _to_int(s.get("to_va")),
                    _to_int(s.get("from_function_va")),
                    _to_int(s.get("to_function_va")),
                    s.get("xref_type"),
                    _to_int(s.get("operand_index")),
                )
            )
        db.insert_xrefs(rows)

    call_edges = _load_json_lines(os.path.join(export_dir, "call_edges.jsonl"))
    if call_edges:
        rows = []
        for s in call_edges:
            rows.append(
                (
                    _to_int(s.get("caller_function_va")),
                    _to_int(s.get("callee_function_va")),
                    _to_int(s.get("call_site_va")),
                    s.get("call_type"),
                )
            )
        db.insert_call_edges(rows)

    db.close()
    return True

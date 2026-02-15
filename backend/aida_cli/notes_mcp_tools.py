from typing import Dict, Any, List, Optional, Union
from .notes_database import NotesDatabase

_notes_db: Optional[NotesDatabase] = None


def set_notes_db(db: NotesDatabase):
    global _notes_db
    _notes_db = db


def get_notes_db() -> NotesDatabase:
    if _notes_db is None:
        raise RuntimeError("Notes database not initialized")
    return _notes_db


def _parse_address(addr: Optional[Union[str, int]]) -> Optional[int]:
    if addr is None:
        return None
    if isinstance(addr, int):
        return addr
    addr_str = str(addr).strip()
    if addr_str.startswith("0x") or addr_str.startswith("0X"):
        return int(addr_str, 16)
    return int(addr_str)


def create_note(
    binary_name: str,
    content: str,
    note_type: str,
    function_name: Optional[str] = None,
    address: Optional[Union[str, int]] = None,
    tags: Optional[str] = None,
    confidence: str = "medium"
) -> Dict[str, Any]:
    db = get_notes_db()
    addr = _parse_address(address)
    note_id = db.create_note(
        binary_name=binary_name,
        content=content,
        note_type=note_type,
        function_name=function_name,
        address=addr,
        tags=tags,
        confidence=confidence
    )
    return {"note_id": note_id}


def get_notes(
    binary_name: Optional[str] = None,
    query: Optional[str] = None,
    note_type: Optional[str] = None,
    tags: Optional[str] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    db = get_notes_db()
    return db.get_notes(
        binary_name=binary_name,
        query=query,
        note_type=note_type,
        tags=tags,
        limit=limit
    )


def update_note(
    note_id: int,
    content: Optional[str] = None,
    tags: Optional[str] = None
) -> Dict[str, Any]:
    db = get_notes_db()
    success = db.update_note(note_id=note_id, content=content, tags=tags)
    return {"success": success}


def delete_note(note_id: int) -> Dict[str, Any]:
    db = get_notes_db()
    success = db.delete_note(note_id=note_id)
    return {"success": success}


def mark_finding(
    binary_name: str,
    severity: str,
    category: str,
    description: str,
    function_name: Optional[str] = None,
    address: Optional[Union[str, int]] = None,
    evidence: Optional[str] = None,
    cvss: Optional[float] = None,
    exploitability: Optional[str] = None
) -> Dict[str, Any]:
    db = get_notes_db()
    addr = _parse_address(address)
    finding_id = db.create_finding(
        binary_name=binary_name,
        severity=severity,
        category=category,
        description=description,
        function_name=function_name,
        address=addr,
        evidence=evidence,
        cvss=cvss,
        exploitability=exploitability
    )
    note_id = db.get_findings(binary_name=binary_name, severity=severity, category=category)
    actual_note_id = note_id[0]["note_id"] if note_id else None
    return {"finding_id": finding_id, "note_id": actual_note_id}


def get_findings(
    binary_name: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None
) -> List[Dict[str, Any]]:
    db = get_notes_db()
    return db.get_findings(binary_name=binary_name, severity=severity, category=category)


def get_analysis_progress(binary_name: str) -> Dict[str, Any]:
    db = get_notes_db()
    return db.get_statistics(binary_name=binary_name)
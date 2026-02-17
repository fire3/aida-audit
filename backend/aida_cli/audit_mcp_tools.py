from typing import Dict, Any, List, Optional, Union
from .audit_database import AuditDatabase

_audit_db: Optional[AuditDatabase] = None

def set_audit_db(db: AuditDatabase):
    global _audit_db
    _audit_db = db

def get_audit_db() -> AuditDatabase:
    if _audit_db is None:
        raise RuntimeError("Audit database not initialized")
    return _audit_db

def _parse_address(addr: Optional[Union[str, int]]) -> Optional[int]:
    if addr is None:
        return None
    if isinstance(addr, int):
        return addr
    addr_str = str(addr).strip()
    if addr_str.startswith("0x") or addr_str.startswith("0X"):
        return int(addr_str, 16)
    return int(addr_str)

# ========== Plan Operations ==========

def audit_create_macro_plan(title: str, description: str, parent_id: Optional[int] = None) -> Dict[str, Any]:
    """Create a high-level audit plan (Audit Plan)."""
    db = get_audit_db()
    plan_id = db.add_plan(title, description, parent_id, plan_type='audit_plan')
    return {"plan_id": plan_id, "status": "success", "type": "audit_plan"}

def audit_create_agent_task(title: str, description: str, parent_plan_id: int, binary_name: str) -> Dict[str, Any]:
    """Create a specific executable task for an agent (Agent Plan)."""
    db = get_audit_db()
    # Verify parent exists and is an audit_plan? (Optional but good practice)
    # For now, just create it.
    plan_id = db.add_plan(title, description, parent_id=parent_plan_id, plan_type='agent_plan', binary_name=binary_name)
    return {"plan_id": plan_id, "status": "success", "type": "agent_plan"}

def audit_submit_summary(plan_id: int, summary: str) -> Dict[str, Any]:
    """Submit a summary for a completed plan task."""
    db = get_audit_db()
    success = db.update_plan_summary(plan_id, summary)
    return {"success": success}

def audit_get_summary(plan_id: int) -> Dict[str, Any]:
    """Get the summary of a plan task."""
    db = get_audit_db()
    plans = db.get_plans() # This is inefficient but okay for prototype. Better to add get_plan_by_id
    plan = next((p for p in plans if p['id'] == plan_id), None)
    if plan:
        return {"plan_id": plan_id, "summary": plan.get("summary")}
    return {"plan_id": plan_id, "summary": None, "error": "Plan not found"}

def audit_plan_update(plan_id: int, notes: Optional[str] = None, status: Optional[str] = None) -> Dict[str, Any]:
    db = get_audit_db()
    
    plans = db.get_plans()
    current_plan = next((p for p in plans if p['id'] == plan_id), None)
    if not current_plan:
        return {"success": False, "error": f"Plan {plan_id} not found"}
        
    current_status = status if status else current_plan['status']
    
    success = db.update_plan_status(plan_id, current_status, notes)
    if notes:
        db.log_progress(f"Plan {plan_id} updated: {notes}", plan_id)
    if status:
         db.log_progress(f"Plan {plan_id} status changed to: {status}", plan_id)
    return {"success": success}

def audit_plan_list(status: Optional[str] = None, plan_type: Optional[str] = None) -> List[Dict[str, Any]]:
    db = get_audit_db()
    return db.get_plans(status, plan_type)

# ========== Log Operations ==========

def audit_log_progress(message: str, plan_id: Optional[int] = None) -> Dict[str, Any]:
    db = get_audit_db()
    db.log_progress(message, plan_id)
    return {"status": "success"}

# ========== Note Operations ==========

def audit_create_note(
    binary_name: str,
    content: str,
    note_type: str,
    function_name: Optional[str] = None,
    address: Optional[Union[str, int]] = None,
    tags: Optional[str] = None,
    confidence: str = "medium"
) -> Dict[str, Any]:
    db = get_audit_db()
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

def audit_get_notes(
    binary_name: Optional[str] = None,
    query: Optional[str] = None,
    note_type: Optional[str] = None,
    tags: Optional[str] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    db = get_audit_db()
    return db.get_notes(
        binary_name=binary_name,
        query=query,
        note_type=note_type,
        tags=tags,
        limit=limit
    )

def audit_update_note(
    note_id: int,
    content: Optional[str] = None,
    tags: Optional[str] = None
) -> Dict[str, Any]:
    db = get_audit_db()
    success = db.update_note(note_id=note_id, content=content, tags=tags)
    return {"success": success}

def audit_delete_note(note_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    success = db.delete_note(note_id=note_id)
    return {"success": success}

# ========== Finding Operations ==========

def audit_mark_finding(
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
    db = get_audit_db()
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

def audit_get_findings(
    binary_name: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None
) -> List[Dict[str, Any]]:
    db = get_audit_db()
    return db.get_findings(binary_name=binary_name, severity=severity, category=category)

def audit_get_analysis_progress(binary_name: str) -> Dict[str, Any]:
    db = get_audit_db()
    return db.get_statistics(binary_name=binary_name)

# ========== Finding-Plan Link Operations ==========

def audit_link_finding_to_plan(finding_id: int, plan_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    success = db.link_finding_to_plan(finding_id, plan_id)
    return {"success": success}

def audit_unlink_finding_from_plan(finding_id: int, plan_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    success = db.unlink_finding_from_plan(finding_id, plan_id)
    return {"success": success}

def audit_get_plan_findings(plan_id: int) -> List[Dict[str, Any]]:
    db = get_audit_db()
    return db.get_plan_findings(plan_id)

def audit_get_finding_plans(finding_id: int) -> List[Dict[str, Any]]:
    db = get_audit_db()
    return db.get_finding_plans(finding_id)
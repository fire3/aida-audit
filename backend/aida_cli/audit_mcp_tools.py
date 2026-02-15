from typing import Dict, Any, List, Optional
from .audit_database import AuditDatabase

_audit_db: Optional[AuditDatabase] = None

def set_audit_db(db: AuditDatabase):
    global _audit_db
    _audit_db = db

def get_audit_db() -> AuditDatabase:
    if _audit_db is None:
        raise RuntimeError("Audit database not initialized")
    return _audit_db

def audit_plan_add(title: str, description: str) -> Dict[str, Any]:
    """
    Add a new task to the audit plan.
    Use this to decompose your audit goal into smaller, manageable steps.
    """
    db = get_audit_db()
    plan_id = db.add_plan(title, description)
    return {"plan_id": plan_id, "status": "success"}

def audit_plan_list(status: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List all tasks in the audit plan.
    Optionally filter by status (pending, in_progress, completed, failed).
    """
    db = get_audit_db()
    return db.get_plans(status)

def audit_plan_update(plan_id: int, status: str, notes: Optional[str] = None) -> Dict[str, Any]:
    """
    Update the status of a plan task.
    Valid statuses: pending, in_progress, completed, failed.
    You can also add a progress note.
    """
    db = get_audit_db()
    success = db.update_plan_status(plan_id, status)
    if notes:
        db.log_progress(f"Plan {plan_id} updated to {status}: {notes}", plan_id)
    return {"success": success}

def audit_log_progress(message: str, plan_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Log a general progress message or a specific update for a plan item.
    """
    db = get_audit_db()
    db.log_progress(message, plan_id)
    return {"status": "success"}

def audit_memory_set(key: str, value: Any) -> Dict[str, Any]:
    """
    Store a piece of information in the long-term memory.
    The value can be a string, number, list, or dictionary (will be JSON encoded).
    Use this to persist important findings, context, or decisions across sessions.
    """
    db = get_audit_db()
    db.set_memory(key, value)
    return {"status": "success"}

def audit_memory_get(key: str) -> Dict[str, Any]:
    """
    Retrieve information from long-term memory by key.
    """
    db = get_audit_db()
    value = db.get_memory(key)
    return {"key": key, "value": value}

def audit_memory_list() -> Dict[str, Any]:
    """
    List all stored memory keys and values.
    """
    db = get_audit_db()
    return db.get_all_memories()

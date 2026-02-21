from typing import Dict, Any, List, Optional, Union
from .audit_database import AuditDatabase
import json

_audit_db: Optional[AuditDatabase] = None

def set_audit_db(db: AuditDatabase):
    global _audit_db
    _audit_db = db

def get_audit_db() -> AuditDatabase:
    if _audit_db is None:
        raise RuntimeError("Audit database not initialized")
    return _audit_db

VALID_PLAN_STATUSES = ["pending", "in_progress", "completed", "failed"]
VALID_PLAN_TYPES = ["audit_plan", "agent_plan", "verification_plan"]

def _validate_option(name: str, value: Optional[str], options: List[str]):
    if value and value not in options:
        raise ValueError(f"Invalid {name}: {value}. Must be one of {options}")

# ========== Plan (Macro) Tools ==========

def audit_create_macro_plan(title: str, description: str) -> Dict[str, Any]:
    """Create a high-level audit plan (Audit Plan)."""
    db = get_audit_db()
    # Note: parent_id removed in new schema for macro plans
    plan_id = db.create_plan(title, description)
    return {"plan_id": plan_id, "status": "success", "type": "audit_plan"}

def audit_get_macro_plan(plan_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    plan = db.get_plan(plan_id)
    if plan:
        plan['type'] = 'audit_plan'
        return plan
    return {"error": "Plan not found"}

def audit_update_macro_plan(plan_id: int, notes: Optional[str] = None, status: Optional[str] = None) -> Dict[str, Any]:
    db = get_audit_db()
    if status:
        _validate_option("status", status, VALID_PLAN_STATUSES)
    
    current_plan = db.get_plan(plan_id)
    if not current_plan:
        return {"error": "Plan not found"}
    
    current_status = status if status else current_plan['status']
    
    success = db.update_plan_status(plan_id, current_status, notes)
    if notes:
        db.log_progress(f"Plan {plan_id} updated: {notes}", plan_id=plan_id)
    return {"success": success}

def audit_delete_macro_plan(plan_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    success = db.delete_plan(plan_id)
    return {"success": success}

def audit_list_macro_plans(status: Optional[str] = None) -> List[Dict[str, Any]]:
    if status:
        _validate_option("status", status, VALID_PLAN_STATUSES)
    db = get_audit_db()
    plans = db.get_plans(status)
    for p in plans:
        p['type'] = 'audit_plan'
        p['parent_id'] = None # For compatibility
    return plans

# ========== Task (Micro) Tools ==========

def audit_create_agent_task(title: str, description: str, parent_plan_id: int, binary_name: str) -> Dict[str, Any]:
    """Create a specific executable task for an agent (Agent Plan)."""
    db = get_audit_db()
    task_id = db.create_task(parent_plan_id, title, description, binary_name, 'agent_task')
    return {"task_id": task_id, "status": "success", "type": "agent_task"}

def audit_create_verification_task(title: str, description: str, parent_plan_id: int, binary_name: str) -> Dict[str, Any]:
    """Create a verification task for a specific vulnerability."""
    db = get_audit_db()
    task_id = db.create_task(parent_plan_id, title, description, binary_name, 'verification_task')
    return {"task_id": task_id, "status": "success", "type": "verification_task"}

def audit_get_task(task_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    task = db.get_task(task_id)
    if task:
        return task
    return {"error": "Task not found"}

def audit_update_task(task_id: int, notes: Optional[str] = None, status: Optional[str] = None) -> Dict[str, Any]:
    db = get_audit_db()
    if status:
        _validate_option("status", status, VALID_PLAN_STATUSES)
        
    current_task = db.get_task(task_id)
    if not current_task:
        return {"error": "Task not found"}
        
    current_status = status if status else current_task['status']
    
    success = db.update_task_status(task_id, current_status, notes)
    if notes:
        db.log_progress(f"Task {task_id} updated: {notes}", task_id=task_id)
    return {"success": success}

def audit_submit_task_summary(task_id: int, summary: str) -> Dict[str, Any]:
    db = get_audit_db()
    success = db.update_task_summary(task_id, summary)
    return {"success": success}

def audit_get_task_summary(task_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    task = db.get_task(task_id)
    if task:
        return {"task_id": task_id, "summary": task.get("summary")}
    return {"task_id": task_id, "summary": None, "error": "Task not found"}

def audit_delete_task(task_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    success = db.delete_task(task_id)
    return {"success": success}

def audit_list_tasks(status: Optional[str] = None, task_type: Optional[str] = None) -> List[Dict[str, Any]]:
    if status:
        _validate_option("status", status, VALID_PLAN_STATUSES)
    
    # Map old plan_type to new task_type if necessary, or just use values
    # VALID_PLAN_TYPES = ["audit_plan", "agent_plan", "verification_plan"]
    # Internal types: agent_task, verification_task
    
    internal_type = None
    if task_type == 'agent_plan':
        internal_type = 'agent_task'
    elif task_type == 'verification_plan':
        internal_type = 'verification_task'
    elif task_type in ['agent_task', 'verification_task']:
        internal_type = task_type
        
    db = get_audit_db()
    tasks = db.get_tasks(status=status, task_type=internal_type)
    for t in tasks:
        t['type'] = t['task_type']
        t['parent_id'] = t['plan_id']
    return tasks

# ========== Note Tools ==========

def audit_create_note(binary_name: str, content: str, note_type: str,
                      title: str = None, function_name: str = None, address = None,
                      tags: str = None, confidence: str = "medium") -> Dict[str, Any]:
    """Create a new analysis note."""
    db = get_audit_db()
    
    # Parse tags
    tag_list = None
    if tags:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
        
    note_id = db.add_note(
        binary_name=binary_name,
        note_type=note_type,
        content=content,
        title=title,
        function_name=function_name,
        address=address,
        confidence=confidence,
        tags=tag_list
    )
    return {"note_id": note_id, "status": "success"}

def audit_get_notes(binary_name: str = None, query: str = None,
                    note_type: str = None, tags: str = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Query analysis notes."""
    db = get_audit_db()
    
    tag_list = None
    if tags:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
        
    # Note: 'query' parameter is currently ignored by DB implementation in get_notes
    # We could implement client-side filtering or update DB method
    
    return db.get_notes(
        binary_name=binary_name,
        note_type=note_type,
        tags=tag_list,
        limit=limit
    )

def audit_update_note(note_id: int, content: str = None, title: str = None, tags: str = None) -> Dict[str, Any]:
    """Update an existing note's content or tags."""
    db = get_audit_db()
    
    tag_list = None
    if tags is not None:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
        
    success = db.update_note(
        note_id=note_id,
        content=content,
        title=title,
        tags=tag_list
    )
    return {"success": success}

def audit_delete_note(note_id: int) -> Dict[str, Any]:
    """Delete a note."""
    db = get_audit_db()
    success = db.delete_note(note_id)
    return {"success": success}

# ========== Vulnerability Tools ==========

def audit_report_vulnerability(binary_name: str, severity: str, category: str, title: str, description: str,
                       function_name: str = None, address = None,
                       evidence: str = None, cvss: float = None,
                       exploitability: str = None) -> Dict[str, Any]:
    """Report a confirmed or suspected security vulnerability."""
    db = get_audit_db()
    
    vuln_id = db.add_vulnerability(
        binary_name=binary_name,
        severity=severity,
        category=category,
        title=title,
        description=description,
        function_name=function_name,
        address=address,
        evidence=evidence,
        cvss=cvss,
        exploitability=exploitability
    )
    return {"vulnerability_id": vuln_id, "status": "success"}

def audit_get_vulnerabilities(binary_name: str = None, severity: str = None,
                       category: str = None, verification_status: str = None) -> List[Dict[str, Any]]:
    """Query reported security vulnerabilities."""
    db = get_audit_db()
    return db.get_vulnerabilities(
        binary_name=binary_name,
        severity=severity,
        category=category,
        verification_status=verification_status
    )

def audit_update_vulnerability_verification(id: int, status: str, details: str = None) -> Dict[str, Any]:
    """Update the verification status of a vulnerability."""
    db = get_audit_db()
    success = db.update_vulnerability_verification(
        vuln_id=id,
        status=status,
        details=details if details else ""
    )
    return {"success": success}

def audit_get_analysis_progress(binary_name: str) -> Dict[str, Any]:
    """Get analysis progress statistics for a binary."""
    db = get_audit_db()
    return db.get_analysis_progress(binary_name)

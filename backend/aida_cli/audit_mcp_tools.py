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


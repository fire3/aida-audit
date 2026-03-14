from typing import Dict, Any, List, Optional, Union
from .audit_database import AuditDatabase
from .constants import VALID_PLAN_STATUSES, VALID_TASK_TYPES
import json

_audit_db: Optional[AuditDatabase] = None

def set_audit_db(db: AuditDatabase):
    global _audit_db
    _audit_db = db

def get_audit_db() -> AuditDatabase:
    if _audit_db is None:
        raise RuntimeError("Audit database not initialized")
    return _audit_db


def _validate_option(name: str, value: Optional[str], options: List[str]):
    if value and value not in options:
        raise ValueError(f"Invalid {name}: {value}. Must be one of {options}")

# ========== Plan (Macro) Tools ==========

def audit_create_macro_plan(title: str, description: str) -> Dict[str, Any]:
    """Create a high-level audit plan (Audit Plan)."""
    db = get_audit_db()
    plan_id = db.create_plan(title, description)
    return {"plan_id": plan_id, "status": "success", "type": "audit_plan"}

def audit_get_macro_plan(plan_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    plan = db.get_plan(plan_id)
    if plan:
        plan['type'] = 'audit_plan'
        return plan
    return {"error": "Plan not found"}

def audit_update_macro_plan(plan_id: int, notes: Optional[str] = None) -> Dict[str, Any]:
    db = get_audit_db()
    
    current_plan = db.get_plan(plan_id)
    if not current_plan:
        return {"error": "Plan not found"}
    
    success = db.update_plan_status(plan_id, current_plan['status'], notes)
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
    return plans

# ========== Task (Micro) Tools ==========

def audit_create_agent_task(title: str, description: str, parent_plan_id: int, binary_name: str, task_type: str = "ANALYSIS") -> Dict[str, Any]:
    """Create a specific executable task for an agent (Agent Plan).
    
    Args:
        task_type: Must be either "ANALYSIS" or "VERIFICATION".
    """
    _validate_option("task_type", task_type, VALID_TASK_TYPES)
    db = get_audit_db()
    task_id = db.create_task(parent_plan_id, title, description, binary_name, task_type)
    return {"task_id": task_id, "status": "success", "task_type": task_type}

def audit_get_agent_task(task_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    task = db.get_task(task_id)
    if task:
        return task
    return {"error": "Task not found"}

def audit_update_agent_task(task_id: int, notes: Optional[str] = None) -> Dict[str, Any]:
    db = get_audit_db()
        
    current_task = db.get_task(task_id)
    if not current_task:
        return {"error": "Task not found"}
        
    success = db.update_task_status(task_id, current_task['status'], notes)
    if notes:
        db.log_progress(f"Task {task_id} updated: {notes}", task_id=task_id)
    return {"success": success}

def audit_submit_agent_task_summary(task_id: int, summary: str) -> Dict[str, Any]:
    db = get_audit_db()
    success = db.update_task_summary(task_id, summary)
    return {"success": success}

def audit_get_agent_task_summary(task_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    task = db.get_task(task_id)
    if task:
        return {"task_id": task_id, "summary": task.get("summary")}
    return {"task_id": task_id, "summary": None, "error": "Task not found"}

def audit_delete_agent_task(task_id: int) -> Dict[str, Any]:
    db = get_audit_db()
    success = db.delete_task(task_id)
    return {"success": success}

def audit_list_agent_tasks() -> List[Dict[str, Any]]:
    db = get_audit_db()
    tasks = db.get_tasks()
    for t in tasks:
        t['type'] = t['task_type']
        t.pop('summary', None)
        t.pop('notes', None)
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

# ========== Finding Tools ==========

def audit_report_finding(binary_name: str, severity: str, category: str, title: str, description: str,
                       function_name: str = None, address = None,
                       evidence: str = None, cvss: float = None,
                       exploitability: str = None) -> Dict[str, Any]:
    """Report a confirmed or suspected security finding."""
    db = get_audit_db()
    
    vuln_id = db.add_finding(
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
    return {"finding_id": vuln_id, "status": "success"}

def audit_get_findings(binary_name: str = None, severity: str = None,
                       category: str = None, verification_status: str = None) -> List[Dict[str, Any]]:
    """Query reported security findings."""
    db = get_audit_db()
    return db.get_findings(
        binary_name=binary_name,
        severity=severity,
        category=category,
        verification_status=verification_status
    )

def audit_report_finding_verification(id: int, status: str, details: str = None) -> Dict[str, Any]:
    """Update the verification status of a finding."""
    db = get_audit_db()
    success = db.update_finding_verification(
        vuln_id=id,
        status=status,
        details=details if details else ""
    )
    return {"success": success}


def audit_record_browse(binary_name: str, record_type: str, target_type: str,
                        target_value: Optional[str] = None, view_types: Optional[str] = None) -> Dict[str, Any]:
    """Record that the agent has viewed a specific item.

    Args:
        binary_name: The binary file name.
        record_type: Type of record (function, string, symbol, import, export, xref).
        target_type: Type of target (function_name, address, etc).
        target_value: The target identifier (function name, address, etc).
        view_types: Comma-separated view types (disasm, pseudocode, callers, etc).

    Returns:
        dict: Contains record_id and status.
    """
    db = get_audit_db()
    record_id = db.add_browse_record(
        binary_name=binary_name,
        record_type=record_type,
        target_type=target_type,
        target_value=target_value,
        view_types=view_types
    )
    # Update summary
    db.update_browse_summary(binary_name, record_type)
    return {"record_id": record_id, "status": "success"}

def audit_get_browse_statistics(binary_name: str) -> Dict[str, Any]:
    """Get browse statistics for a binary.

    Args:
        binary_name: The binary file name.

    Returns:
        dict: Statistics including totals, viewed counts, and coverage percentages.
    """
    db = get_audit_db()
    return db.get_browse_statistics(binary_name)

def audit_init_browse_summaries(binary_name: str, total_functions: int = 0, total_strings: int = 0,
                                total_symbols: int = 0, total_imports: int = 0, total_exports: int = 0) -> Dict[str, Any]:
    """Initialize or update total counts for browse statistics.

    Args:
        binary_name: The binary file name.
        total_functions: Total number of functions in the binary.
        total_strings: Total number of strings in the binary.
        total_symbols: Total number of symbols in the binary.
        total_imports: Total number of imports in the binary.
        total_exports: Total number of exports in the binary.

    Returns:
        dict: Contains success boolean.
    """
    db = get_audit_db()
    success = db.init_browse_summaries(
        binary_name=binary_name,
        total_functions=total_functions,
        total_strings=total_strings,
        total_symbols=total_symbols,
        total_imports=total_imports,
        total_exports=total_exports
    )
    return {"success": success}

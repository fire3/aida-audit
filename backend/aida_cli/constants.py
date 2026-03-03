AUDIT_DB_FILENAME = "aida_audit.db"
VALID_PLAN_STATUSES = ["pending", "in_progress", "completed", "failed"]
VALID_TASK_TYPES = ["ANALYSIS", "VERIFICATION"]

NOTE_TYPES = [
    "finding",
    "behavior",
    "function_summary",
    "data_structure",
    "control_flow",
    "crypto_usage",
    "obfuscation",
    "io_operation",
    "general"
]

VULNERABILITY_CATEGORIES = [
    "buffer_overflow",
    "format_string",
    "integer_overflow",
    "use_after_free",
    "double_free",
    "memory_disclosure",
    "crypto_weak",
    "hardcoded_secret",
    "injection",
    "path_traversal",
    "authentication",
    "authorization",
    "anti_debug",
    "anti_vm",
    "packing",
    "other"
]

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

CONFIDENCE_LEVELS = ["high", "medium", "low", "speculative"]

PREDEFINED_TAGS = [
    "security", "performance", "reliability",
    "priority-high", "priority-medium", "priority-low",
    "confirmed", "suspected", "needs-review",
    "anti-debug", "anti-vm", "obfuscation",
    "network", "file-io", "process", "crypto"
]


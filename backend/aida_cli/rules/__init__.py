from typing import Dict, Type
from .base import BaseRule
from .cwe_78 import CWE78Rule

# Registry for all available rules
_RULES: Dict[str, Type[BaseRule]] = {
    "cwe-78": CWE78Rule,
}

def get_all_rules() -> Dict[str, Type[BaseRule]]:
    return _RULES

def get_rule(name: str) -> Type[BaseRule]:
    return _RULES.get(name)

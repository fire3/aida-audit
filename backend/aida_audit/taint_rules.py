import re
from typing import Dict, List, Optional, Any

from .ida_microcode import CrossFuncRule


class RuleSet:
    """Rule container with compiled name/regex matchers."""
    def __init__(self, rule_id, cwe, title, severity, sources, sinks, propagators, cross_rules=None):
        self.rule_id = rule_id
        self.cwe = cwe
        self.title = title
        self.severity = severity
        self.sources = self._compile_rules(sources)
        self.sinks = self._compile_rules(sinks)
        self.propagators = self._compile_rules(propagators)
        self.cross_rules = self._compile_cross_rules(cross_rules)

    def _compile_rules(self, rules):
        compiled = []
        for rule in rules or []:
            entry = dict(rule)
            pattern = entry.get("pattern")
            if pattern:
                entry["regex"] = re.compile(pattern, re.IGNORECASE)
            compiled.append(entry)
        return compiled

    def _compile_cross_rules(self, rules):
        compiled = []
        for rule in rules or []:
            if isinstance(rule, CrossFuncRule):
                compiled.append(rule)
                continue
            if isinstance(rule, dict):
                compiled.append(
                    CrossFuncRule(
                        name=rule.get("name") or "cross_rule",
                        caller_pattern=rule.get("caller_pattern"),
                        callee_pattern=rule.get("callee_pattern"),
                        caller_ea=rule.get("caller_ea"),
                        callee_ea=rule.get("callee_ea"),
                        arg_flows=rule.get("arg_flows") or [],
                        ret_flow=rule.get("ret_flow"),
                        ret_to_args=rule.get("ret_to_args") or [],
                    )
                )
        return compiled


def default_cwe78_rules():
    """Built-in CWE-78 ruleset for OS command injection."""
    sources = [
        {"name": "recv", "args": [1], "label": "recv"},
        {"name": "recvfrom", "args": [1], "label": "recvfrom"},
        {"name": "read", "args": [1], "label": "read"},
        {"name": "fread", "args": [0], "label": "fread"},
        {"name": "fgets", "args": [0], "label": "fgets"},
        {"name": "gets", "args": [0], "label": "gets"},
        {"name": "gets_s", "args": [0], "label": "gets_s"},
        {"name": "scanf", "args": [1], "label": "scanf"},
        {"name": "fscanf", "args": [1], "label": "fscanf"},
        {"name": "scanf_s", "args": [1], "label": "scanf_s"},
        {"name": "getline", "args": [0], "ret": True, "label": "getline"},
        {"name": "recvmsg", "args": [1], "label": "recvmsg"},
        {"name": "getenv", "ret": True, "label": "getenv"},
    ]
    sinks = [
        {"name": "system", "args": [0]},
        {"name": "popen", "args": [0]},
        {"name": "execl", "args": None},
        {"name": "execlp", "args": None},
        {"name": "execle", "args": None},
        {"name": "execv", "args": None},
        {"name": "execve", "args": None},
        {"name": "execvp", "args": None},
        {"name": "CreateProcessA", "args": [1]},
        {"name": "CreateProcessW", "args": [1]},
        {"name": "WinExec", "args": [0]},
        {"name": "ShellExecuteA", "args": [2]},
        {"name": "ShellExecuteW", "args": [2]},
        {"name": "ShellExecuteExA", "args": [0]},
        {"name": "ShellExecuteExW", "args": [0]},
    ]
    propagators = [
        {"name": "strcpy", "from_args": [1], "to_args": [0]},
        {"name": "strncpy", "from_args": [1], "to_args": [0]},
        {"name": "strcat", "from_args": [1], "to_args": [0]},
        {"name": "strncat", "from_args": [1], "to_args": [0]},
        {"name": "sprintf", "from_args": [1], "to_args": [0]},
        {"name": "snprintf", "from_args": [2], "to_args": [0]},
        {"name": "memcpy", "from_args": [1], "to_args": [0]},
        {"name": "memmove", "from_args": [1], "to_args": [0]},
        {"name": "strdup", "from_args": [0], "to_ret": True},
        {"pattern": r"^_*strncat_chk$", "from_args": [1], "to_args": [0]},
        {"pattern": r"^_*strcat_chk$", "from_args": [1], "to_args": [0]},
        {"pattern": r"^_*strncpy_chk$", "from_args": [1], "to_args": [0]},
        {"pattern": r"^_*strcpy_chk$", "from_args": [1], "to_args": [0]},
        {"pattern": r"^_*memcpy_chk$", "from_args": [1], "to_args": [0]},
        {"pattern": r"^_*memmove_chk$", "from_args": [1], "to_args": [0]},
        {"name": "getenv", "from_ret": True, "to_ret": True},
        {"name": "getline", "from_ret": True, "to_ret": True},
    ]
    cross_rules = []
    return RuleSet(
        rule_id="cwe-78",
        cwe="CWE-78",
        title="OS Command Injection",
        severity="high",
        sources=sources,
        sinks=sinks,
        propagators=propagators,
        cross_rules=cross_rules,
    )

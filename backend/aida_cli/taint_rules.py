import re


class RuleSet:
    """Rule container with compiled name/regex matchers."""
    def __init__(self, rule_id, cwe, title, severity, sources, sinks, propagators):
        self.rule_id = rule_id
        self.cwe = cwe
        self.title = title
        self.severity = severity
        self.sources = self._compile_rules(sources)
        self.sinks = self._compile_rules(sinks)
        self.propagators = self._compile_rules(propagators)

    def _compile_rules(self, rules):
        compiled = []
        for rule in rules or []:
            entry = dict(rule)
            pattern = entry.get("pattern")
            if pattern:
                entry["regex"] = re.compile(pattern, re.IGNORECASE)
            compiled.append(entry)
        return compiled


def default_cwe78_rules():
    """Built-in CWE-78 ruleset for OS command injection."""
    sources = [
        {"name": "recv", "args": [1], "label": "recv"},
        {"name": "recvfrom", "args": [1], "label": "recvfrom"},
        {"name": "read", "args": [1], "label": "read"},
        {"name": "fgets", "args": [0], "label": "fgets"},
        {"name": "gets", "args": [0], "label": "gets"},
        {"name": "scanf", "args": [1], "label": "scanf"},
        {"name": "fscanf", "args": [1], "label": "fscanf"},
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
    ]
    return RuleSet(
        rule_id="cwe-78",
        cwe="CWE-78",
        title="OS Command Injection",
        severity="high",
        sources=sources,
        sinks=sinks,
        propagators=propagators,
    )

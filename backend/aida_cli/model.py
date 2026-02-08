from typing import List, Dict, Any

# --- Graph Schema Constants ---
# Node Labels
NODE_PROG = "Program"
NODE_FUNC = "Function"
NODE_BLOCK = "Block"
NODE_INSTR = "Instr"
NODE_CALL = "CallSite"
NODE_VAR = "Var"
NODE_CONST = "Const"
NODE_STRING = "String"
NODE_MEM = "Mem"
NODE_EXPR = "Expr"

# Edge Types
EDGE_HAS_FUNC = "HAS_FUNCTION"
EDGE_HAS_BLOCK = "HAS_BLOCK"
EDGE_HAS_INSTR = "HAS_INSTR"
EDGE_CFG = "CFG_BB"
EDGE_CALL_OF = "CALLSITE_OF"
EDGE_ARG = "ARG"
EDGE_RET = "RET"
EDGE_DEF = "DEF"
EDGE_USE = "USE"

class Finding:
    def __init__(self, rule_id, cwe, title, severity, binary_id, func_ea, sink, sources, evidence):
        self.rule_id = rule_id
        self.cwe = cwe
        self.title = title
        self.severity = severity
        self.binary_id = binary_id
        self.func_ea = func_ea
        self.sink = sink
        self.sources = sources
        self.evidence = evidence

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "title": self.title,
            "severity": self.severity,
            "binary_id": self.binary_id,
            "func_ea": self.func_ea,
            "sink": self.sink,
            "sources": [s for s in self.sources],
            "evidence": self.evidence
        }

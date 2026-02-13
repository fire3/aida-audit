from dataclasses import dataclass, field
from typing import Optional, Set, Dict, List, FrozenSet, Tuple, Deque, Any
from collections import deque

from .common import (
    OperandAttr,
    InsnInfo,
)
from .state import TaintOrigin


@dataclass(frozen=True, order=True)
class WorkItem:
    block_id: int
    insn_idx: int
    insn: InsnInfo
    reason: str = "initial"
    priority: int = 0


@dataclass
class Block:
    block_id: int
    insns: List[InsnInfo] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)


@dataclass
class CFG:
    blocks: Dict[int, Block] = field(default_factory=dict)
    entry_block: int = 0
    exit_blocks: List[int] = field(default_factory=list)

    def get_block(self, block_id: int) -> Optional[Block]:
        return self.blocks.get(block_id)

    def add_block(self, block: Block):
        self.blocks[block.block_id] = block


@dataclass(frozen=True, order=True)
class AliasChange:
    from_attr: OperandAttr
    to_attr: OperandAttr
    reason: str = ""


@dataclass
class TaintPolicy:
    propagate_through_moves: bool = True
    propagate_through_arithmetic: bool = True
    propagate_through_load: bool = True
    propagate_through_store: bool = True
    follow_aliases: bool = True
    max_alias_chain_depth: int = 10
    max_loop_iterations: int = 3
    force_loop_convergence: bool = True
    max_total_iterations: int = 1000
    early_termination_threshold: float = 0.01


@dataclass
class Finding:
    rule_id: str
    cwe: str
    title: str
    severity: str
    func_name: str
    func_ea: str
    sink: Dict
    arg_indexes: List[int]
    taint_labels: List[str]
    sources: List[Dict]
    type: str = "sink"
    intra_proc_path: List[Dict] = field(default_factory=list)
    inter_proc_path: List[Dict] = field(default_factory=list)
    propagation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "title": self.title,
            "severity": self.severity,
            "func_name": self.func_name,
            "func_ea": self.func_ea,
            "sink": self.sink,
            "arg_indexes": self.arg_indexes,
            "taint_labels": self.taint_labels,
            "sources": self.sources,
            "type": self.type,
            "intra_proc_path": self.intra_proc_path,
            "inter_proc_path": self.inter_proc_path,
            "propagation_steps": self.propagation_steps,
        }

    def __hash__(self):
        return hash((self.rule_id, self.func_ea, self.sink.get("ea"), tuple(sorted(self.arg_indexes))))

    def __eq__(self, other):
        if not isinstance(other, Finding):
            return False
        return (self.rule_id, self.func_ea, self.sink.get("ea"), tuple(sorted(self.arg_indexes))) == \
               (other.rule_id, other.func_ea, other.sink.get("ea"), tuple(sorted(other.arg_indexes)))


@dataclass
class CallEdge:
    caller_ea: int
    callee_ea: int
    call_site_ea: int
    caller_arg_count: int = 0
    callee_arg_count: int = 0
    arg_mapping: Dict[int, int] = field(default_factory=dict)
    ret_mapping: Optional[int] = None
    call_insn_text: str = ""

    def __hash__(self):
        return hash((self.caller_ea, self.callee_ea, self.call_site_ea))

    def __eq__(self, other):
        if not isinstance(other, CallEdge):
            return False
        return (self.caller_ea, self.callee_ea, self.call_site_ea) == (
            other.caller_ea, other.callee_ea, other.call_site_ea
        )


@dataclass
class FunctionContext:
    func_ea: int
    func_name: str
    arg_count: int = 0
    arg_taints: Dict[int, Tuple[Set[str], Set[TaintOrigin]]] = field(default_factory=dict)
    ret_taint: Optional[Tuple[Set[str], Set[TaintOrigin]]] = None
    out_arg_taints: Dict[int, Tuple[Set[str], Set[TaintOrigin]]] = field(default_factory=dict)
    analyzed: bool = False


@dataclass
class InterProcState:
    call_graph: Dict[int, List[CallEdge]] = field(default_factory=dict)
    func_contexts: Dict[int, FunctionContext] = field(default_factory=dict)
    analyzed_functions: Set[int] = field(default_factory=set)
    pending_calls: Deque[CallEdge] = field(default_factory=lambda: deque())
    source_sink_paths: List[List[Dict[str, Any]]] = field(default_factory=list)
    source_sink_history: List[List[List[Dict[str, Any]]]] = field(default_factory=list)
    analyzing_funcs: Set[int] = field(default_factory=set)
    global_taints: Dict[str, Tuple[Set[str], Set[TaintOrigin]]] = field(default_factory=dict)


@dataclass
class CrossFuncRule:
    name: str
    caller_pattern: Optional[str] = None
    callee_pattern: Optional[str] = None
    caller_ea: Optional[int] = None
    callee_ea: Optional[int] = None
    arg_flows: List[Tuple[int, int]] = field(default_factory=list)
    ret_flow: Optional[str] = None
    ret_to_args: List[int] = field(default_factory=list)

    def matches(self, caller_name: str, callee_name: str, caller_ea: int, callee_ea: int) -> bool:
        if self.caller_ea is not None and caller_ea != self.caller_ea:
            return False
        if self.callee_ea is not None and callee_ea != self.callee_ea:
            return False
        if self.caller_pattern is not None:
            import re
            if not re.match(self.caller_pattern, caller_name):
                return False
        if self.callee_pattern is not None:
            import re
            if not re.match(self.callee_pattern, callee_name):
                return False
        return True


__all__ = [
    "WorkItem",
    "Block",
    "CFG",
    "AliasChange",
    "TaintPolicy",
    "Finding",
    "CallEdge",
    "FunctionContext",
    "InterProcState",
    "CrossFuncRule",
]

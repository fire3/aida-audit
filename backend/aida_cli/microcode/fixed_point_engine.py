from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Optional, Set, Dict, List, FrozenSet, Tuple, Deque
from copy import deepcopy

from .state import TaintState, TaintOrigin, TaintEntry
from .analyzer import analyze_function
from .utils import MicroCodeUtils
from .common import (
    LocalVarAttr,
    AddressAttr,
    LoadAttr,
    RegisterAttr,
    OperandAttr,
    InsnInfo,
    CallInfo,
    FuncInfo,
)
from .constants import (
    idc,
    ida_funcs,
    idautils,
    BADADDR,
    ida_hexrays,
)
from ..pathfinder import PathFinder, PathFinderConfig


@dataclass(frozen=True)
class WorkItem:
    block_id: int
    insn_idx: int
    insn: InsnInfo
    reason: str = "initial"
    priority: int = 0

    def __lt__(self, other):
        return self.priority > other.priority


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


@dataclass(frozen=True)
class AliasChange:
    from_attr: OperandAttr
    to_attr: OperandAttr
    reason: str = ""

    def __lt__(self, other):
        return (self.from_attr, self.to_attr, self.reason) < (
            other.from_attr, other.to_attr, other.reason
        )


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
        }


class SimpleLogger:
    def __init__(self, verbose=False):
        import logging
        self._logger = logging.getLogger("FixedPointTaintEngine")
        self._verbose = verbose

    def log(self, message):
        if self._verbose:
            self._logger.info(message)
        else:
            self._logger.debug(message)

    def debug(self, message):
        self._logger.debug(message)

    def info(self, message):
        self._logger.info(message)

    def warn(self, message):
        self._logger.warning(message)

    def error(self, message):
        self._logger.error(message)


class RuleResolver:
    def __init__(self, ruleset, logger):
        self.ruleset = ruleset
        self.logger = logger

    def resolve_rules(self):
        if not idc:
            return
        for rule in self._iter_rules():
            name = rule.get("name")
            if not name:
                continue
            ea = self.resolve_rule_ea(name)
            if ea is not None:
                rule["ea"] = ea

    def resolve_rule_ea(self, name):
        def try_name(value):
            if idc:
                try:
                    return idc.get_name_ea_simple(value)
                except Exception:
                    pass
            return BADADDR

        for candidate in (
            name,
            "_" + name,
            "__imp_" + name,
            "__imp__" + name,
            "." + name,
        ):
            ea = try_name(candidate)
            if ea != BADADDR:
                return ea
        return None

    def _iter_rules(self):
        for rule in self.ruleset.sources:
            yield rule
        for rule in self.ruleset.sinks:
            yield rule
        for rule in self.ruleset.propagators:
            yield rule


class AliasAnalyzer:
    def __init__(self, state: TaintState, utils: MicroCodeUtils, logger: SimpleLogger):
        self.state = state
        self.utils = utils
        self.logger = logger

    def analyze(self, insn: InsnInfo) -> List[AliasChange]:
        changes = []

        if self.utils.is_move_opcode(insn.opcode):
            changes.extend(self._handle_move(insn))

        if self._is_address_taken(insn):
            changes.extend(self._handle_address_taken(insn))

        if self._is_load(insn):
            changes.extend(self._handle_load(insn))

        if self._is_store(insn):
            changes.extend(self._handle_store(insn))

        return changes

    def _handle_move(self, insn: InsnInfo) -> List[AliasChange]:
        changes = []
        if len(insn.reads) != 1 or len(insn.writes) != 1:
            return changes

        src = insn.reads[0].attr
        dst = insn.writes[0].attr

        if src is None or dst is None:
            return changes

        if isinstance(src, AddressAttr):
            if self.state.add_alias(dst, src.inner):
                changes.append(AliasChange(dst, src.inner, "mov_address"))
                self.logger.log(f"[ALIAS] {dst} -> {src.inner}")

        if isinstance(dst, LoadAttr):
            if self.state.add_alias(dst, src):
                changes.append(AliasChange(dst, src, "mov_load"))
                self.logger.log(f"[ALIAS] {dst} -> {src}")

        return changes

    def _is_address_taken(self, insn: InsnInfo) -> bool:
        if not insn.writes:
            return False
        write = insn.writes[0]
        if write.attr and isinstance(write.attr, AddressAttr):
            return True
        return False

    def _handle_address_taken(self, insn: InsnInfo) -> List[AliasChange]:
        changes = []
        if len(insn.reads) != 1 or len(insn.writes) != 1:
            return changes

        src = insn.reads[0].attr
        dst = insn.writes[0].attr

        if src is None or dst is None:
            return changes

        if isinstance(dst, AddressAttr):
            if self.state.add_alias(dst.inner, src):
                changes.append(AliasChange(dst.inner, src, "address_taken"))
                self.logger.log(f"[ALIAS] &{src} -> {dst.inner}")

        return changes

    def _is_load(self, insn: InsnInfo) -> bool:
        return insn.opcode in ("mov", "op_4") and len(insn.reads) >= 1

    def _handle_load(self, insn: InsnInfo) -> List[AliasChange]:
        changes = []
        return changes

    def _is_store(self, insn: InsnInfo) -> bool:
        return self.utils.is_store_opcode(insn.opcode)

    def _handle_store(self, insn: InsnInfo) -> List[AliasChange]:
        changes = []
        return changes


class InstructionProcessor:
    def __init__(
        self,
        engine: "FixedPointTaintEngine",
        state: TaintState,
        logger: SimpleLogger,
    ):
        self.engine = engine
        self.state = state
        self.logger = logger
        self.utils = MicroCodeUtils()

    def process(self, insn: InsnInfo, block_id: int) -> List[Finding]:
        findings = []

        read_taint = self._collect_read_taint(insn)

        self._propagate_to_writes(insn, read_taint)

        self._handle_store(insn, read_taint)

        self._handle_call(insn, findings)

        return findings

    def _collect_read_taint(self, insn: InsnInfo) -> Tuple[Set[str], Set[TaintOrigin]]:
        labels = set()
        origins = set()

        for read in insn.reads:
            if read.attr is None:
                continue
            labels.update(self.state.get_taint(read.attr))
            origins.update(self.state.get_origins(read.attr))

        return labels, origins

    def _propagate_to_writes(self, insn: InsnInfo, read_taint: Tuple[Set[str], Set[TaintOrigin]]):
        labels, origins = read_taint
        if not labels or not insn.writes:
            return

        for write in insn.writes:
            if write.attr is None:
                continue
            if self.state.add_taint(write.attr, labels, origins):
                self.logger.log(f"[TAINT] Propagate {sorted(labels)} -> {write.attr}")

    def _handle_store(
        self, insn: InsnInfo, read_taint: Tuple[Set[str], Set[TaintOrigin]]
    ):
        labels, origins = read_taint
        if not labels or not self.utils.is_store_opcode(insn.opcode):
            return

        for read in insn.reads:
            if read.attr is None:
                continue
            resolved = self.state._resolve(read.attr)
            if resolved in self.state.aliases:
                target = self.state.aliases[resolved]
                self.state.add_taint(target, labels, origins)
                self.logger.log(f"[TAINT] Store {sorted(labels)} -> {target}")

    def _handle_call(self, insn: InsnInfo, findings: List[Finding]):
        for call in insn.calls:
            self._apply_sources(call, insn)
            self._apply_propagators(call)
            self._apply_default_return_propagation(call)
            self._apply_sinks(call, insn, findings)

    def _resolve_callee(self, call: CallInfo):
        callee = call.callee_name or ""
        target = call.target
        callee_ea = None

        if target is not None and hasattr(target, "ea"):
            callee_ea = target.ea

        if callee_ea is None and callee:
            callee_ea = self.engine.rule_resolver.resolve_rule_ea(callee)

        if callee_ea is not None:
            ida_name = None
            if ida_funcs:
                ida_name = ida_funcs.get_func_name(callee_ea)
            if not ida_name and idc:
                try:
                    ida_name = idc.get_name(callee_ea)
                except Exception:
                    pass
            if ida_name:
                callee = ida_name

        return callee, callee_ea

    def _collect_arg_taint(self, args: List[OperandAttr]) -> Tuple[Set[str], Set[TaintOrigin]]:
        labels = set()
        origins = set()
        for arg in args:
            if arg is None:
                continue
            labels.update(self.state.get_taint(arg))
            origins.update(self.state.get_origins(arg))
        return labels, origins

    def _rule_matches(self, rule, callee, callee_ea=None):
        if "ea" not in rule:
            if "regex" in rule and callee:
                import re
                match = re.match(rule["regex"], callee)
                return match is not None
            return False
        if callee_ea is None:
            return False
        return rule["ea"] == callee_ea

    def _apply_sources(self, call: CallInfo, insn: InsnInfo):
        callee, callee_ea = self._resolve_callee(call)
        args = call.args or []

        for rule in self.engine.ruleset.sources:
            if not self._rule_matches(rule, callee, callee_ea):
                continue

            label = rule.get("label") or callee
            origins = {(label, insn.ea, self.engine.func_info.function)}
            out_args = rule.get("out_args") or rule.get("args") or []

            self.logger.log(f"[SOURCE] Matched: {rule.get('name')} -> label={label}")

            for idx in out_args:
                if idx < 0 or idx >= len(args):
                    continue
                attr = args[idx]
                if attr and self.state.add_taint(attr, {label}, origins):
                    self.logger.log(f"[SOURCE] Taint added to arg[{idx}]")

            if rule.get("ret") and call.ret:
                self.state.add_taint(call.ret, {label}, origins)

    def _apply_propagators(self, call: CallInfo):
        callee, callee_ea = self._resolve_callee(call)
        args = call.args or []

        for rule in self.engine.ruleset.propagators:
            if not self._rule_matches(rule, callee, callee_ea):
                continue

            from_args = rule.get("from_args")
            if from_args is None:
                from_args = list(range(len(args)))

            valid_args = [args[i] for i in from_args if i < len(args)]
            labels, origins = self._collect_arg_taint(valid_args)

            if not labels:
                continue

            to_args = rule.get("to_args") or []
            for idx in to_args:
                if idx < 0 or idx >= len(args):
                    continue
                attr = args[idx]
                if attr:
                    self.state.add_taint(attr, labels, origins)

            if rule.get("to_ret") and call.ret:
                self.state.add_taint(call.ret, labels, origins)

    def _apply_default_return_propagation(self, call: CallInfo):
        if not call.ret:
            return
        args = call.args or []
        labels, origins = self._collect_arg_taint(args)
        if labels:
            self.state.add_taint(call.ret, labels, origins)

    def _apply_sinks(self, call: CallInfo, insn: InsnInfo, findings: List[Finding]):
        callee, callee_ea = self._resolve_callee(call)
        args = call.args or []

        for rule in self.engine.ruleset.sinks:
            if not self._rule_matches(rule, callee, callee_ea):
                continue

            arg_indexes = rule.get("args")
            if arg_indexes is None:
                arg_indexes = list(range(len(args)))

            tainted_args = []
            labels = set()
            origins = set()

            for idx in arg_indexes:
                if idx < 0 or idx >= len(args):
                    continue
                attr = args[idx]
                if attr is None:
                    continue

                t = self.state.get_taint(attr)
                if not t:
                    continue

                for label in t:
                    if label.startswith("SYM:ARG:"):
                        try:
                            findings.append(
                                Finding(
                                    rule_id=self.engine.ruleset.rule_id,
                                    cwe=self.engine.ruleset.cwe,
                                    title=self.engine.ruleset.title,
                                    severity=self.engine.ruleset.severity,
                                    func_name=self.engine.func_info.function,
                                    func_ea=self.engine.func_info.ea,
                                    sink={"name": callee, "ea": insn.ea},
                                    arg_indexes=[int(label.split(":")[2])],
                                    taint_labels=[label],
                                    sources=[],
                                )
                            )
                        except Exception:
                            pass

                tainted_args.append(idx)
                labels.update(t)
                origins.update(self.state.get_origins(attr))

            if tainted_args:
                self.logger.log(f"[SINK] Matched: {callee} args={tainted_args}")
                findings.append(
                    Finding(
                        rule_id=self.engine.ruleset.rule_id,
                        cwe=self.engine.ruleset.cwe,
                        title=self.engine.ruleset.title,
                        severity=self.engine.ruleset.severity,
                        func_name=self.engine.func_info.function,
                        func_ea=self.engine.func_info.ea,
                        sink={"name": callee, "ea": insn.ea},
                        arg_indexes=tainted_args,
                        taint_labels=sorted(labels),
                        sources=[{"label": o[0], "ea": o[1], "function": o[2]} for o in sorted(origins)],
                    )
                )


class CFGBuilder:
    def __init__(self, func_info: FuncInfo, logger: SimpleLogger):
        self.func_info = func_info
        self.logger = logger
        self.cfg = CFG()

    def build(self) -> CFG:
        self._build_blocks()
        self._connect_blocks()
        return self.cfg

    def _build_blocks(self):
        blocks = defaultdict(list)

        for insn in self.func_info.insns:
            block_id = insn.block_id
            blocks[block_id].append(insn)

        for block_id, insns in blocks.items():
            self.cfg.blocks[block_id] = Block(
                block_id=block_id, insns=insns
            )

        if self.func_info.insns:
            first_block = self.func_info.insns[0].block_id
            self.cfg.entry_block = first_block

    def _connect_blocks(self):
        for block_id, block in self.cfg.blocks.items():
            if not block.insns:
                continue

            last_insn = block.insns[-1]

            if self._is_unconditional_jump(last_insn):
                successors = self._get_jump_targets(last_insn)
                block.successors.extend(successors)

            elif self._is_conditional_jump(last_insn):
                successors = self._get_jump_targets(last_insn)
                block.successors.extend(successors)

            else:
                next_block = self._get_next_block(block_id)
                if next_block is not None:
                    block.successors.append(next_block)

        for block_id, block in self.cfg.blocks.items():
            for succ_id in block.successors:
                if succ_id in self.cfg.blocks:
                    self.cfg.blocks[succ_id].predecessors.append(block_id)

        self.cfg.exit_blocks = [
            bid for bid, b in self.cfg.blocks.items()
            if not b.successors
        ]

    def _is_unconditional_jump(self, insn: InsnInfo) -> bool:
        return insn.opcode in ("goto", "jmp")

    def _is_conditional_jump(self, insn: InsnInfo) -> bool:
        return insn.opcode in ("jz", "jnz", "jc", "jnc", "jo", "jno", "js", "jns")

    def _get_jump_targets(self, insn: InsnInfo) -> List[int]:
        targets = []
        for read in insn.reads:
            if read.attr and hasattr(read.attr, "block_id"):
                targets.append(read.attr.block_id)
        return targets

    def _get_next_block(self, current_block_id: int) -> Optional[int]:
        block_ids = sorted(self.cfg.blocks.keys())
        try:
            idx = block_ids.index(current_block_id)
            if idx + 1 < len(block_ids):
                return block_ids[idx + 1]
        except ValueError:
            pass
        return None


class FixedPointTaintEngine:
    def __init__(
        self,
        ruleset,
        logger: SimpleLogger = None,
        verbose: bool = False,
        policy: TaintPolicy = None,
    ):
        self.ruleset = ruleset
        self.logger = logger or SimpleLogger(verbose=verbose)
        self.utils = MicroCodeUtils()
        self.rule_resolver = RuleResolver(ruleset, self.logger)
        self.pathfinder_config = PathFinderConfig(max_depth=10)
        self.pathfinder = PathFinder(ruleset, self.logger, self.pathfinder_config)
        self.policy = policy or TaintPolicy()
        self.func_info: Optional[FuncInfo] = None
        self.cfg: Optional[CFG] = None
        self.worklist: Deque[WorkItem] = deque()
        self.state = TaintState()
        self.visited_items: Set[Tuple[int, int]] = set()

    def analyze_function(self, func_info: FuncInfo) -> Tuple[TaintState, List[Finding]]:
        self.func_info = func_info
        self.state = TaintState()
        self.worklist = deque()
        self.visited_items = set()

        self.logger.log(f"[ENGINE] Analyzing {func_info.function}")

        self._build_cfg()
        self._initialize_worklist()
        self._initialize_with_sources()

        findings = self._run_fixed_point_iteration()

        self.logger.log(f"[ENGINE] Final state: {self.state}")
        return self.state, findings

    def _build_cfg(self):
        builder = CFGBuilder(self.func_info, self.logger)
        self.cfg = builder.build()
        self.logger.log(f"[CFG] Built {len(self.cfg.blocks)} blocks")

    def _initialize_worklist(self):
        for block_id, block in self.cfg.blocks.items():
            for insn_idx, insn in enumerate(block.insns):
                self.worklist.append(
                    WorkItem(
                        block_id=block_id,
                        insn_idx=insn_idx,
                        insn=insn,
                        reason="initial",
                        priority=0,
                    )
                )

    def _initialize_with_sources(self):
        for rule in self.ruleset.sources:
            if "ea" not in rule:
                continue
            if "ret" not in rule and not rule.get("args") and not rule.get("out_args"):
                continue
            self.logger.log(f"[SOURCE] Initializing: {rule.get('name')}")

    def _run_fixed_point_iteration(self) -> List[Finding]:
        findings = []
        iteration = 0
        processed_count = 0
        last_change_count = 0

        while self.worklist:
            iteration += 1

            if iteration > self.policy.max_total_iterations:
                self.logger.warn(f"Exceeded max iterations ({self.policy.max_total_iterations})")
                break

            work_item = self.worklist.popleft()
            key = (work_item.block_id, work_item.insn_idx)

            if key in self.visited_items and work_item.reason == "initial":
                continue

            self.visited_items.add(key)
            processed_count += 1

            old_entry_count = len(self.state.entries)
            old_alias_count = len(self.state.aliases)

            processor = InstructionProcessor(self, self.state, self.logger)
            new_findings = processor.process(work_item.insn, work_item.block_id)
            findings.extend(new_findings)

            new_entry_count = len(self.state.entries)
            new_alias_count = len(self.state.aliases)

            entry_changed = new_entry_count != old_entry_count
            alias_changed = new_alias_count != old_alias_count

            if entry_changed or alias_changed:
                self._notify_successors(work_item.block_id, work_item.insn_idx)

            last_change_count += 1

            if iteration % 100 == 0:
                self.logger.log(
                    f"[ENGINE] Iteration {iteration}: processed={processed_count}, "
                    f"entries={new_entry_count}, aliases={new_alias_count}"
                )

        self.logger.log(
            f"[ENGINE] Completed {iteration} iterations, processed {processed_count} items"
        )
        return findings

    def _notify_successors(self, block_id: int, insn_idx: int):
        block = self.cfg.get_block(block_id)
        if not block:
            return

        if insn_idx < len(block.insns) - 1:
            next_idx = insn_idx + 1
            next_key = (block_id, next_idx)
            if next_key not in self.visited_items:
                self.worklist.append(
                    WorkItem(
                        block_id=block_id,
                        insn_idx=next_idx,
                        insn=block.insns[next_idx],
                        reason="taint_change",
                        priority=1,
                    )
                )

        for succ_id in block.successors:
            succ_block = self.cfg.get_block(succ_id)
            if succ_block and succ_block.insns:
                first_insn_key = (succ_id, 0)
                if first_insn_key not in self.visited_items:
                    self.worklist.append(
                        WorkItem(
                            block_id=succ_id,
                            insn_idx=0,
                            insn=succ_block.insns[0],
                            reason="taint_change",
                            priority=1,
                        )
                    )

    def _find_insn(self, block_id: int, insn_idx: int) -> Optional[InsnInfo]:
        block = self.cfg.get_block(block_id)
        if block and insn_idx < len(block.insns):
            return block.insns[insn_idx]
        return None

    def scan_function(self, func_info: FuncInfo):
        return self.analyze_function(func_info)


class WorklistTaintEngine:
    def __init__(self, ruleset, logger=None, verbose=False):
        self.ruleset = ruleset
        self.logger = logger or SimpleLogger(verbose=verbose)
        self.engine = FixedPointTaintEngine(ruleset, self.logger, verbose)

    def scan_function(self, func_info: FuncInfo):
        return self.engine.analyze_function(func_info)

    def scan_global(self, maturity):
        self.engine.rule_resolver.resolve_rules()

        self.engine.pathfinder.ruleset = self.ruleset
        self.engine.pathfinder.identify_markers()
        path_result = self.engine.pathfinder.find_paths()

        if not path_result:
            return []

        raw_chains = [p["nodes"] for p in path_result]

        chain_functions = set()
        for path in raw_chains:
            for node in path:
                ea = int(node["ea"], 16)
                chain_functions.add(ea)

        if not chain_functions:
            return []

        chain_functions = sorted(chain_functions, key=lambda x: x)

        findings = []
        for ea in chain_functions:
            func = ida_funcs.get_func(ea)
            if not func:
                continue

            func_info = analyze_function(func, maturity)
            if func_info:
                state, f_findings = self.engine.analyze_function(func_info)

                real_findings = []
                proxy_findings = []
                for f in f_findings:
                    if hasattr(f, "type") and f.type == "sink_proxy":
                        proxy_findings.append(f)
                    else:
                        labels = f.taint_labels if hasattr(f, "taint_labels") else []
                        has_real = any(not str(label).startswith("SYM:ARG:") for label in labels)
                        if has_real or not labels:
                            real_findings.append(f)

                findings.extend(real_findings)

        for finding in findings:
            if hasattr(finding, "call_chains"):
                finding.call_chains = raw_chains
            else:
                finding.call_chains = raw_chains

        return findings


__all__ = [
    "WorkItem",
    "Block",
    "CFG",
    "AliasChange",
    "TaintPolicy",
    "Finding",
    "FixedPointTaintEngine",
    "WorklistTaintEngine",
]
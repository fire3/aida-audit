from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Optional, Set, Dict, List, FrozenSet, Tuple, Deque
from copy import deepcopy

from .state import TaintState, TaintOrigin, TaintEntry
from .analyzer import analyze_function
from .utils import MicroCodeUtils
from .common import (
    LocalVarAttr,
    StackAttr,
    AddressAttr,
    LoadAttr,
    StoreAttr,
    RegisterAttr,
    ImmediateAttr,
    StringAttr,
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
from .interproc_datatypes import (
    WorkItem,
    Block,
    CFG,
    AliasChange,
    TaintPolicy,
    Finding,
    CallEdge,
    FunctionContext,
    InterProcState,
    CrossFuncRule,
)


class SimpleLogger:
    def __init__(self, verbose=False):
        import logging
        self._logger = logging.getLogger("FixedPointTaintEngine")
        self._verbose = verbose
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.DEBUG)

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


from ..rule_matcher import RuleMatcher


def _log_info(logger, message):
    if hasattr(logger, "info"):
        logger.info(message)
    else:
        logger.log(message)


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
        if not insn.reads or not insn.writes:
            return changes

        src = insn.reads[0].attr
        dst = insn.writes[0].attr

        if src is None or dst is None:
            return changes

        address_src = None
        for read in insn.reads:
            if isinstance(read.attr, AddressAttr):
                address_src = read.attr
                break
        if address_src is not None:
            if self.state.add_alias(dst, address_src.inner):
                changes.append(AliasChange(dst, address_src.inner, "mov_address"))
                self.logger.log(f"[ALIAS] {dst} -> {address_src.inner}")

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
        if not insn.reads or not insn.writes:
            return changes

        read_attr = None
        for read in insn.reads:
            if isinstance(read.attr, LoadAttr):
                read_attr = read.attr
                break
        write_attr = insn.writes[0].attr
        if read_attr is None or write_attr is None:
            return changes

        if isinstance(read_attr, LoadAttr):
            ptr = read_attr.ptr
            while isinstance(ptr, LoadAttr):
                ptr = ptr.ptr
            target = None
            if isinstance(ptr, AddressAttr):
                target = ptr.inner
            elif ptr in self.state.aliases:
                target = self.state.aliases[ptr]
            if target is not None and self.state.add_alias(write_attr, target):
                changes.append(AliasChange(write_attr, target, "load"))
                self.logger.log(f"[ALIAS] {write_attr} -> {target}")
        return changes

    def _is_store(self, insn: InsnInfo) -> bool:
        return self.utils.is_store_opcode(insn.opcode)

    def _handle_store(self, insn: InsnInfo) -> List[AliasChange]:
        changes = []
        if len(insn.writes) != 1:
            return changes
        write_attr = insn.writes[0].attr
        if not isinstance(write_attr, StoreAttr):
            return changes
        ptr = write_attr.ptr
        value = write_attr.value
        if ptr is None or value is None:
            return changes
        target = value.inner if isinstance(value, AddressAttr) else value
        if isinstance(target, (ImmediateAttr, StringAttr)):
            return changes
        ptr_candidates = [ptr]
        if isinstance(ptr, AddressAttr):
            ptr_candidates.append(ptr.inner)
        for candidate in ptr_candidates:
            if candidate is None:
                continue
            if self.state.add_alias(candidate, target):
                changes.append(AliasChange(candidate, target, "store"))
                self.logger.log(f"[ALIAS] {candidate} -> {target}")
            resolved = self.state.aliases.get(candidate)
            if resolved is not None and self.state.add_alias(resolved, target):
                changes.append(AliasChange(resolved, target, "store"))
                self.logger.log(f"[ALIAS] {resolved} -> {target}")
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

        AliasAnalyzer(self.state, self.utils, self.logger).analyze(insn)

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
            origin_labels = [o.label for o in origins] if origins else []
            self.logger.log(f"[TRACE] {insn.ea}: {insn.text!r}  # labels={sorted(labels)} -> {write.attr}")
            if self.state.add_taint(write.attr, labels, origins, reason="propagate"):
                self.logger.log(f"[TAINT] {write.attr}: labels={sorted(labels)}")

    def _handle_store(
        self, insn: InsnInfo, read_taint: Tuple[Set[str], Set[TaintOrigin]]
    ):
        labels, origins = read_taint
        if not labels or not self.utils.is_store_opcode(insn.opcode):
            return

        for write in insn.writes:
            if write.attr is None:
                continue
            if isinstance(write.attr, StoreAttr):
                for target_attr in self._expand_arg_attrs(write.attr.ptr):
                    if self.state.add_taint(target_attr, labels, origins, reason="store_ptr"):
                        origin_labels = [o.label for o in origins] if origins else []
                        _log_info(self.logger, f"[TAINT][store_ptr] {sorted(labels)} -> {target_attr} (origins: {sorted(origin_labels)})")

        for read in insn.reads:
            if read.attr is None:
                continue
            resolved = self.state._resolve(read.attr)
            if resolved in self.state.aliases:
                target = self.state.aliases[resolved]
                self.state.add_taint(target, labels, origins, reason="store")
                origin_labels = [o.label for o in origins] if origins else []
                _log_info(self.logger, f"[TAINT][store] {sorted(labels)} -> {target} (origins: {sorted(origin_labels)})")

    def _handle_call(self, insn: InsnInfo, findings: List[Finding]):
        for call in insn.calls:
            if not call.args:
                inferred_args = self._infer_call_args_from_reads(insn)
                if inferred_args:
                    call.args = inferred_args
            self._apply_sources(call, insn)
            self._apply_propagators(call)
            self._apply_default_return_propagation(call)
            self._apply_interproc(call)
            self._apply_sinks(call, insn, findings)

    def _resolve_callee(self, call: CallInfo):
        return self.engine._resolve_callee(call)

    def _collect_arg_taint(self, args: List[OperandAttr]) -> Tuple[Set[str], Set[TaintOrigin]]:
        labels = set()
        origins = set()
        for arg in args:
            if arg is None:
                continue
            for attr in self._expand_arg_attrs(arg):
                labels.update(self.state.get_taint(attr))
                origins.update(self.state.get_origins(attr))
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
            origins = {TaintOrigin(label=label, ea=insn.ea, function=self.engine.func_info.function)}
            out_args = rule.get("out_args") or rule.get("args") or []

            self.logger.log(f"[SOURCE] Matched: {rule.get('name')} -> label={label}")

            for idx in out_args:
                if idx < 0 or idx >= len(args):
                    continue
                attr = args[idx]
                self.logger.log(f"[TRACE] Source rule '{rule.get('name')}': trying to add label={label} to arg[{idx}], attr={attr}")
                for target_attr in self._expand_arg_attrs(attr):
                    if self.state.add_taint(target_attr, {label}, origins, reason="source"):
                        self.logger.log(f"[TAINT][source][{rule.get('name')}] label={label} -> arg[{idx}]")

            if rule.get("ret") and call.ret:
                if self.state.add_taint(call.ret, {label}, origins, reason="source_ret"):
                    self.logger.log(f"[TAINT][source][{rule.get('name')}] label={label} -> ret")

    def _apply_propagators(self, call: CallInfo):
        callee, callee_ea = self._resolve_callee(call)
        args = call.args or []

        for rule in self.engine.ruleset.propagators:
            if not self._rule_matches(rule, callee, callee_ea):
                continue

            collected_labels = set()
            collected_origins = set()

            from_ret = rule.get("from_ret")
            from_args = rule.get("from_args")

            if from_ret and call.ret:
                ret_labels = self.state.get_taint(call.ret)
                ret_origins = self.state.get_origins(call.ret)
                if ret_labels:
                    collected_labels.update(ret_labels)
                    collected_origins.update(ret_origins)

            if from_args:
                valid_args = [args[i] for i in from_args if i < len(args)]
                arg_labels, arg_origins = self._collect_arg_taint(valid_args)
                if arg_labels:
                    collected_labels.update(arg_labels)
                    collected_origins.update(arg_origins)

            if not collected_labels:
                continue

            to_args = rule.get("to_args") or []
            for idx in to_args:
                if idx < 0 or idx >= len(args):
                    continue
                attr = args[idx]
                for target_attr in self._expand_arg_attrs(attr):
                    if self.state.add_taint(target_attr, collected_labels, collected_origins, reason="propagator"):
                        origin_labels = [o.label for o in collected_origins] if collected_origins else []
                        _log_info(self.logger, f"[TAINT][propagator][{rule.get('name') or rule.get('pattern')}] {sorted(collected_labels)} -> arg[{idx}] (origins: {sorted(origin_labels)})")

            if rule.get("to_ret") and call.ret:
                if self.state.add_taint(call.ret, collected_labels, collected_origins, reason="propagator_ret"):
                    origin_labels = [o.label for o in collected_origins] if collected_origins else []
                    _log_info(self.logger, f"[TAINT][propagator][{rule.get('name') or rule.get('pattern')}] {sorted(collected_labels)} -> ret (origins: {sorted(origin_labels)})")

    def _apply_default_return_propagation(self, call: CallInfo):
        if not call.ret:
            return
        args = call.args or []
        labels, origins = self._collect_arg_taint(args)
        if labels:
            if self.state.add_taint(call.ret, labels, origins, reason="default_return"):
                origin_labels = [o.label for o in origins] if origins else []
                _log_info(self.logger, f"[TAINT][default_return] {sorted(labels)} -> ret (origins: {sorted(origin_labels)})")

    def _apply_interproc(self, call: CallInfo):
        interproc_state = self.engine.interproc_state
        if not interproc_state:
            return
        callee, callee_ea = self._resolve_callee(call)
        if callee_ea is None and callee:
            for ea, ctx in interproc_state.func_contexts.items():
                if ctx.func_name == callee:
                    callee_ea = ea
                    break
        if callee_ea is None:
            return
        ctx = interproc_state.func_contexts.get(callee_ea)
        if ctx is None or not ctx.analyzed:
            return
        args = call.args or []
        caller_ea = self.engine._get_func_ea_int(self.engine.func_info.ea)
        caller_name = self.engine.func_info.function
        mappings = self.engine._collect_cross_mappings(caller_name, callee, caller_ea, callee_ea)
        for mapping, rule in mappings:
            for callee_idx, payload in ctx.out_arg_taints.items():
                labels, origins = payload
                if not labels:
                    continue
                caller_idx = mapping.get(callee_idx, callee_idx) if mapping else callee_idx
                if caller_idx < 0 or caller_idx >= len(args):
                    continue
                attr = args[caller_idx]
                for target_attr in self._expand_arg_attrs(attr):
                    if self.state.add_taint(target_attr, set(labels), set(origins), reason="interproc_out_arg"):
                        origin_labels = [o.label for o in origins] if origins else []
                        _log_info(self.logger, f"[TAINT][interproc][out_arg] {sorted(labels)} -> arg[{caller_idx}] (origins: {sorted(origin_labels)})")
            if ctx.ret_taint and call.ret:
                labels, origins = ctx.ret_taint
                if labels and self.state.add_taint(call.ret, set(labels), set(origins), reason="interproc_ret"):
                    origin_labels = [o.label for o in origins] if origins else []
                    _log_info(self.logger, f"[TAINT][interproc][ret] {sorted(labels)} -> ret (origins: {sorted(origin_labels)})")
            if ctx.ret_taint and rule and rule.ret_to_args:
                labels, origins = ctx.ret_taint
                for idx in rule.ret_to_args:
                    if idx < 0 or idx >= len(args):
                        continue
                    attr = args[idx]
                    if not labels:
                        continue
                    for target_attr in self._expand_arg_attrs(attr):
                        if self.state.add_taint(target_attr, set(labels), set(origins), reason="interproc_ret_to_arg"):
                            origin_labels = [o.label for o in origins] if origins else []
                            _log_info(self.logger, f"[TAINT][interproc][ret_to_arg] {sorted(labels)} -> arg[{idx}] (origins: {sorted(origin_labels)})")

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
                collected = False
                for target_attr in self._expand_arg_attrs(attr):
                    t = self.state.get_taint(target_attr)
                    if not t:
                        continue
                    collected = True
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
                    labels.update(t)
                    origins.update(self.state.get_origins(target_attr))
                if collected:
                    tainted_args.append(idx)

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
                        sources=[{"label": o.label, "ea": o.ea, "function": o.function} for o in sorted(origins)],
                    )
                )

    def _expand_arg_attrs(self, attr: Optional[OperandAttr]) -> List[OperandAttr]:
        if attr is None:
            return []
        attrs = []
        queue = [attr]
        seen = set()
        while queue:
            current = queue.pop(0)
            if current is None or current in seen:
                continue
            seen.add(current)
            attrs.append(current)
            if isinstance(current, AddressAttr):
                queue.append(current.inner)
                if current.base is not None:
                    queue.append(current.base)
                if current.offset is not None:
                    queue.append(current.offset)
            elif isinstance(current, LoadAttr):
                queue.append(current.ptr)
            elif isinstance(current, StoreAttr):
                queue.append(current.ptr)
                queue.append(current.value)
        return attrs

    def _infer_call_args_from_reads(self, insn: InsnInfo) -> List[OperandAttr]:
        args = []
        seen = set()
        for read in insn.reads:
            attr = read.attr
            if attr is None:
                continue
            if isinstance(attr, (LocalVarAttr, StackAttr, AddressAttr, LoadAttr, StoreAttr, RegisterAttr)):
                if attr in seen:
                    continue
                seen.add(attr)
                args.append(attr)
        return args


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
        return insn.opcode.startswith("j") and insn.opcode not in ("goto", "jmp")

    def _get_jump_targets(self, insn: InsnInfo) -> List[int]:
        targets = []
        for read in insn.reads:
            if read.attr and hasattr(read.attr, "block_id"):
                targets.append(read.attr.block_id)
        if not targets and insn.jump_targets:
            targets.extend(insn.jump_targets)
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
        self.rule_matcher = RuleMatcher(self.logger)
        self.pathfinder_config = PathFinderConfig(max_depth=10)
        self.pathfinder = PathFinder(ruleset, self.logger, self.pathfinder_config)
        self.policy = policy or TaintPolicy()
        self.func_info: Optional[FuncInfo] = None
        self.cfg: Optional[CFG] = None
        self.worklist: Deque[WorkItem] = deque()
        self.state = TaintState()
        self.visited_items: Set[Tuple[int, int]] = set()
        self.interproc_state: Optional[InterProcState] = None
        self.current_context: Optional[FunctionContext] = None
        self.cross_rules: List[CrossFuncRule] = []

    def analyze_function(
        self,
        func_info: FuncInfo,
        func_context: Optional[FunctionContext] = None,
        interproc_state: Optional[InterProcState] = None,
        cross_rules: Optional[List[CrossFuncRule]] = None,
    ) -> Tuple[TaintState, List[Finding]]:
        self.func_info = func_info
        self.state = TaintState()
        self.worklist = deque()
        self.visited_items = set()
        self.current_context = func_context
        self.interproc_state = interproc_state
        self.cross_rules = list(cross_rules or [])

        self.logger.log(f"[ENGINE] Analyzing {func_info.function}")

        self._initialize_worklist()
        self._initialize_with_sources()
        self._seed_context_taints()

        findings = self._run_fixed_point_iteration()

        self.logger.log(f"[ENGINE] Final state: {self.state}")
        return self.state, findings

    def _initialize_worklist(self):
        for insn in self.func_info.insns:
            block_id = insn.block_id
            self.worklist.append(
                WorkItem(
                    block_id=block_id,
                    insn_idx=insn.insn_idx,
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

    def _seed_context_taints(self):
        if not self.current_context:
            return
        if self.func_info.args:
            for idx, payload in self.current_context.arg_taints.items():
                labels, origins = payload
                if not labels:
                    continue
                if idx < 0 or idx >= len(self.func_info.args):
                    continue
                lvar_idx = self.func_info.args[idx].lvar_idx
                attr = LocalVarAttr(lvar_idx=lvar_idx)
                source_label = f"ARG:{self.func_info.function}:{idx}"
                merged_labels = set(labels)
                merged_labels.add(source_label)
                new_origins = set(origins)
                new_origins.add(TaintOrigin(label=source_label, ea=self.func_info.ea, function=self.func_info.function))
                if self.state.add_taint(attr, merged_labels, new_origins, reason="interproc_arg_source"):
                    origin_labels = [o.label for o in origins] if origins else []
                    self.logger.info(f"[TAINT][interproc][arg] {sorted(labels)} -> arg[{idx}] (origins: {sorted(origin_labels)})")
            return
        inferred_args = self._infer_entry_args()
        if not inferred_args:
            return
        for idx, payload in self.current_context.arg_taints.items():
            labels, origins = payload
            if not labels:
                continue
            if idx < 0 or idx >= len(inferred_args):
                continue
            attr = inferred_args[idx]
            source_label = f"ARG:{self.func_info.function}:{idx}"
            merged_labels = set(labels)
            merged_labels.add(source_label)
            new_origins = set(origins)
            new_origins.add(TaintOrigin(label=source_label, ea=self.func_info.ea, function=self.func_info.function))
            if self.state.add_taint(attr, merged_labels, new_origins, reason="interproc_arg_infer_source"):
                origin_labels = [o.label for o in origins] if origins else []
                _log_info(self.logger, f"[TAINT][interproc][arg] {sorted(labels)} -> arg[{idx}] (origins: {sorted(origin_labels)})")

    def _infer_entry_args(self) -> List[OperandAttr]:
        entry_block = self.func_info.entry_block
        seen = set()
        ordered = []
        for insn in self.func_info.insns:
            if insn.block_id != entry_block:
                continue
            for read in insn.reads:
                attr = read.attr
                if isinstance(attr, AddressAttr) and isinstance(attr.inner, LocalVarAttr):
                    attr = attr.inner
                if isinstance(attr, (LocalVarAttr, StackAttr, RegisterAttr)):
                    if attr not in seen:
                        seen.add(attr)
                        ordered.append(attr)
        return ordered

    def _get_func_ea_int(self, value) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                if value.startswith("0x"):
                    return int(value, 16)
                return int(value)
            except Exception:
                return 0
        return 0

    def _resolve_callee(self, call: CallInfo):
        callee = call.callee_name or ""
        target = call.target
        callee_ea = None

        if target is not None and hasattr(target, "ea"):
            callee_ea = target.ea

        if callee_ea is None and callee:
            callee_ea = self.rule_matcher.resolve_name(callee)
            if callee_ea == self.rule_matcher.badaddr:
                callee_ea = None

        if callee_ea is None and callee:
            stripped = callee.lstrip("$")
            if stripped and stripped != callee:
                callee_ea = self.rule_matcher.resolve_name(stripped)
                if callee_ea == self.rule_matcher.badaddr:
                    callee_ea = None

        if callee_ea is None and callee:
            normalized = self.rule_matcher.normalize_name(callee)
            if normalized and normalized != callee:
                callee_ea = self.rule_matcher.resolve_name(normalized)
                if callee_ea == self.rule_matcher.badaddr:
                    callee_ea = None

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

    def _collect_cross_mappings(
        self, caller_name: str, callee_name: str, caller_ea: int, callee_ea: int
    ) -> List[Tuple[Optional[Dict[int, int]], Optional[CrossFuncRule]]]:
        mappings = []
        for rule in self.cross_rules:
            try:
                if rule.matches(caller_name, callee_name, caller_ea, callee_ea):
                    if rule.arg_flows:
                        mapping = {callee_idx: caller_idx for caller_idx, callee_idx in rule.arg_flows}
                    else:
                        mapping = None
                    mappings.append((mapping, rule))
            except Exception:
                continue
        if not mappings:
            mappings.append((None, None))
        return mappings

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
        block = self.func_info.cfg_blocks.get(block_id)
        if not block:
            return

        for insn in self.func_info.insns:
            if insn.block_id == block_id and insn.insn_idx == insn_idx:
                if insn_idx < len(block.insns) - 1 if hasattr(block, 'insns') else False:
                    next_idx = insn_idx + 1
                    next_key = (block_id, next_idx)
                    if next_key not in self.visited_items:
                        next_insn = self._find_insn(block_id, next_idx)
                        if next_insn:
                            self.worklist.append(
                                WorkItem(
                                    block_id=block_id,
                                    insn_idx=next_idx,
                                    insn=next_insn,
                                    reason="taint_change",
                                    priority=1,
                                )
                            )

                for succ_id in insn.jump_targets:
                    if succ_id != block_id:
                        succ_key = (succ_id, 0)
                        if succ_key not in self.visited_items:
                            succ_insn = self._find_insn(succ_id, 0)
                            if succ_insn:
                                self.worklist.append(
                                    WorkItem(
                                        block_id=succ_id,
                                        insn_idx=0,
                                        insn=succ_insn,
                                        reason="taint_change",
                                        priority=1,
                                    )
                                )

                if insn.fallthrough_block is not None:
                    ft_key = (insn.fallthrough_block, 0)
                    if ft_key not in self.visited_items:
                        ft_insn = self._find_insn(insn.fallthrough_block, 0)
                        if ft_insn:
                            self.worklist.append(
                                WorkItem(
                                    block_id=insn.fallthrough_block,
                                    insn_idx=0,
                                    insn=ft_insn,
                                    reason="taint_change",
                                    priority=1,
                                )
                            )

    def _find_insn(self, block_id: int, insn_idx: int) -> Optional[InsnInfo]:
        for insn in self.func_info.insns:
            if insn.block_id == block_id and insn.insn_idx == insn_idx:
                return insn
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
        for rule in self.engine.ruleset.sources:
            if "name" in rule:
                ea = self.engine.rule_matcher.resolve_name(rule["name"])
                if ea != self.engine.rule_matcher.badaddr:
                    rule["ea"] = ea
        for rule in self.engine.ruleset.sinks:
            if "name" in rule:
                ea = self.engine.rule_matcher.resolve_name(rule["name"])
                if ea != self.engine.rule_matcher.badaddr:
                    rule["ea"] = ea
        for rule in self.engine.ruleset.propagators:
            if "name" in rule:
                ea = self.engine.rule_matcher.resolve_name(rule["name"])
                if ea != self.engine.rule_matcher.badaddr:
                    rule["ea"] = ea

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


class InterProcTaintEngine:
    def __init__(self, ruleset, logger=None, verbose=False, policy: TaintPolicy = None, cross_rules: Optional[List[CrossFuncRule]] = None):
        self.ruleset = ruleset
        self.logger = logger or SimpleLogger(verbose=verbose)
        self.engine = FixedPointTaintEngine(ruleset, self.logger, verbose, policy)
        self.interproc_state = InterProcState()
        if cross_rules is None:
            cross_rules = getattr(ruleset, "cross_rules", [])
        self.cross_rules = list(cross_rules or [])
        self.pathfinder = PathFinder(ruleset, self.logger, PathFinderConfig(max_depth=10))

    def _resolve_rule_eas(self):
        for rule in self.engine.ruleset.sources:
            if "name" in rule:
                ea = self.engine.rule_matcher.resolve_name(rule["name"])
                if ea != self.engine.rule_matcher.badaddr:
                    rule["ea"] = ea
        for rule in self.engine.ruleset.sinks:
            if "name" in rule:
                ea = self.engine.rule_matcher.resolve_name(rule["name"])
                if ea != self.engine.rule_matcher.badaddr:
                    rule["ea"] = ea
        for rule in self.engine.ruleset.propagators:
            if "name" in rule:
                ea = self.engine.rule_matcher.resolve_name(rule["name"])
                if ea != self.engine.rule_matcher.badaddr:
                    rule["ea"] = ea

    def _get_func_ea_int(self, value) -> int:
        return self.engine._get_func_ea_int(value)

    def _ensure_context(self, func_info: FuncInfo) -> FunctionContext:
        func_ea = self._get_func_ea_int(func_info.ea)
        if func_ea not in self.interproc_state.func_contexts:
            ctx = FunctionContext(func_ea=func_ea, func_name=func_info.function, arg_count=len(func_info.args))
            self.interproc_state.func_contexts[func_ea] = ctx
        return self.interproc_state.func_contexts[func_ea]

    def _resolve_callee_ea_by_name(self, callee_name: str, func_infos: Dict[int, FuncInfo]) -> Optional[int]:
        if not callee_name:
            return None
        candidates = [callee_name]
        stripped = callee_name.lstrip("$")
        if stripped and stripped not in candidates:
            candidates.append(stripped)
        normalizer = getattr(self.engine, "rule_matcher", None)
        if normalizer:
            normalized = normalizer.normalize_name(callee_name)
            if normalized and normalized not in candidates:
                candidates.append(normalized)
            normalized_stripped = normalizer.normalize_name(stripped)
            if normalized_stripped and normalized_stripped not in candidates:
                candidates.append(normalized_stripped)
        for ea, info in func_infos.items():
            if info.function in candidates:
                return ea
            if normalizer:
                info_norm = normalizer.normalize_name(info.function)
                if info_norm and info_norm in candidates:
                    return ea
        return None

    def _seed_root_args(self, func_info: FuncInfo):
        ctx = self._ensure_context(func_info)
        if ctx.arg_taints:
            return
        for idx, arg in enumerate(func_info.args):
            label = f"SYM:ARG:{idx}"
            origins = {TaintOrigin(label=label, ea=func_info.ea, function=func_info.function)}
            ctx.arg_taints[idx] = ({label}, origins)

    def _update_context_from_state(self, func_info: FuncInfo, state: TaintState) -> bool:
        ctx = self._ensure_context(func_info)
        changed = False
        for idx, arg in enumerate(func_info.args):
            attr = LocalVarAttr(lvar_idx=arg.lvar_idx)
            labels = set(state.get_taint(attr))
            origins = set(state.get_origins(attr))
            if labels:
                prev = ctx.out_arg_taints.get(idx)
                if prev is None:
                    ctx.out_arg_taints[idx] = (labels, origins)
                    changed = True
                else:
                    prev_labels, prev_origins = prev
                    new_labels = labels - prev_labels
                    new_origins = origins - prev_origins
                    if new_labels or new_origins:
                        ctx.out_arg_taints[idx] = (prev_labels | labels, prev_origins | origins)
                        changed = True
        ret_labels = set()
        ret_origins = set()
        for lvar_idx in func_info.return_vars:
            attr = LocalVarAttr(lvar_idx=lvar_idx)
            ret_labels.update(state.get_taint(attr))
            ret_origins.update(state.get_origins(attr))
        if ret_labels:
            if ctx.ret_taint is None:
                ctx.ret_taint = (ret_labels, ret_origins)
                changed = True
            else:
                prev_labels, prev_origins = ctx.ret_taint
                new_labels = ret_labels - prev_labels
                new_origins = ret_origins - prev_origins
                if new_labels or new_origins:
                    ctx.ret_taint = (prev_labels | ret_labels, prev_origins | ret_origins)
                    changed = True
        if not ctx.analyzed:
            ctx.analyzed = True
            changed = True
        return changed

    def _build_call_graph(self, func_infos: Dict[int, FuncInfo]):
        for func_ea, func_info in func_infos.items():
            edges = []
            for insn in func_info.insns:
                for call in insn.calls:
                    callee_name, callee_ea = self.engine._resolve_callee(call)
                    if callee_ea is None or callee_ea not in func_infos:
                        callee_ea = self._resolve_callee_ea_by_name(callee_name, func_infos)
                    if callee_ea is None or callee_ea not in func_infos:
                        continue
                    call_args = call.args or self._infer_call_args_from_reads(insn)
                    caller_arg_count = len(call_args)
                    callee_arg_count = len(func_infos[callee_ea].args)
                    arg_mapping = {i: i for i in range(min(caller_arg_count, callee_arg_count))}
                    edge = CallEdge(
                        caller_ea=func_ea,
                        callee_ea=callee_ea,
                        call_site_ea=call.call_site_ea or 0,
                        caller_arg_count=caller_arg_count,
                        callee_arg_count=callee_arg_count,
                        arg_mapping=arg_mapping,
                        ret_mapping=0 if call.ret else None,
                        call_insn_text=insn.text,
                    )
                    edges.append(edge)
            self.interproc_state.call_graph[func_ea] = edges

    def _propagate_callsite_taints(self, func_info: FuncInfo, state: TaintState, func_infos: Dict[int, FuncInfo]) -> Set[int]:
        changed_funcs = set()
        caller_ea = self._get_func_ea_int(func_info.ea)
        caller_name = func_info.function
        for insn in func_info.insns:
            for call in insn.calls:
                callee_name, callee_ea = self.engine._resolve_callee(call)
                if callee_ea is None or callee_ea not in func_infos:
                    callee_ea = self._resolve_callee_ea_by_name(callee_name, func_infos)
                if callee_ea is None or callee_ea not in func_infos:
                    continue
                callee_ctx = self._ensure_context(func_infos[callee_ea])
                mappings = self.engine._collect_cross_mappings(caller_name, callee_name, caller_ea, callee_ea)
                args = call.args or self._infer_call_args_from_reads(insn)
                for mapping, _ in mappings:
                    for caller_idx, attr in enumerate(args):
                        if attr is None:
                            continue
                        labels, origins = self._collect_call_arg_taint(state, attr)
                        if not labels:
                            continue
                        callee_idx = mapping.get(caller_idx, caller_idx) if mapping else caller_idx
                        if callee_idx < 0:
                            continue
                        if func_infos[callee_ea].args and callee_idx >= len(func_infos[callee_ea].args):
                            continue
                        prev = callee_ctx.arg_taints.get(callee_idx)
                        if prev is None:
                            callee_ctx.arg_taints[callee_idx] = (labels, origins)
                            changed_funcs.add(callee_ea)
                        else:
                            prev_labels, prev_origins = prev
                            new_labels = labels - prev_labels
                            new_origins = origins - prev_origins
                            if new_labels or new_origins:
                                callee_ctx.arg_taints[callee_idx] = (prev_labels | labels, prev_origins | origins)
                                changed_funcs.add(callee_ea)
        return changed_funcs

    def _collect_call_arg_taint(self, state: TaintState, attr: OperandAttr) -> Tuple[Set[str], Set[TaintOrigin]]:
        labels = set(state.get_taint(attr))
        origins = set(state.get_origins(attr))
        if labels:
            return labels, origins
        if isinstance(attr, AddressAttr):
            inner = attr.inner
            while isinstance(inner, AddressAttr):
                inner = inner.inner
            labels.update(state.get_taint(inner))
            origins.update(state.get_origins(inner))
            if attr.base is not None:
                labels.update(state.get_taint(attr.base))
                origins.update(state.get_origins(attr.base))
            if attr.offset is not None:
                labels.update(state.get_taint(attr.offset))
                origins.update(state.get_origins(attr.offset))
        if isinstance(attr, LoadAttr):
            ptr = attr.ptr
            while isinstance(ptr, LoadAttr):
                ptr = ptr.ptr
            labels.update(state.get_taint(ptr))
            origins.update(state.get_origins(ptr))
            if isinstance(ptr, AddressAttr):
                inner = ptr.inner
                while isinstance(inner, AddressAttr):
                    inner = inner.inner
                labels.update(state.get_taint(inner))
                origins.update(state.get_origins(inner))
        if isinstance(attr, StoreAttr):
            if attr.value is not None:
                labels.update(state.get_taint(attr.value))
                origins.update(state.get_origins(attr.value))
            labels.update(state.get_taint(attr.ptr))
            origins.update(state.get_origins(attr.ptr))
        return labels, origins

    def _infer_call_args_from_reads(self, insn: InsnInfo) -> List[OperandAttr]:
        args = []
        seen = set()
        for read in insn.reads:
            attr = read.attr
            if attr is None:
                continue
            if isinstance(attr, (LocalVarAttr, StackAttr, AddressAttr, LoadAttr, StoreAttr, RegisterAttr)):
                if attr in seen:
                    continue
                seen.add(attr)
                args.append(attr)
        return args

    def scan_global(self, maturity):
        self._resolve_rule_eas()
        self.pathfinder.ruleset = self.ruleset
        self.pathfinder.identify_markers()
        path_result = self.pathfinder.find_paths()
        if not path_result:
            return []
        raw_chains = [p["nodes"] for p in path_result]
        self.interproc_state.source_sink_paths = raw_chains
        self.interproc_state.source_sink_history.append(raw_chains)
        chain_functions = set()
        for path in raw_chains:
            for node in path:
                ea = int(node["ea"], 16)
                chain_functions.add(ea)
        if not chain_functions:
            return []
        chain_functions = sorted(chain_functions)
        func_infos: Dict[int, FuncInfo] = {}
        for ea in chain_functions:
            func = ida_funcs.get_func(ea)
            if not func:
                continue
            func_info = analyze_function(func, maturity)
            if func_info:
                func_ea = self._get_func_ea_int(func_info.ea)
                func_infos[func_ea] = func_info
        if not func_infos:
            return []
        self._build_call_graph(func_infos)
        caller_map: Dict[int, Set[int]] = defaultdict(set)
        for caller_ea, edges in self.interproc_state.call_graph.items():
            for edge in edges:
                caller_map[edge.callee_ea].add(caller_ea)
        for func_ea, func_info in func_infos.items():
            if caller_map.get(func_ea) is None:
                self._seed_root_args(func_info)
        worklist = deque(func_infos.keys())
        findings: List[Finding] = []
        while worklist:
            func_ea = worklist.popleft()
            if func_ea in self.interproc_state.analyzing_funcs:
                continue
            func_info = func_infos.get(func_ea)
            if not func_info:
                continue
            self.interproc_state.analyzing_funcs.add(func_ea)
            try:
                ctx = self._ensure_context(func_info)
                state, f_findings = self.engine.analyze_function(
                    func_info,
                    func_context=ctx,
                    interproc_state=self.interproc_state,
                    cross_rules=self.cross_rules,
                )
                findings.extend(f_findings)
                changed_context = self._update_context_from_state(func_info, state)
                changed_callees = self._propagate_callsite_taints(func_info, state, func_infos)
                if changed_context:
                    for caller in caller_map.get(func_ea, []):
                        if caller in func_infos:
                            worklist.append(caller)
                for callee in changed_callees:
                    if callee in func_infos:
                        worklist.append(callee)
            finally:
                self.interproc_state.analyzing_funcs.discard(func_ea)
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
    "CallEdge",
    "FunctionContext",
    "InterProcState",
    "CrossFuncRule",
    "FixedPointTaintEngine",
    "WorklistTaintEngine",
    "InterProcTaintEngine",
]

from collections import deque
from typing import Deque, Optional, Set, Tuple, List, Dict

from .state import TaintState, TaintOrigin
from .microcode_analyzer import analyze_function
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
from ..rule_matcher import RuleMatcher
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
from .logger import SimpleLogger, _log_info
from .instruction_processor import InstructionProcessor
from .cfg_builder import CFGBuilder


class FixedPointTaintEngine:
    def __init__(
        self,
        ruleset,
        logger=None,
        verbose=False,
        policy=None,
    ):
        self.ruleset = ruleset
        self.logger = logger or SimpleLogger(verbose=verbose)
        self.utils = MicroCodeUtils()
        self.rule_matcher = RuleMatcher(self.logger)
        self.pathfinder_config = PathFinderConfig(max_depth=10)
        self.pathfinder = PathFinder(ruleset, self.logger, self.pathfinder_config)
        self.policy = policy or TaintPolicy()
        self.func_info = None
        self.cfg = None
        self.worklist = deque()
        self.state = TaintState()
        self.visited_items = set()
        self.interproc_state = None
        self.current_context = None
        self.cross_rules = []

    def analyze_function(
        self,
        func_info,
        func_context=None,
        interproc_state=None,
        cross_rules=None,
    ):
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

    def _infer_entry_args(self):
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

    def _get_func_ea_int(self, value):
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

    def _resolve_callee(self, call):
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
        self, caller_name, callee_name, caller_ea, callee_ea
    ):
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

    def _run_fixed_point_iteration(self):
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

    def _notify_successors(self, block_id, insn_idx):
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

    def _find_insn(self, block_id, insn_idx):
        for insn in self.func_info.insns:
            if insn.block_id == block_id and insn.insn_idx == insn_idx:
                return insn
        return None

    def scan_function(self, func_info):
        return self.analyze_function(func_info)


__all__ = ["FixedPointTaintEngine"]
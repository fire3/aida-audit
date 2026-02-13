from collections import deque, defaultdict
from typing import List, Optional, Set, Dict, Tuple

from .common import (
    LocalVarAttr,
    StackAttr,
    AddressAttr,
    LoadAttr,
    StoreAttr,
    RegisterAttr,
    OperandAttr,
    GlobalAttr,
    HelperFuncAttr,
    InsnInfo,
)
from .state import TaintState, TaintOrigin
from .logger import SimpleLogger, _log_info
from .proc_engine import ProcTaintEngine
from .interproc_datatypes import (
    TaintPolicy,
    Finding,
    CallEdge,
    FunctionContext,
    InterProcState,
    CrossFuncRule,
)
from .constants import ida_funcs
from ..pathfinder import PathFinder, PathFinderConfig


class InterProcTaintEngine:
    def __init__(
        self,
        ruleset,
        logger=None,
        verbose=False,
        policy=None,
        cross_rules=None,
    ):
        self.ruleset = ruleset
        self.logger = logger or SimpleLogger(verbose=verbose)
        self.engine = ProcTaintEngine(ruleset, self.logger, verbose, policy)
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

    def _get_func_ea_int(self, value):
        return self.engine._get_func_ea_int(value)

    def _ensure_context(self, func_info):
        func_ea = self._get_func_ea_int(func_info.ea)
        if func_ea not in self.interproc_state.func_contexts:
            ctx = FunctionContext(func_ea=func_ea, func_name=func_info.function, arg_count=len(func_info.args))
            self.interproc_state.func_contexts[func_ea] = ctx
        return self.interproc_state.func_contexts[func_ea]

    def _resolve_callee_ea_by_name(self, callee_name, func_infos):
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

    def _seed_root_args(self, func_info):
        ctx = self._ensure_context(func_info)
        if ctx.arg_taints:
            return
        for idx, arg in enumerate(func_info.args):
            label = f"SYM:ARG:{idx}"
            origins = {TaintOrigin(label=label, ea=func_info.ea, function=func_info.function)}
            ctx.arg_taints[idx] = ({label}, origins)

    def _update_context_from_state(self, func_info, state):
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
        
        global_changed = False
        for attr, entry in state.entries.items():
            if not entry.labels:
                continue
            g_key = None
            if isinstance(attr, HelperFuncAttr):
                g_key = attr.name
            elif isinstance(attr, GlobalAttr):
                g_key = hex(attr.ea)
            
            if g_key:
                labels = set(entry.labels)
                origins = set(entry.origins)
                prev = self.interproc_state.global_taints.get(g_key)
                if prev is None:
                    self.interproc_state.global_taints[g_key] = (labels, origins)
                    global_changed = True
                else:
                    prev_labels, prev_origins = prev
                    new_labels = labels - prev_labels
                    new_origins = origins - prev_origins
                    if new_labels or new_origins:
                        self.interproc_state.global_taints[g_key] = (prev_labels | labels, prev_origins | origins)
                        global_changed = True

        for alias_ptr, alias_target in state.aliases.items():
            g_key = None
            if isinstance(alias_ptr, HelperFuncAttr):
                g_key = alias_ptr.get_global_key()
            elif isinstance(alias_ptr, GlobalAttr):
                g_key = hex(alias_ptr.ea)
            
            if g_key:
                t_labels = state.get_taint(alias_target)
                t_origins = state.get_origins(alias_target)
                if t_labels:
                    prev = self.interproc_state.global_taints.get(g_key)
                    if prev is None:
                        self.interproc_state.global_taints[g_key] = (set(t_labels), set(t_origins))
                        global_changed = True
                    else:
                        prev_labels, prev_origins = prev
                        new_labels = t_labels - prev_labels
                        new_origins = t_origins - prev_origins
                        if new_labels or new_origins:
                            self.interproc_state.global_taints[g_key] = (prev_labels | t_labels, prev_origins | t_origins)
                            global_changed = True

        if not ctx.analyzed:
            ctx.analyzed = True
            changed = True
        return changed, global_changed

    def _build_call_graph(self, func_infos):
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

    def _propagate_callsite_taints(self, func_info, state, func_infos):
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

    def _collect_call_arg_taint(self, state, attr):
        labels = set(state.get_taint(attr))
        origins = set(state.get_origins(attr))

        resolved = state._resolve(attr)
        if resolved != attr:
            resolved_labels = state.get_taint(resolved)
            if resolved_labels:
                labels.update(resolved_labels)
                origins.update(state.get_origins(resolved))

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

    def _infer_call_args_from_reads(self, insn):
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
        func_infos = {}
        from .microcode_analyzer import analyze_function
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
        caller_map = defaultdict(set)
        for caller_ea, edges in self.interproc_state.call_graph.items():
            for edge in edges:
                caller_map[edge.callee_ea].add(caller_ea)
        for func_ea, func_info in func_infos.items():
            if caller_map.get(func_ea) is None:
                self._seed_root_args(func_info)
        worklist = deque(func_infos.keys())
        findings = []
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
                changed_context, global_changed = self._update_context_from_state(func_info, state)
                changed_callees = self._propagate_callsite_taints(func_info, state, func_infos)
                
                if global_changed:
                    for f_ea in func_infos:
                        worklist.append(f_ea)

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
            finding.call_chains = raw_chains
            if not finding.inter_proc_path:
                finding.inter_proc_path = self._build_interproc_path(finding, raw_chains, func_infos)

        unique_findings = self._deduplicate_findings(findings)
        return unique_findings

    def _deduplicate_findings(self, findings):
        seen = set()
        unique = []
        for f in findings:
            key = (f.rule_id, f.func_ea, f.sink.get("ea"), tuple(sorted(f.arg_indexes)))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _build_interproc_path(self, finding, raw_chains, func_infos):
        inter_path = []
        finding_labels = set(finding.taint_labels)
        for chain in raw_chains:
            chain_functions = []
            for node in chain:
                ea = int(node["ea"], 16)
                func_info = func_infos.get(ea)
                if func_info:
                    chain_functions.append({
                        "function": func_info.function,
                        "function_ea": hex(ea),
                    })
            inter_path.append({
                "chain": chain_functions,
                "type": "call_chain",
            })
        return inter_path


__all__ = ["InterProcTaintEngine"]
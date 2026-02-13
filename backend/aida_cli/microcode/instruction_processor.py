from typing import List, Optional, Set, Tuple
from collections import defaultdict

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
    ExpressionAttr,
    InsnInfo,
    CallInfo,
)
from .state import TaintState, TaintOrigin
from .utils import MicroCodeUtils
from .alias_analyzer import AliasAnalyzer
from .logger import SimpleLogger, _log_info
from .interproc_datatypes import Finding


class InstructionProcessor:
    def __init__(self, engine, state, logger):
        self.engine = engine
        self.state = state
        self.logger = logger
        self.utils = MicroCodeUtils()
        self.propagation_trace = defaultdict(list)

    def process(self, insn, block_id):
        findings = []

        AliasAnalyzer(self.state, self.utils, self.logger).analyze(insn)

        read_taint = self._collect_read_taint(insn)

        self._propagate_to_writes(insn, read_taint)

        self._handle_store(insn, read_taint)

        self._handle_call(insn, findings)

        return findings

    def _collect_read_taint(self, insn):
        labels = set()
        origins = set()

        for read in insn.reads:
            if read.attr is None:
                continue
            labels.update(self.state.get_taint(read.attr))
            origins.update(self.state.get_origins(read.attr))

            if self.engine.interproc_state:
                resolved = self.state._resolve(read.attr)
                g_key = None
                if isinstance(resolved, HelperFuncAttr):
                    g_key = resolved.name
                elif isinstance(resolved, GlobalAttr):
                    g_key = hex(resolved.ea)
                
                if g_key and g_key in self.engine.interproc_state.global_taints:
                    g_labels, g_origins = self.engine.interproc_state.global_taints[g_key]
                    labels.update(g_labels)
                    origins.update(g_origins)
                    self.state.add_taint(read.attr, g_labels, g_origins, reason="global_pull")

        return labels, origins

    def _propagate_to_writes(self, insn, read_taint):
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
                for label in labels:
                    self.propagation_trace[label].append({
                        "insn_ea": insn.ea,
                        "insn_text": insn.text,
                        "from_attr": str(list(r.attr for r in insn.reads if r.attr)),
                        "to_attr": str(write.attr),
                        "operation": "propagate",
                        "function": self.engine.func_info.function,
                    })

    def _handle_store(self, insn, read_taint):
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

        if not labels:
            return

        for write in insn.writes:
            if write.attr is None:
                continue
            if isinstance(write.attr, StoreAttr):
                ptr = write.attr.ptr
                value = write.attr.value
                if ptr is None or value is None:
                    continue

                if isinstance(ptr, GlobalAttr):
                    self.state.add_taint(ptr, labels, origins, reason="store_global")
                    origin_labels = [o.label for o in origins] if origins else []
                    _log_info(self.logger, f"[TAINT][store_global] {sorted(labels)} -> {ptr} (origins: {sorted(origin_labels)})")

    def _handle_call(self, insn, findings):
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

    def _resolve_callee(self, call):
        return self.engine._resolve_callee(call)

    def _collect_arg_taint(self, args):
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

    def _apply_sources(self, call, insn):
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
                        self.propagation_trace[label].append({
                            "insn_ea": insn.ea,
                            "insn_text": insn.text,
                            "from_attr": f"source:{rule.get('name')}",
                            "to_attr": str(target_attr),
                            "operation": "source",
                            "function": self.engine.func_info.function,
                        })

            if rule.get("ret") and call.ret:
                if self.state.add_taint(call.ret, {label}, origins, reason="source_ret"):
                    self.logger.log(f"[TAINT][source][{rule.get('name')}] label={label} -> ret")
                    self.propagation_trace[label].append({
                        "insn_ea": insn.ea,
                        "insn_text": insn.text,
                        "from_attr": f"source:{rule.get('name')}",
                        "to_attr": str(call.ret),
                        "operation": "source_ret",
                        "function": self.engine.func_info.function,
                    })

    def _apply_propagators(self, call):
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
                        for label in collected_labels:
                            self.propagation_trace[label].append({
                                "insn_ea": call.call_site_ea or 0,
                                "insn_text": f"call {callee}",
                                "from_attr": f"propagator:{rule.get('name') or rule.get('pattern')}",
                                "to_attr": str(target_attr),
                                "operation": "propagator",
                                "function": self.engine.func_info.function,
                            })

            if rule.get("to_ret") and call.ret:
                if self.state.add_taint(call.ret, collected_labels, collected_origins, reason="propagator_ret"):
                    origin_labels = [o.label for o in collected_origins] if collected_origins else []
                    _log_info(self.logger, f"[TAINT][propagator][{rule.get('name') or rule.get('pattern')}] {sorted(collected_labels)} -> ret (origins: {sorted(origin_labels)})")
                    for label in collected_labels:
                        self.propagation_trace[label].append({
                            "insn_ea": call.call_site_ea or 0,
                            "insn_text": f"call {callee}",
                            "from_attr": f"propagator:{rule.get('name') or rule.get('pattern')}",
                            "to_attr": str(call.ret),
                            "operation": "propagator_ret",
                            "function": self.engine.func_info.function,
                        })

    def _apply_default_return_propagation(self, call):
        if not call.ret:
            return
        args = call.args or []
        labels, origins = self._collect_arg_taint(args)
        if labels:
            if self.state.add_taint(call.ret, labels, origins, reason="default_return"):
                origin_labels = [o.label for o in origins] if origins else []
                _log_info(self.logger, f"[TAINT][default_return] {sorted(labels)} -> ret (origins: {sorted(origin_labels)})")

    def _apply_interproc(self, call):
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

    def _get_propagation_trace(self, label):
        return self.propagation_trace.get(label, [])

    def _get_interproc_path(self, label):
        if not self.engine.interproc_state:
            return []
        inter_path = []
        interproc_state = self.engine.interproc_state
        for func_ea, ctx in interproc_state.func_contexts.items():
            if label in str(ctx.arg_taints) or label in str(ctx.ret_taint):
                inter_path.append({
                    "function": ctx.func_name,
                    "function_ea": hex(func_ea) if isinstance(func_ea, int) else func_ea,
                    "type": "context_arg" if label in str(ctx.arg_taints) else "context_ret",
                })
        return inter_path

    def _build_propagation_steps(self, label):
        steps = []
        traces = self._get_propagation_trace(label)
        for trace in traces:
            step = f"{trace.get('function', '?')}::{trace.get('operation', '?')}: {trace.get('from_attr', '?')} -> {trace.get('to_attr', '?')} at {trace.get('insn_ea', '?')}"
            steps.append(step)
        return steps

    def _apply_sinks(self, call, insn, findings):
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
            label_traces = defaultdict(list)

            for idx in arg_indexes:
                if idx < 0 or idx >= len(args):
                    continue
                attr = args[idx]
                if attr is None:
                    continue
                collected = False
                for target_attr in self._expand_arg_attrs(attr):
                    t = self.state.get_taint(target_attr)
                    current_origins = self.state.get_origins(target_attr)

                    if not t and isinstance(target_attr, ExpressionAttr):
                        for entry_attr, entry_val in self.state.entries.items():
                            if not entry_val.labels:
                                continue
                            if isinstance(entry_attr, HelperFuncAttr):
                                if entry_attr.name in target_attr.expr:
                                    t = entry_val.labels
                                    current_origins = entry_val.origins
                                    break

                    if not t:
                        continue
                    collected = True
                    for label in t:
                        if label.startswith("SYM:ARG:"):
                            intra_path = self._get_propagation_trace(label)
                            inter_path = self._get_interproc_path(label)
                            propagation_steps = self._build_propagation_steps(label)
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
                                        intra_proc_path=intra_path,
                                        inter_proc_path=inter_path,
                                        propagation_steps=propagation_steps,
                                    )
                                )
                            except Exception:
                                pass
                    labels.update(t)
                    origins.update(current_origins)
                    for label in t:
                        label_traces[label].extend(self._get_propagation_trace(label))
                if collected:
                    tainted_args.append(idx)

            if tainted_args:
                self.logger.log(f"[SINK] Matched: {callee} args={tainted_args}")
                source_list = [{"label": o.label, "ea": o.ea, "function": o.function} for o in sorted(origins)]
                intra_path = []
                for label in labels:
                    intra_path.extend(self._get_propagation_trace(label))
                inter_path = []
                for label in labels:
                    inter_path.extend(self._get_interproc_path(label))
                propagation_steps = []
                for label in labels:
                    propagation_steps.extend(self._build_propagation_steps(label))
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
                        sources=source_list,
                        intra_proc_path=intra_path,
                        inter_proc_path=inter_path,
                        propagation_steps=propagation_steps,
                    )
                )

    def _expand_arg_attrs(self, attr):
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

    def _get_propagation_trace(self, label):
        return self.propagation_trace.get(label, [])

    def _get_interproc_path(self, label):
        if not self.engine.interproc_state:
            return []
        inter_path = []
        interproc_state = self.engine.interproc_state
        for func_ea, ctx in interproc_state.func_contexts.items():
            ctx_str = str(ctx.arg_taints) + str(ctx.ret_taint)
            if label in ctx_str:
                inter_path.append({
                    "function": ctx.func_name,
                    "function_ea": hex(func_ea) if isinstance(func_ea, int) else func_ea,
                    "type": "context_arg" if label in str(ctx.arg_taints) else "context_ret",
                })
        return inter_path

    def _build_propagation_steps(self, label):
        steps = []
        traces = self._get_propagation_trace(label)
        for trace in traces:
            step = f"{trace.get('function', '?')}::{trace.get('operation', '?')}: {trace.get('from_attr', '?')} -> {trace.get('to_attr', '?')} at {trace.get('insn_ea', '?')}"
            steps.append(step)
        return steps


__all__ = ["InstructionProcessor"]
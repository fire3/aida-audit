from collections import deque
import sys
import logging

from .state import TaintState
from .analyzer import analyze_function
from .utils import MicroCodeUtils
from .common import (
    LocalVarAttr,
    AddressAttr,
)
from .constants import (
    idc,
    ida_funcs,
    idautils,
    BADADDR,
)
from ..pathfinder import PathFinder, PathFinderConfig


class SimpleLogger:
    """简单的日志适配器"""
    def __init__(self, verbose=False):
        self._logger = logging.getLogger(__name__)
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

        for candidate in (name, "_" + name, "__imp_" + name, "__imp__" + name, "." + name):
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


class SummaryGenerator:
    """基于污点状态生成动态规则"""

    def __init__(self, ruleset, logger, utils=None):
        self.ruleset = ruleset
        self.logger = logger
        self.utils = utils or MicroCodeUtils()

    def generate(self, func_info, state, proxy_findings=None):
        func_ea_str = func_info.ea
        if not func_ea_str:
            return
        func_ea = int(func_ea_str, 16)
        func_name = func_info.function

        is_source, tainted_out_args = self._inspect_taint_outputs(func_info, state)

        if is_source:
            new_rule = {
                "ea": func_ea,
                "name": func_name,
                "label": f"Dynamic:{func_name}",
                "out_args": tainted_out_args,
                "ret": True,
            }
            self.ruleset.sources.append(new_rule)

        if proxy_findings:
            proxy_args = self._collect_proxy_args(proxy_findings)
            if proxy_args:
                base_rule = proxy_findings[0].get("sink_rule", {})
                new_rule = {
                    "ea": func_ea,
                    "name": func_name,
                    "label": f"DynamicSink:{func_name}",
                    "args": list(proxy_args),
                    "cwe": base_rule.get("cwe", "CWE-78"),
                    "severity": base_rule.get("severity", "HIGH"),
                    "title": f"Proxy for {base_rule.get('title', 'Sink')}",
                }
                self.ruleset.sinks.append(new_rule)

    def _inspect_taint_outputs(self, func_info, state):
        is_source = False
        tainted_out_args = []

        for insn in func_info.insns:
            if insn.opcode == "ret":
                for read in insn.reads:
                    if read.attr and state.get_taint(read.attr):
                        is_source = True
                        break

        if not is_source:
            for lvar_idx in func_info.return_vars:
                attr = LocalVarAttr(lvar_idx=lvar_idx)
                if state.get_taint(attr):
                    is_source = True
                    break

        args_map = {a.lvar_idx: i for i, a in enumerate(func_info.args)}

        for lvar_idx, arg_pos in args_map.items():
            inner = LocalVarAttr(lvar_idx=lvar_idx)
            attr = AddressAttr(inner=inner)
            if state.get_taint(attr):
                tainted_out_args.append(arg_pos)
                is_source = True

        return is_source, tainted_out_args

    def _collect_proxy_args(self, proxy_findings):
        proxy_args = set()
        for pf in proxy_findings:
            for arg in pf.get("proxy_args", []):
                proxy_args.add(arg)
        return proxy_args


class InstructionTaintProcessor:
    """指令级污点处理器"""

    def __init__(self, ruleset, logger, rule_resolver, utils=None):
        self.ruleset = ruleset
        self.logger = logger
        self.rule_resolver = rule_resolver
        self.utils = utils or MicroCodeUtils()

    def process(self, state, insn, func_info, findings):
        calls = insn.calls
        opcode = insn.opcode
        writes = insn.writes
        reads = insn.reads

        if calls and self.utils.is_move_opcode(opcode):
            if writes:
                for call in calls:
                    if call.ret is None:
                        call.ret = writes[0].attr

        if self.utils.is_move_opcode(opcode) and len(writes) == 1:
            w_attr = writes[0].attr
            if w_attr:
                for r in reads:
                    r_attr = r.attr
                    if r_attr and isinstance(r_attr, AddressAttr):
                        state.add_alias(w_attr, r_attr.inner)

        read_attrs, read_origins = self._collect_reads(state, insn.reads)

        if self.utils.is_store_opcode(opcode) and read_attrs:
            for r in reads:
                r_attr = r.attr
                if r_attr:
                    resolved = state._resolve(r_attr)
                    if resolved in state.aliases:
                        target = state.aliases[resolved]
                        state.add_taint(target, read_attrs, read_origins)

        if read_attrs:
            self._propagate_writes(state, insn, read_attrs, read_origins)

        for call in insn.calls:
            findings.extend(self._apply_call(insn, call, state, func_info))

    def _propagate_writes(self, state, insn, labels, origins):
        for write in insn.writes:
            if write.attr:
                state.add_taint(write.attr, labels, origins)

    def _collect_reads(self, state, reads):
        labels = set()
        origins = set()
        attrs = []
        for read in reads:
            if read.attr is None:
                continue
            attrs.append(read.attr)
            labels.update(state.get_taint(read.attr))
            origins.update(state.get_origins(read.attr))
        return labels, origins

    def _apply_call(self, insn, call, state, func_info):
        findings = []
        callee, callee_ea = self._resolve_callee(call)
        if not callee and not callee_ea:
            return findings

        args = call.args or []
        ret = call.ret

        labels, origins = self._collect_arg_taint(state, args)

        self._apply_sources(insn, callee, callee_ea, args, ret, state, func_info)
        self._apply_propagators(callee, callee_ea, args, ret, state)
        self._apply_default_return_propagation(args, ret, state)
        findings.extend(self._apply_sinks(insn, callee, callee_ea, args, state, func_info))

        return findings

    def _collect_arg_taint(self, state, args):
        labels = set()
        origins = set()
        for arg in args:
            if arg is None:
                continue
            labels.update(state.get_taint(arg))
            origins.update(state.get_origins(arg))
        return labels, origins

    def _rule_matches(self, rule, callee, callee_ea=None):
        if "ea" not in rule:
            if "regex" in rule and callee:
                match = rule["regex"].match(callee)
                return match
            return False
        if callee_ea is None:
            return False
        return rule["ea"] == callee_ea

    def _resolve_callee(self, call):
        callee = call.callee_name or ""
        target = call.target
        callee_ea = None
        if target is not None and hasattr(target, "ea"):
            callee_ea = target.ea
        if callee_ea is None and callee:
            callee_ea = self.rule_resolver.resolve_rule_ea(callee)
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

    def _apply_sources(self, insn, callee, callee_ea, args, ret, state, func_info):
        for rule in self.ruleset.sources:
            if not self._rule_matches(rule, callee, callee_ea):
                continue
            label = rule.get("label") or callee
            origins = {(label, insn.ea, func_info.function)}
            out_args = rule.get("out_args") or rule.get("args") or []
            self.logger.log(f"[TAINTER] Source matched: {rule.get('name')} -> label={label}")

            for idx in out_args:
                if idx < 0 or idx >= len(args):
                    continue
                attr = args[idx]
                if attr:
                    changed = state.add_taint(attr, {label}, origins)
                    if changed:
                        self.logger.log(f"[TAINTER]   Taint added: arg[{idx}]")

            if rule.get("ret") and ret:
                changed = state.add_taint(ret, {label}, origins)
                if changed:
                    self.logger.log(f"[TAINTER]   Taint added: ret")

    def _apply_propagators(self, callee, callee_ea, args, ret, state):
        for rule in self.ruleset.propagators:
            if not self._rule_matches(rule, callee, callee_ea):
                continue
            from_args = rule.get("from_args")
            if from_args is None:
                from_args = list(range(len(args)))
            labels, origins = self._collect_arg_taint(state, [args[i] for i in from_args if i < len(args)])
            if not labels:
                continue

            to_args = rule.get("to_args") or []
            for idx in to_args:
                if idx < 0 or idx >= len(args):
                    continue
                attr = args[idx]
                if attr:
                    state.add_taint(attr, labels, origins)

            if rule.get("to_ret") and ret:
                state.add_taint(ret, labels, origins)

    def _apply_default_return_propagation(self, args, ret, state):
        if not ret:
            return
        labels, origins = self._collect_arg_taint(state, args)
        if labels:
            state.add_taint(ret, labels, origins)

    def _apply_sinks(self, insn, callee, callee_ea, args, state, func_info):
        findings = []
        for rule in self.ruleset.sinks:
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

                t = state.get_taint(attr)
                if not t:
                    continue

                for label in t:
                    if label.startswith("SYM:ARG:"):
                        try:
                            findings.append({
                                "type": "sink_proxy",
                                "proxy_args": [int(label.split(":")[2])],
                                "sink_rule": rule,
                            })
                        except Exception:
                            pass

                tainted_args.append(idx)
                labels.update(t)
                origins.update(state.get_origins(attr))

            if tainted_args:
                self.logger.log(f"[TAINTER] Sink matched: {callee} rule={rule.get('name')} args={tainted_args}")
                finding = {
                    "rule_id": self.ruleset.rule_id,
                    "cwe": self.ruleset.cwe,
                    "title": self.ruleset.title,
                    "severity": self.ruleset.severity,
                    "func_name": func_info.function,
                    "func_ea": func_info.ea,
                    "sink": {"name": callee, "ea": insn.ea},
                    "arg_indexes": tainted_args,
                    "taint_labels": sorted(labels),
                    "sources": [
                        {"label": o[0], "ea": o[1], "function": o[2]} for o in sorted(origins)
                    ],
                }
                findings.append(finding)

        return findings


class FunctionScanner:
    """函数扫描器"""

    def __init__(self, processor, logger):
        self.processor = processor
        self.logger = logger

    def scan(self, func_info):
        state = TaintState()
        self.logger.log(f"[TAINTER] Initial state for {func_info.function}:\n{state}")

        findings = []
        for insn in func_info.insns:
            self.processor.process(state, insn, func_info, findings)
        self.logger.log(f"[TAINTER] Final state for {func_info.function}:\n{state}")
        return findings, state


class MicrocodeTaintEngine:
    def __init__(self, ruleset, logger=None, verbose=False):
        self.ruleset = ruleset
        self.logger = logger
        self.utils = MicroCodeUtils()
        self.rule_resolver = RuleResolver(ruleset, self.logger)
        self.pathfinder_config = PathFinderConfig(max_depth=10)
        self.pathfinder = PathFinder(ruleset, self.logger, self.pathfinder_config)
        self.processor = InstructionTaintProcessor(
            ruleset, self.logger, self.rule_resolver, utils=self.utils
        )
        self.function_scanner = FunctionScanner(self.processor, self.logger)
        self.summary_generator = SummaryGenerator(ruleset, self.logger, utils=self.utils)

    def scan_function(self, func_info):
        return self.function_scanner.scan(func_info)

    def _sort_call_chain(self, chain_functions):
        visited = set()
        sorted_list = []

        def visit(u):
            visited.add(u)
            func = ida_funcs.get_func(u)
            if func:
                for head in idautils.FuncItems(func.start_ea):
                    for ref in idautils.CodeRefsFrom(head, 0):
                        f = ida_funcs.get_func(ref)
                        if f and f.start_ea == ref:
                            callee = f.start_ea
                            if callee in chain_functions and callee not in visited:
                                visit(callee)
            sorted_list.append(u)

        for ea in chain_functions:
            if ea not in visited:
                visit(ea)

        return sorted_list

    def scan_global(self, maturity):
        self.rule_resolver.resolve_rules()

        self.pathfinder.ruleset = self.ruleset
        self.pathfinder.identify_markers()
        path_result = self.pathfinder.find_paths()

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

        sorted_chain = self._sort_call_chain(chain_functions)

        findings = []
        for ea in sorted_chain:
            func = ida_funcs.get_func(ea)
            if not func:
                continue

            func_info = analyze_function(func, maturity)
            self.logger.log(f"[DEBUG] function info {func_info.to_string()}")

            if func_info:
                f_findings, state = self.function_scanner.scan(func_info)

                if state.entries:
                    self.logger.log(f"[TAINTER] Function {func_info.function}: taint entries={len(state.entries)}")

                real_findings = []
                proxy_findings = []
                for f in f_findings:
                    if f.get("type") == "sink_proxy":
                        proxy_findings.append(f)
                    else:
                        labels = f.get("taint_labels", [])
                        has_real = any(not label.startswith("SYM:ARG:") for label in labels)
                        if has_real or not labels:
                            real_findings.append(f)

                findings.extend(real_findings)
                self.summary_generator.generate(func_info, state, proxy_findings)

        for finding in findings:
            finding["call_chains"] = raw_chains

        return findings
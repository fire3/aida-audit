from collections import deque
import sys

from .state import TaintState
from .analyzer import analyze_function
from .common import MicroCodeUtils
from .constants import (
    idc,
    ida_funcs,
    idautils,
    BADADDR,
)
from ..pathfinder import PathFinder, PathFinderConfig


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
    """基于污点状态生成动态规则，输出为对 ruleset 的就地更新。"""

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
                    key = self.utils.op_key(read.location)
                    taint = state.get_taint(key)
                    if taint:
                        is_source = True
                        break

        if not is_source:
            for lvar_idx in func_info.return_vars:
                key = f"lvar:{lvar_idx}"
                taint = state.get_taint(key)
                if taint:
                    is_source = True
                    break

        args_map = {a.lvar_idx: i for i, a in enumerate(func_info.args)}

        for lvar_idx, arg_pos in args_map.items():
            key = f"addr:lvar:{lvar_idx}"
            taint = state.get_taint(key)
            if taint:
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
    """指令级污点处理器，输出为对 state 与 findings 的就地更新。"""

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
                        call.ret = writes[0].location

        if self.utils.is_move_opcode(opcode) and len(writes) == 1:
            w_key = self.utils.op_key(writes[0].location)
            for r in reads:
                r_key = self.utils.op_key(r.location)
                if self.utils.is_addr_key(r_key) and w_key:
                    target = self.utils.strip_addr_key(r_key)
                    state.add_alias(w_key, target)

        read_labels, read_origins, read_keys = self._collect_reads(state, insn.reads)

        if self.utils.is_store_opcode(opcode) and read_labels:
            for r in reads:
                r_key = self.utils.op_key(r.location)
                if r_key and r_key in state.aliases:
                    target = state.aliases[r_key]
                    state.add_taint(target, read_labels, read_origins)

        if read_labels:
            self._propagate_writes(state, insn, read_labels, read_origins, read_keys)
        for call in insn.calls:
            findings.extend(self._apply_call(insn, call, state, func_info))

    def _propagate_writes(self, state, insn, labels, origins, read_keys):
        write_keys = []
        for write in insn.writes:
            key = self.utils.op_key(write.location)
            state.add_taint(key, labels, origins)
            if key:
                write_keys.append(key)

    def _collect_reads(self, state, reads):
        labels = set()
        origins = set()
        keys = []
        for read in reads:
            key = self.utils.op_key(read.location)
            if not key:
                continue
            keys.append(key)
            labels.update(state.get_taint(key))
            origins.update(state.get_origins(key))
        return labels, origins, keys

    def _apply_call(self, insn, call, state, func_info):
        findings = []
        callee, callee_ea = self._resolve_callee(call)
        if not callee and not callee_ea:
            return findings
        args = call.args or []
        ret = call.ret

        labels, origins = self._collect_arg_taint(state, args, range(len(args)))

        self._apply_sources(insn, callee, callee_ea, args, ret, state, func_info)
        self._apply_propagators(callee, callee_ea, args, ret, state, func_info)
        self._apply_default_return_propagation(callee, args, ret, state, func_info)
        findings.extend(self._apply_sinks(insn, callee, callee_ea, args, state, func_info))

        return findings

    def _collect_arg_taint(self, state, args, indexes):
        labels = set()
        origins = set()
        for idx in indexes:
            if idx < 0 or idx >= len(args):
                continue
            key = self.utils.op_key(args[idx])
            labels.update(state.get_taint(key))
            origins.update(state.get_origins(key))
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
        if target is not None:
            if hasattr(target, "ea"):
                callee_ea = target.ea
            elif isinstance(target, dict):
                callee_ea = target.get("ea")
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
        print(f"[TAINT_DEBUG_SOURCE] _apply_sources: callee={callee} callee_ea={callee_ea} args_count={len(args)}", file=sys.stderr)
        for rule in self.ruleset.sources:
            print(f"[TAINT_DEBUG_SOURCE]   Checking rule: name={rule.get('name')} ea={rule.get('ea')} label={rule.get('label')}", file=sys.stderr)
            if not self._rule_matches(rule, callee, callee_ea):
                print(f"[TAINT_DEBUG_SOURCE]   Rule does NOT match: {rule.get('name')}", file=sys.stderr)
                continue
            print(f"[TAINT_DEBUG_SOURCE]   Rule MATCHED: {rule.get('name')}", file=sys.stderr)
            label = rule.get("label") or callee
            origins = {(label, insn.ea, func_info.function)}
            out_args = rule.get("out_args") or rule.get("args") or []
            print(f"[TAINT_DEBUG_SOURCE]   out_args={out_args}", file=sys.stderr)
            for idx in out_args:
                if idx < 0 or idx >= len(args):
                    continue
                key = self.utils.op_key(args[idx])
                print(f"[TAINT_DEBUG_SOURCE]   Adding taint: idx={idx} key={key} labels={{{label}}}", file=sys.stderr)
                state.add_taint(key, {label}, origins)
            if rule.get("ret"):
                key = self.utils.op_key(ret)
                print(f"[TAINT_DEBUG_SOURCE]   Adding return taint: key={key}", file=sys.stderr)
                state.add_taint(key, {label}, origins)
            if rule.get("ret"):
                key = self.utils.op_key(ret)
                print(f"[TAINT_DEBUG_SOURCE]   Adding return taint: key={key}", file=sys.stderr)
                state.add_taint(key, {label}, origins)

    def _apply_propagators(self, callee, callee_ea, args, ret, state, func_info):
        for rule in self.ruleset.propagators:
            if not self._rule_matches(rule, callee, callee_ea):
                continue
            from_args = rule.get("from_args")
            if from_args is None:
                from_args = list(range(len(args)))
            labels, origins = self._collect_arg_taint(state, args, from_args)
            if not labels:
                continue
            to_args = rule.get("to_args") or []
            to_keys = []
            for idx in to_args:
                if idx < 0 or idx >= len(args):
                    continue
                key = self.utils.op_key(args[idx])
                state.add_taint(key, labels, origins)
                if key:
                    to_keys.append(key)
            ret_key = None
            if rule.get("to_ret"):
                ret_key = self.utils.op_key(ret)
                state.add_taint(ret_key, labels, origins)

    def _apply_default_return_propagation(self, callee, args, ret, state, func_info):
        if not ret:
            return
        labels, origins = self._collect_arg_taint(state, args, range(len(args)))
        if labels:
            key = self.utils.op_key(ret)
            state.add_taint(key, labels, origins)

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
            print(f"[TAINT_DEBUG_SINK] Checking sink: callee={callee} rule_name={rule.get('name')} arg_indexes={arg_indexes} args_count={len(args)}", file=sys.stderr)
            for idx in arg_indexes:
                if idx < 0 or idx >= len(args):
                    continue
                key = self.utils.op_key(args[idx])
                t = state.get_taint(key)
                print(f"[TAINT_DEBUG_SINK]   idx={idx} key={key} taint={t}", file=sys.stderr)
                if not t:
                    continue

                for label in t:
                    if label.startswith("SYM:ARG:"):
                        try:
                            findings.append(
                                {
                                    "type": "sink_proxy",
                                    "proxy_args": [int(label.split(":")[2])],
                                    "sink_rule": rule,
                                }
                            )
                        except Exception:
                            pass

                tainted_args.append(idx)
                labels.update(t)
                origins.update(state.get_origins(key))
            if tainted_args:
                print(f"[TAINT_DEBUG_SINK]   FOUND TAINTED SINK: callee={callee} tainted_args={tainted_args} labels={labels}", file=sys.stderr)
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
    """函数扫描器，输出为 (findings, state)。"""
    def __init__(self, processor, logger):
        self.processor = processor
        self.logger = logger

    def scan(self, func_info):
        state = TaintState()
        self._seed_args(state, func_info)

        findings = []
        for insn in func_info.insns:
            self.processor.process(state, insn, func_info, findings)
        return findings, state

    def _seed_args(self, state, func_info):
        for arg in func_info.args:
            lvar_idx = arg.lvar_idx
            if lvar_idx is not None:
                key = f"lvar:{lvar_idx}"
                sym_label = f"SYM:ARG:{lvar_idx}"
                state.add_taint(key, {sym_label}, set())


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
            
            if func_info:
                f_findings, state = self.function_scanner.scan(func_info)

                real_findings = []
                proxy_findings = []
                for f in f_findings:
                    if f.get("type") == "sink_proxy":
                        proxy_findings.append(f)
                    else:
                        labels = f.get("taint_labels", [])
                        has_real = False
                        for label in labels:
                            if not label.startswith("SYM:ARG:"):
                                has_real = True
                                break
                        if has_real or not labels:
                            real_findings.append(f)

                findings.extend(real_findings)
                self.summary_generator.generate(func_info, state, proxy_findings)

        for finding in findings:
            finding["call_chains"] = raw_chains

        return findings

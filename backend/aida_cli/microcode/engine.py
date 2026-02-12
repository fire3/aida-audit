from collections import deque

from .state import TaintState
from .logger import EngineLogger
from .analyzer import analyze_function
from .common import MicroCodeUtils
from .constants import (
    idc,
    ida_funcs,
    idautils,
    ida_hexrays,
    BADADDR,
)


class RuleResolver:
    """解析规则名称到地址并写回 ruleset，输出为更新后的规则集内容。"""
    def __init__(self, ruleset, logger):
        self.ruleset = ruleset
        self.logger = logger

    def resolve_rules(self):
        if not idc:
            self.logger.warn("rules.resolve.unavailable")
            return
        self.logger.info("rules.resolve.start")
        for rule in self._iter_rules():
            name = rule.get("name")
            if not name:
                continue
            ea = self.resolve_rule_ea(name)
            if ea is not None:
                rule["ea"] = ea
                self.logger.debug("rules.resolve.hit", name=name, ea=hex(ea))

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


class CallChainPlanner:
    """调用链规划器，输出调用者集合与路径列表。"""
    def __init__(self, logger):
        self.logger = logger

    def collect_callers(self, rules):
        caller_set = set()
        for rule in rules:
            ea = rule.get("ea")
            if not ea:
                continue
            for ref in idautils.CodeRefsTo(ea, 0):
                func = ida_funcs.get_func(ref)
                if func:
                    caller_set.add(func.start_ea)
        return caller_set

    def find_call_chain(self, source_callers, sink_callers):
        chain_functions = set()
        all_paths = []

        self.logger.info("scan.global.bfs.fwd", sources=len(source_callers), sinks=len(sink_callers))
        fwd_nodes, fwd_paths = self._bfs_search(source_callers, sink_callers, "Forward")
        chain_functions.update(fwd_nodes)
        all_paths.extend(fwd_paths)

        self.logger.info("scan.global.bfs.rev", sources=len(source_callers), sinks=len(sink_callers))
        rev_nodes, rev_paths = self._bfs_search(sink_callers, source_callers, "Reverse")
        chain_functions.update(rev_nodes)
        for path in rev_paths:
            all_paths.append(path[::-1])

        return chain_functions, all_paths

    def sort_call_chain(self, chain_functions):
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

    def _bfs_search(self, start_nodes, end_nodes, direction_name):
        max_depth = 10
        found_nodes = set()
        found_paths = []

        queue = deque()
        for ea in start_nodes:
            queue.append((ea, [ea]))

        visited = set(start_nodes)

        while queue:
            curr_ea, path = queue.popleft()

            if curr_ea in end_nodes:
                found_nodes.update(path)
                found_paths.append(path)
                names = [ida_funcs.get_func_name(x) for x in path]
                self.logger.debug(f"scan.global.path.{direction_name.lower()}", path=" -> ".join(names))
                continue

            if len(path) >= max_depth:
                continue

            func = ida_funcs.get_func(curr_ea)
            if not func:
                continue

            callees = set()
            for head in idautils.FuncItems(func.start_ea):
                for ref in idautils.CodeRefsFrom(head, 0):
                    f = ida_funcs.get_func(ref)
                    if f and f.start_ea == ref:
                        callee_ea = f.start_ea
                        if f.flags & (ida_funcs.FUNC_THUNK | ida_funcs.FUNC_LIB):
                            if callee_ea not in end_nodes:
                                continue
                        callees.add(callee_ea)

            for callee in callees:
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))

        return found_nodes, found_paths


class SummaryGenerator:
    """基于污点状态生成动态规则，输出为对 ruleset 的就地更新。"""

    def __init__(self, ruleset, logger, utils=None):
        self.ruleset = ruleset
        self.logger = logger
        self.utils = utils or MicroCodeUtils()

    def generate(self, func_info, state, proxy_findings=None):
        func_ea_str = func_info.get("ea")
        if not func_ea_str:
            return
        func_ea = int(func_ea_str, 16)
        func_name = func_info.get("function")

        self.logger.debug("summary.gen.start", function=func_name)
        is_source, tainted_out_args = self._inspect_taint_outputs(func_info, state)

        if is_source:
            self.logger.info("rules.dynamic.add", function=func_name, ret=is_source, out_args=tainted_out_args)
            new_rule = {
                "ea": func_ea,
                "name": func_name,
                "label": f"Dynamic:{func_name}",
                "out_args": tainted_out_args,
                "ret": True,
            }
            self.ruleset.sources.append(new_rule)
        else:
            self.logger.debug("summary.gen.no_taint", function=func_name)

        if proxy_findings:
            proxy_args = self._collect_proxy_args(proxy_findings)
            if proxy_args:
                self.logger.info("rules.dynamic.add_sink", function=func_name, args=list(proxy_args))
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
        for insn in func_info.get("insns", []):
            if insn.get("opcode") == "ret":
                self.logger.debug("summary.gen.ret_insn", ea=insn.get("ea"), reads=insn.get("reads"))
                for read in insn.get("reads", []):
                    key = self.utils.op_key(read.get("op"))
                    taint = state.get_taint(key)
                    if taint:
                        self.logger.debug("summary.gen.ret_taint", key=key, labels=list(taint))
                        is_source = True
                        break

        if not is_source:
            for lvar_idx in func_info.get("return_vars", []):
                key = f"lvar:{lvar_idx}"
                taint = state.get_taint(key)
                if taint:
                    self.logger.debug("summary.gen.ret_var_taint", key=key, labels=list(taint))
                    is_source = True
                    break

        args_map = {a["lvar_idx"]: i for i, a in enumerate(func_info.get("args", []))}

        for lvar_idx, arg_pos in args_map.items():
            key = f"addr:lvar:{lvar_idx}"
            taint = state.get_taint(key)
            if taint:
                self.logger.debug("summary.gen.arg_taint", arg_idx=arg_pos, key=key, labels=list(taint))
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
        calls = insn.get("calls", [])
        opcode = insn.get("opcode")
        writes = insn.get("writes", [])
        reads = insn.get("reads", [])

        if calls and (opcode == "op_4" or opcode == "mov"):
            if writes:
                for call in calls:
                    if call.get("ret") is None:
                        call["ret"] = writes[0].get("op")

        if (opcode == "op_4" or opcode == "mov") and len(writes) == 1:
            w_key = self.utils.op_key(writes[0].get("op"))
            for r in reads:
                r_key = self.utils.op_key(r.get("op"))
                if r_key and r_key.startswith("addr:") and w_key:
                    target = r_key[5:]
                    state.add_alias(w_key, target)
                    if self.logger._verbose:
                        self.logger.debug("alias.add", ptr=w_key, target=target)

        read_labels, read_origins, read_keys = self._collect_reads(state, insn.get("reads", []))

        if (opcode == "op_1" or opcode == "stx") and read_labels:
            for r in reads:
                r_key = self.utils.op_key(r.get("op"))
                if r_key and r_key in state.aliases:
                    target = state.aliases[r_key]
                    state.add_taint(target, read_labels, read_origins)
                    if self.logger._verbose:
                        self.logger.debug("alias.store", ptr=r_key, target=target, labels=list(read_labels))

        if read_labels:
            self._propagate_writes(state, insn, read_labels, read_origins, read_keys)
        for call in insn.get("calls", []):
            findings.extend(self._apply_call(insn, call, state, func_info))

    def _propagate_writes(self, state, insn, labels, origins, read_keys):
        write_keys = []
        for write in insn.get("writes", []):
            key = self.utils.op_key(write.get("op"))
            state.add_taint(key, labels, origins)
            if key:
                write_keys.append(key)
        if write_keys:
            self.logger.debug(
                "taint.flow",
                ea=insn.get("ea"),
                reads=read_keys,
                writes=write_keys,
                labels=sorted(labels),
                origins=sorted(origins),
            )

    def _collect_reads(self, state, reads):
        labels = set()
        origins = set()
        keys = []
        for read in reads:
            key = self.utils.op_key(read.get("op"))
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
        args = call.get("args") or []
        ret = call.get("ret")

        labels, origins = self._collect_arg_taint(state, args, range(len(args)))
        if labels:
            self.logger.debug(
                "taint.call.in",
                caller=func_info.get("function"),
                callee=callee,
                args=[idx for idx in range(len(args))],
                labels=sorted(labels),
                origins=sorted(origins),
            )

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
        callee = call.get("callee_name") or ""
        target = call.get("target")
        callee_ea = target.get("ea") if target else None
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
            origins = {(label, insn.get("ea"), func_info.get("function"))}
            out_args = rule.get("args") or rule.get("out_args") or []
            for idx in out_args:
                if idx < 0 or idx >= len(args):
                    continue
                key = self.utils.op_key(args[idx])
                state.add_taint(key, {label}, origins)
                self.logger.debug(
                    "taint.source",
                    label=label,
                    ea=insn.get("ea"),
                    function=func_info.get("function"),
                    target=f"arg[{idx}]",
                    key=key,
                )
            if rule.get("ret"):
                key = self.utils.op_key(ret)
                state.add_taint(key, {label}, origins)
                self.logger.debug(
                    "taint.source",
                    label=label,
                    ea=insn.get("ea"),
                    function=func_info.get("function"),
                    target="ret",
                    key=key,
                )

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
            self.logger.debug(
                "taint.call.propagate",
                caller=func_info.get("function"),
                callee=callee,
                from_args=from_args,
                to_args=to_args,
                to_keys=to_keys,
                labels=sorted(labels),
                ret_key=ret_key,
            )

    def _apply_default_return_propagation(self, callee, args, ret, state, func_info):
        if not ret:
            return
        labels, origins = self._collect_arg_taint(state, args, range(len(args)))
        if labels:
            key = self.utils.op_key(ret)
            state.add_taint(key, labels, origins)
            self.logger.debug(
                "taint.call.ret",
                caller=func_info.get("function"),
                callee=callee,
                ret_key=key,
                labels=sorted(labels),
                origins=sorted(origins),
            )

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
                key = self.utils.op_key(args[idx])
                t = state.get_taint(key)
                if self.logger._verbose:
                    self.logger.debug("sink.check", index=idx, key=key, taint=list(t))
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
                self.logger.debug("taint.sink.arg", callee=callee, index=idx, key=key)
            if tainted_args:
                finding = {
                    "rule_id": self.ruleset.rule_id,
                    "cwe": self.ruleset.cwe,
                    "title": self.ruleset.title,
                    "severity": self.ruleset.severity,
                    "func_name": func_info.get("function"),
                    "func_ea": func_info.get("ea"),
                    "sink": {"name": callee, "ea": insn.get("ea")},
                    "arg_indexes": tainted_args,
                    "taint_labels": sorted(labels),
                    "sources": [
                        {"label": o[0], "ea": o[1], "function": o[2]} for o in sorted(origins)
                    ],
                }
                findings.append(finding)
                self.logger.info(
                    "taint.sink.hit",
                    callee=callee,
                    args=tainted_args,
                    function=func_info.get("function"),
                    labels=sorted(labels),
                    sources=sorted(origins),
                )
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
        insns = func_info.get("insns", [])
        self.logger.info(
            "scan.function.start", function=func_info.get("function"), insn_count=len(insns)
        )
        for insn in insns:
            if self.logger._verbose:
                self.logger.debug(
                    "scan.insn",
                    ea=insn.get("ea"),
                    text=insn.get("text"),
                    opcode=insn.get("opcode"),
                    writes=self.logger._format_value(insn.get("writes")),
                    reads=self.logger._format_value(insn.get("reads")),
                )
            self.processor.process(state, insn, func_info, findings)
        return findings, state

    def _seed_args(self, state, func_info):
        args = func_info.get("args", [])
        for arg in args:
            lvar_idx = arg.get("lvar_idx")
            if lvar_idx is not None:
                key = f"lvar:{lvar_idx}"
                sym_label = f"SYM:ARG:{lvar_idx}"
                state.add_taint(key, {sym_label}, set())


class MicrocodeTaintEngine:
    """微码污点分析入口，输出 findings 列表。"""
    def __init__(self, ruleset, logger=None, verbose=False):
        self.ruleset = ruleset
        self.logger = EngineLogger(logger=logger, verbose=verbose)
        self.utils = MicroCodeUtils()
        self.rule_resolver = RuleResolver(ruleset, self.logger)
        self.call_chain_planner = CallChainPlanner(self.logger)
        self.processor = InstructionTaintProcessor(
            ruleset, self.logger, self.rule_resolver, utils=self.utils
        )
        self.function_scanner = FunctionScanner(self.processor, self.logger)
        self.summary_generator = SummaryGenerator(ruleset, self.logger, utils=self.utils)

    def scan_function(self, func_info):
        return self.function_scanner.scan(func_info)

    def scan_global(self, maturity):
        self.rule_resolver.resolve_rules()

        source_callers = self.call_chain_planner.collect_callers(self.ruleset.sources)
        sink_callers = self.call_chain_planner.collect_callers(self.ruleset.sinks)
        self.logger.info("scan.global.callers", sources=len(source_callers), sinks=len(sink_callers))

        if not source_callers or not sink_callers:
            self.logger.warn("scan.global.missing_callers")
            return []

        chain_functions, raw_chains = self.call_chain_planner.find_call_chain(
            source_callers, sink_callers
        )
        if not chain_functions:
            self.logger.warn("scan.global.no_path")
            return []

        self.logger.info("scan.global.chain", functions=len(chain_functions))

        formatted_chains = []
        for path in raw_chains:
            chain_info = []
            for ea in path:
                chain_info.append({"ea": hex(ea), "name": ida_funcs.get_func_name(ea) or f"sub_{ea:x}"})
            formatted_chains.append(chain_info)

        sorted_chain = self.call_chain_planner.sort_call_chain(chain_functions)

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
            finding["call_chains"] = formatted_chains

        return findings

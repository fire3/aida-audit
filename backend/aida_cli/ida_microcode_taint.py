import json
import re


# Try to import IDA modules
try:
    import idapro
except ImportError:
    idapro = None

try:
    import ida_auto
    import ida_pro
    import ida_ida
    import idc
    import ida_nalt
    import ida_hexrays
    import ida_funcs
except ImportError:
    print("Error: This script must be run within IDA Pro.")
    sys.exit(1)



_mop_visitor_base = ida_hexrays.mop_visitor_t if ida_hexrays else object


class MopUsageVisitor(_mop_visitor_base):
    def __init__(self, analyzer, reads, writes, calls):
        if ida_hexrays:
            ida_hexrays.mop_visitor_t.__init__(self)
        self.analyzer = analyzer
        self.reads = reads
        self.writes = writes
        self.calls = calls
        self.seen_reads = set()
        self.seen_writes = set()
        self.seen_calls = set()

    def visit_mop(self, mop, type_id, is_target):
        if ida_hexrays is None:
            return 0
        try:
            t = getattr(mop, "t", None)
            if t == ida_hexrays.mop_d:
                inner = getattr(mop, "d", None)
                if inner is not None and self.analyzer._is_call_opcode(inner.opcode):
                    key = id(inner)
                    if key not in self.seen_calls:
                        self.seen_calls.add(key)
                        self.analyzer._record_call(inner, self.calls)

            if t in (ida_hexrays.mop_c, ida_hexrays.mop_sc, ida_hexrays.mop_f, ida_hexrays.mop_d):
                return 0

            access_mode = None
            if t == ida_hexrays.mop_a:
                access_mode = "addr"

            op = self.analyzer._mop_entry(mop)
            if op is None:
                return 0

            role = "dst" if is_target else "src"
            key = (role, op.get("key"), access_mode)
            entry = {"role": role, "op": op}
            if access_mode:
                entry["access_mode"] = access_mode

            if is_target:
                if key not in self.seen_writes:
                    self.seen_writes.add(key)
                    self.writes.append(entry)
            else:
                if key not in self.seen_reads:
                    self.seen_reads.add(key)
                    self.reads.append(entry)
        except Exception:
            pass
        return 0


class MicrocodeAnalyzer:
    def __init__(self, mba):
        self.mba = mba

    def analyze_instruction(self, insn):
        reads, writes, calls = self._analyze_minsn(insn)

        opname = self._get_opcode_name(insn.opcode)

        return {
            "text": self._safe_dstr(insn),
            "opcode": opname,
            "reads": reads,
            "writes": writes,
            "calls": calls,
        }

    def _is_arg_list(self, mop):
        if ida_hexrays is None:
            return False
        return mop is not None and getattr(mop, "t", None) == ida_hexrays.mop_f

    def _is_none_mop(self, mop):
        if ida_hexrays is None:
            return mop is None
        return mop is None or getattr(mop, "t", None) == ida_hexrays.mop_z

    def _select_call_operands(self, l, r, d):
        arg_list_mop = None
        if self._is_arg_list(r):
            arg_list_mop = r
        elif self._is_arg_list(d):
            arg_list_mop = d
        elif self._is_arg_list(l):
            arg_list_mop = l

        callee = l
        if self._is_none_mop(callee) or self._is_arg_list(callee):
            if r is not None and not self._is_arg_list(r):
                callee = r
            elif d is not None and not self._is_arg_list(d):
                callee = d

        ret_mop = d
        if self._is_none_mop(ret_mop) or ret_mop == arg_list_mop or ret_mop == callee:
            if r is not None and r != arg_list_mop and r != callee and not self._is_none_mop(r):
                ret_mop = r
            elif l is not None and l != arg_list_mop and l != callee and not self._is_none_mop(l):
                ret_mop = l
            else:
                ret_mop = None

        return callee, arg_list_mop, ret_mop

    def _iter_call_args(self, obj):
        if obj is None:
            return []
        try:
            return list(obj)
        except Exception:
            pass
        if hasattr(obj, "args"):
            try:
                return list(obj.args)
            except Exception:
                pass
        if hasattr(obj, "f"):
            f = getattr(obj, "f", None)
            if f is not None:
                try:
                    return list(f)
                except Exception:
                    pass
                if hasattr(f, "args"):
                    try:
                        return list(f.args)
                    except Exception:
                        pass
        return []

    def _normalize_call_arg(self, arg):
        if arg is None:
            return None
        if hasattr(arg, "mop"):
            return self._mop_entry(arg.mop)
        if hasattr(arg, "arg"):
            return self._mop_entry(arg.arg)
        return self._mop_entry(arg)

    def _analyze_minsn(self, insn):
        reads = []
        writes = []
        calls = []

        if self._is_call_opcode(insn.opcode):
            self._record_call(insn, calls)

        visitor = MopUsageVisitor(self, reads, writes, calls)
        if hasattr(insn, "for_all_ops"):
            insn.for_all_ops(visitor)
        else:
            for mop, is_target in (
                (getattr(insn, "d", None), True),
                (getattr(insn, "l", None), False),
                (getattr(insn, "r", None), False),
            ):
                if mop is None:
                    continue
                visitor.visit_mop(mop, None, is_target)
                try:
                    mop.for_all_ops(visitor)
                except Exception:
                    pass

        return reads, writes, calls

    def _record_call(self, insn, calls):
        opname = self._get_opcode_name(insn.opcode)
        l = getattr(insn, "l", None)
        r = getattr(insn, "r", None)
        d = getattr(insn, "d", None)

        callee_mop, arg_list_mop, ret_mop = self._select_call_operands(l, r, d)

        callee = None
        if not self._is_none_mop(callee_mop):
            callee = self._mop_entry(callee_mop)

        args = []
        arg_sources = []
        if hasattr(insn, "args") and insn.args:
            arg_sources.append(insn.args)
        if arg_list_mop:
            arg_sources.append(arg_list_mop)
        for src in arg_sources:
            for arg in self._iter_call_args(src):
                norm = self._normalize_call_arg(arg)
                if norm is not None:
                    args.append(norm)

        ret = self._mop_entry(ret_mop) if not self._is_none_mop(ret_mop) else None

        callee_name = None
        if callee:
            callee_name = callee.get("text")

        calls.append(
            {
                "kind": opname,
                "callee_name": callee_name,
                "target": callee,
                "args": args,
                "ret": ret,
            }
        )

    def _get_opcode_name(self, opcode):
        if hasattr(ida_hexrays, "get_mcode_name"):
            return ida_hexrays.get_mcode_name(opcode)
        return f"op_{opcode}"

    def _is_call_opcode(self, opcode):
        if ida_hexrays is None:
            return False
        calls = []
        if hasattr(ida_hexrays, "m_call"):
            calls.append(ida_hexrays.m_call)
        if hasattr(ida_hexrays, "m_icall"):
            calls.append(ida_hexrays.m_icall)
        if opcode in calls:
            return True
        return "call" in self._get_opcode_name(opcode).lower()

    def _safe_dstr(self, obj):
        try:
            s = obj.dstr()
            if s and "ida_hexrays.mnumber_t" in s:
                if hasattr(obj, "value"):
                    return str(obj.value)
            return s
        except Exception:
            try:
                return obj._print()
            except Exception:
                try:
                    return str(obj)
                except Exception:
                    return "<?>"

    def _to_int(self, x):
        try:
            if x is None:
                return None
            return int(x)
        except Exception:
            return None

    def _mop_entry(self, mop):
        key = self._mop_key(mop)
        if key is None:
            return None
        return {"key": key, "text": self._safe_dstr(mop)}

    def _mop_key(self, mop):
        if mop is None or ida_hexrays is None:
            return None
        t = getattr(mop, "t", None)
        if t == ida_hexrays.mop_r:
            reg_id = self._to_int(getattr(mop, "r", None))
            return f"reg:{reg_id}"
        if t == ida_hexrays.mop_l:
            lv = getattr(mop, "l", None)
            idx = self._to_int(getattr(lv, "idx", None)) if lv is not None else None
            return f"lvar:{idx}"
        if t == ida_hexrays.mop_S:
            sv = getattr(mop, "s", None)
            if sv is None:
                sv = getattr(mop, "sv", None)
            off = self._to_int(getattr(sv, "off", None)) if sv is not None else None
            return f"stack:{off}"
        if t == ida_hexrays.mop_v:
            g = getattr(mop, "g", None)
            ea = self._to_int(getattr(g, "ea", None)) if g is not None else None
            return f"global:{ea}"
        if t == ida_hexrays.mop_a:
            a = getattr(mop, "a", None)
            inner = self._mop_key(a)
            return f"addr:{inner}" if inner else f"addr:{self._safe_dstr(mop)}"
        if t == ida_hexrays.mop_n:
            n = getattr(mop, "n", None)
            value = self._to_int(getattr(n, "value", None)) if n is not None else None
            return f"const:{value}"
        if t == ida_hexrays.mop_str:
            return f"str:{self._safe_dstr(mop)}"
        return f"expr:{self._safe_dstr(mop)}"


def analyze_function(pfn, maturity):
    hf = ida_hexrays.hexrays_failure_t()
    mbr = ida_hexrays.mba_ranges_t(pfn)
    mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_WARNINGS, maturity)

    if not mba:
        return None

    analyzer = MicrocodeAnalyzer(mba)
    func_name = ida_funcs.get_func_name(pfn.start_ea)
    output = {
        "function": func_name,
        "ea": hex(pfn.start_ea),
        "maturity": maturity,
        "insns": [],
    }

    for i in range(mba.qty):
        block = mba.get_mblock(i)
        curr = block.head
        insn_idx = 0
        while curr:
            ea_str = hex(curr.ea)
            try:
                cpg_info = analyzer.analyze_instruction(curr)
                insn_entry = {
                    "block_id": i,
                    "insn_idx": insn_idx,
                    "ea": ea_str,
                    "opcode": cpg_info["opcode"],
                    "text": cpg_info["text"],
                    "reads": cpg_info["reads"],
                    "writes": cpg_info["writes"],
                    "calls": cpg_info["calls"],
                }
                output["insns"].append(insn_entry)
            except Exception:
                pass

            curr = curr.next
            insn_idx += 1

    return output


class RuleSet:
    def __init__(self, rule_id, cwe, title, severity, sources, sinks, propagators):
        self.rule_id = rule_id
        self.cwe = cwe
        self.title = title
        self.severity = severity
        self.sources = self._compile_rules(sources)
        self.sinks = self._compile_rules(sinks)
        self.propagators = self._compile_rules(propagators)

    def _compile_rules(self, rules):
        compiled = []
        for rule in rules or []:
            entry = dict(rule)
            pattern = entry.get("pattern")
            if pattern:
                entry["regex"] = re.compile(pattern, re.IGNORECASE)
            compiled.append(entry)
        return compiled


class TaintState:
    def __init__(self):
        self.taint = {}
        self.origins = {}

    def get_taint(self, key):
        return self.taint.get(key, set())

    def get_origins(self, key):
        return self.origins.get(key, set())

    def add_taint(self, key, labels, origins):
        if not key:
            return
        existing = self.taint.setdefault(key, set())
        existing.update(labels)
        if origins:
            origin_set = self.origins.setdefault(key, set())
            origin_set.update(origins)


class MicrocodeTaintEngine:
    def __init__(self, ruleset):
        self.ruleset = ruleset

    def scan_function(self, func_info):
        state = TaintState()
        findings = []
        for insn in func_info.get("insns", []):
            read_labels, read_origins = self._collect_reads(state, insn.get("reads", []))
            if read_labels:
                for write in insn.get("writes", []):
                    key = self._op_key(write.get("op"))
                    state.add_taint(key, read_labels, read_origins)
            for call in insn.get("calls", []):
                findings.extend(self._apply_call(insn, call, state, func_info))
        return findings

    def _collect_reads(self, state, reads):
        labels = set()
        origins = set()
        for read in reads:
            key = self._op_key(read.get("op"))
            if not key:
                continue
            labels.update(state.get_taint(key))
            origins.update(state.get_origins(key))
        return labels, origins

    def _apply_call(self, insn, call, state, func_info):
        findings = []
        callee = call.get("callee_name") or ""
        if not callee:
            return findings
        args = call.get("args") or []
        ret = call.get("ret")

        for rule in self.ruleset.sources:
            if not self._rule_matches(rule, callee):
                continue
            label = rule.get("label") or callee
            origins = {(label, insn.get("ea"), func_info.get("function"))}
            out_args = rule.get("args") or rule.get("out_args") or []
            for idx in out_args:
                if idx < 0 or idx >= len(args):
                    continue
                key = self._op_key(args[idx])
                state.add_taint(key, {label}, origins)
            if rule.get("ret"):
                state.add_taint(self._op_key(ret), {label}, origins)

        for rule in self.ruleset.propagators:
            if not self._rule_matches(rule, callee):
                continue
            from_args = rule.get("from_args")
            if from_args is None:
                from_args = list(range(len(args)))
            labels, origins = self._collect_arg_taint(state, args, from_args)
            if not labels:
                continue
            to_args = rule.get("to_args") or []
            for idx in to_args:
                if idx < 0 or idx >= len(args):
                    continue
                state.add_taint(self._op_key(args[idx]), labels, origins)
            if rule.get("to_ret"):
                state.add_taint(self._op_key(ret), labels, origins)

        labels, origins = self._collect_arg_taint(state, args, range(len(args)))
        if labels and ret:
            state.add_taint(self._op_key(ret), labels, origins)

        for rule in self.ruleset.sinks:
            if not self._rule_matches(rule, callee):
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
                key = self._op_key(args[idx])
                t = state.get_taint(key)
                if not t:
                    continue
                tainted_args.append(idx)
                labels.update(t)
                origins.update(state.get_origins(key))
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

        return findings

    def _collect_arg_taint(self, state, args, indexes):
        labels = set()
        origins = set()
        for idx in indexes:
            if idx < 0 or idx >= len(args):
                continue
            key = self._op_key(args[idx])
            labels.update(state.get_taint(key))
            origins.update(state.get_origins(key))
        return labels, origins

    def _rule_matches(self, rule, callee):
        name = rule.get("name")
        if name:
            if callee == name or callee.lower() == name.lower():
                return True
        regex = rule.get("regex")
        if regex and regex.search(callee):
            return True
        return False

    def _op_key(self, op):
        if not op:
            return None
        key = op.get("key")
        if key:
            return key
        text = op.get("text")
        return text or None


def default_cwe78_rules():
    sources = [
        {"name": "recv", "args": [1], "label": "recv"},
        {"name": "recvfrom", "args": [1], "label": "recvfrom"},
        {"name": "read", "args": [1], "label": "read"},
        {"name": "fgets", "args": [0], "label": "fgets"},
        {"name": "gets", "args": [0], "label": "gets"},
        {"name": "scanf", "args": [1], "label": "scanf"},
        {"name": "fscanf", "args": [1], "label": "fscanf"},
        {"name": "getenv", "ret": True, "label": "getenv"},
    ]
    sinks = [
        {"name": "system", "args": [0]},
        {"name": "popen", "args": [0]},
        {"name": "execl", "args": [0, 1]},
        {"name": "execlp", "args": [0, 1]},
        {"name": "execle", "args": [0, 1]},
        {"name": "execv", "args": [0, 1]},
        {"name": "execve", "args": [0, 1]},
        {"name": "execvp", "args": [0, 1]},
        {"name": "CreateProcessA", "args": [1]},
        {"name": "CreateProcessW", "args": [1]},
        {"name": "WinExec", "args": [0]},
        {"name": "ShellExecuteA", "args": [2]},
        {"name": "ShellExecuteW", "args": [2]},
        {"name": "ShellExecuteExA", "args": [0]},
        {"name": "ShellExecuteExW", "args": [0]},
    ]
    propagators = [
        {"name": "strcpy", "from_args": [1], "to_args": [0]},
        {"name": "strncpy", "from_args": [1], "to_args": [0]},
        {"name": "strcat", "from_args": [1], "to_args": [0]},
        {"name": "strncat", "from_args": [1], "to_args": [0]},
        {"name": "sprintf", "from_args": [1], "to_args": [0]},
        {"name": "snprintf", "from_args": [2], "to_args": [0]},
        {"name": "memcpy", "from_args": [1], "to_args": [0]},
        {"name": "memmove", "from_args": [1], "to_args": [0]},
    ]
    return RuleSet(
        rule_id="cwe-78",
        cwe="CWE-78",
        title="OS Command Injection",
        severity="high",
        sources=sources,
        sinks=sinks,
        propagators=propagators,
    )

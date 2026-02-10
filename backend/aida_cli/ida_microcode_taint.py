import json
import re
import sys


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
    import idautils
    import ida_gdl
    import ida_idaapi
except ImportError as e:
    print(f"Warning: Failed to import main IDA modules: {e}")
    ida_auto = None
    ida_pro = None
    ida_ida = None
    idc = None
    ida_nalt = None
    ida_hexrays = None
    ida_funcs = None
    idautils = None
    ida_gdl = None
    ida_idaapi = None

# ...

def get_badaddr():
    if ida_idaapi and hasattr(ida_idaapi, "BADADDR"):
        return ida_idaapi.BADADDR
    if idc and hasattr(idc, "BADADDR"):
        return idc.BADADDR
    return 0xFFFFFFFFFFFFFFFF

BADADDR = get_badaddr()


try:
    import ida_names
except ImportError:
    ida_names = None

try:
    import ida_xref
except ImportError:
    ida_xref = None



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
        res = {"key": key, "text": self._safe_dstr(mop)}
        if mop and ida_hexrays:
             t = getattr(mop, "t", None)
             if t == ida_hexrays.mop_v:
                 g = getattr(mop, "g", None)
                 if g:
                     res["ea"] = self._to_int(getattr(g, "ea", None))
             elif t == ida_hexrays.mop_h:
                 helper = getattr(mop, "helper", None)
                 if helper:
                     # Try to resolve helper name to EA
                     if ida_names:
                         ea = ida_names.get_name_ea(ida_ida.inf_get_min_ea(), helper)
                         if ea != BADADDR:
                             res["ea"] = ea
                     elif idc:
                         ea = idc.get_name_ea_simple(helper)
                         if ea != BADADDR:
                             res["ea"] = ea
        return res

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
        
        # Handle instructions (like ADD for pointer arithmetic)
        if t == ida_hexrays.mop_d:
            insn = getattr(mop, "d", None)
            if insn and insn.opcode == ida_hexrays.m_add:
                # Prefer the operand that looks like a variable/pointer
                l_key = self._mop_key(insn.l)
                r_key = self._mop_key(insn.r)
                
                # Helper to check if key is a variable
                def is_var(k):
                    return k and (k.startswith("lvar:") or k.startswith("reg:") or k.startswith("addr:"))

                if is_var(l_key):
                    return l_key
                if is_var(r_key):
                    return r_key
        
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
        print(f"[DEBUG] Scanning function: {func_info.get('function')}")
        for insn in func_info.get("insns", []):
            print(f"[DEBUG] Processing insn: {insn.get('text')} (Op: {insn.get('opcode')})")
            read_labels, read_origins = self._collect_reads(state, insn.get("reads", []))
            if read_labels:
                print(f"[DEBUG] Taint read at {insn.get('text')}: {read_labels}")
                for write in insn.get("writes", []):
                    key = self._op_key(write.get("op"))
                    print(f"[DEBUG] Propagating taint to {key}")
                    state.add_taint(key, read_labels, read_origins)
            for call in insn.get("calls", []):
                findings.extend(self._apply_call(insn, call, state, func_info))
        return findings

    def resolve_rules(self):
        print("[DEBUG] Resolving rule addresses...")
        if not ida_names and not idc:
            print("[DEBUG] ida_names and idc modules not available.")
            return
        
        # Debug: Print first 10 names in IDB
        # print("[DEBUG] Sample names in IDB:")
        # try:
        #     count = 0
        #     for ea, name in idautils.Names():
        #         print(f"  {hex(ea)}: {name}")
        #         count += 1
        #         if count >= 10: break
        # except Exception as e:
        #     print(f"[DEBUG] Failed to list names: {e}")

        def _resolve(rules):
            for rule in rules:
                name = rule.get("name")
                if not name:
                    continue
                
                ea = BADADDR
                
                # Helper to try to resolve a name
                def try_name(n):
                    if ida_names and ida_ida:
                        return ida_names.get_name_ea(ida_ida.inf_get_min_ea(), n)
                    if idc:
                         # Fallback to idc
                         return idc.get_name_ea_simple(n)
                    return BADADDR

                # Try exact match
                ea = try_name(name)
                if ea == BADADDR:
                    ea = try_name("_" + name)
                if ea == BADADDR:
                    ea = try_name("__imp_" + name)
                if ea == BADADDR:
                    ea = try_name("__imp__" + name)
                if ea == BADADDR:
                     ea = try_name("." + name)

                if ea != BADADDR:
                    rule["ea"] = ea
                    print(f"[DEBUG] Resolved {name} -> {hex(ea)}")
                # else:
                #    print(f"[DEBUG] Failed to resolve {name}")

        _resolve(self.ruleset.sources)
        _resolve(self.ruleset.sinks)
        _resolve(self.ruleset.propagators)

    def scan_global(self, maturity):
        self.resolve_rules()
        
        # 1. Find Callers
        source_callers = set()
        sink_callers = set()
        
        def find_callers(rules, caller_set, type_name):
            for rule in rules:
                ea = rule.get("ea")
                if not ea:
                    continue
                for ref in idautils.CodeRefsTo(ea, 0):
                    func = ida_funcs.get_func(ref)
                    if func:
                        caller_set.add(func.start_ea)

        find_callers(self.ruleset.sources, source_callers, "source")
        find_callers(self.ruleset.sinks, sink_callers, "sink")
        
        print(f"[DEBUG] Source callers: {len(source_callers)}")
        print(f"[DEBUG] Sink callers: {len(sink_callers)}")
        
        if not source_callers or not sink_callers:
            print("[DEBUG] Missing sources or sinks. Aborting.")
            return []
            
        # 2. Find Paths (BFS)
        print("[DEBUG] Analyzing call graph connectivity...")
        
        reachable_sinks = set()
        chain_functions = set()
        
        for src in source_callers:
            queue = [src]
            visited = {src}
            parent = {src: None}
            
            while queue:
                curr = queue.pop(0)
                if curr in sink_callers:
                    reachable_sinks.add(curr)
                    path = []
                    t = curr
                    while t is not None:
                        path.append(t)
                        t = parent[t]
                    path.reverse()
                    chain_functions.update(path)
                    names = [ida_funcs.get_func_name(x) for x in path]
                    print(f"[DEBUG] Found Path: {' -> '.join(names)}")
                
                func = ida_funcs.get_func(curr)
                if not func: continue
                
                callees = set()
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    for ref in idautils.CodeRefsFrom(head, 0):
                        f = ida_funcs.get_func(ref)
                        if f and f.start_ea == ref:
                             callees.add(f.start_ea)
                
                for callee in callees:
                    if callee not in visited:
                        visited.add(callee)
                        parent[callee] = curr
                        queue.append(callee)

        if not chain_functions:
             print("[DEBUG] No path found between source callers and sink callers.")
             return []
             
        # 3. Analyze functions in the chain
        print(f"[DEBUG] Analyzing {len(chain_functions)} functions in the call chain...")
        findings = []
        for ea in chain_functions:
             func = ida_funcs.get_func(ea)
             if not func: continue
             func_info = analyze_function(func, maturity)
             if func_info:
                 findings.extend(self.scan_function(func_info))
                 
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
        callee_ea = None
        target = call.get("target")
        if target:
             callee_ea = target.get("ea")

        if not callee and not callee_ea:
            return findings
        args = call.get("args") or []
        ret = call.get("ret")

        print(f"[DEBUG] Checking call to {callee} (EA: {hex(callee_ea) if callee_ea else 'None'})")

        for rule in self.ruleset.sources:
            if not self._rule_matches(rule, callee, callee_ea):
                continue
            print(f"[DEBUG] Matched Source: {callee}")
            label = rule.get("label") or callee
            origins = {(label, insn.get("ea"), func_info.get("function"))}
            out_args = rule.get("args") or rule.get("out_args") or []
            for idx in out_args:
                if idx < 0 or idx >= len(args):
                    continue
                key = self._op_key(args[idx])
                print(f"[DEBUG] Tainting arg {idx} ({key}) with {label}")
                state.add_taint(key, {label}, origins)
            if rule.get("ret"):
                key = self._op_key(ret)
                print(f"[DEBUG] Tainting ret ({key}) with {label}")
                state.add_taint(key, {label}, origins)

        for rule in self.ruleset.propagators:
            if not self._rule_matches(rule, callee, callee_ea):
                continue
            from_args = rule.get("from_args")
            if from_args is None:
                from_args = list(range(len(args)))
            labels, origins = self._collect_arg_taint(state, args, from_args)
            if not labels:
                continue
            print(f"[DEBUG] Matched Propagator: {callee}, propagating {labels}")
            to_args = rule.get("to_args") or []
            for idx in to_args:
                if idx < 0 or idx >= len(args):
                    continue
                key = self._op_key(args[idx])
                print(f"[DEBUG] Tainting arg {idx} ({key})")
                state.add_taint(key, labels, origins)
            if rule.get("to_ret"):
                key = self._op_key(ret)
                print(f"[DEBUG] Tainting ret ({key})")
                state.add_taint(key, labels, origins)

        # Default propagation (all args -> ret)
        labels, origins = self._collect_arg_taint(state, args, range(len(args)))
        if labels and ret:
            key = self._op_key(ret)
            # print(f"[DEBUG] Default propagation to ret ({key}): {labels}")
            state.add_taint(key, labels, origins)

        for rule in self.ruleset.sinks:
            if not self._rule_matches(rule, callee, callee_ea):
                continue
            print(f"[DEBUG] Matched Sink: {callee}")
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
                print(f"[DEBUG] Taint reach Sink at arg {idx} ({key}): {t}")
                tainted_args.append(idx)
                labels.update(t)
                origins.update(state.get_origins(key))
            if tainted_args:
                print(f"[DEBUG] FOUND VULNERABILITY in {callee}")
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

    def _rule_matches(self, rule, callee, callee_ea=None):
        if callee_ea is not None and "ea" in rule:
            if rule["ea"] == callee_ea:
                return True
        name = rule.get("name")
        if name:
            if callee == name or callee.lower() == name.lower():
                return True
            # Handle prefixes like _, $, ., __imp__
            sanitized = callee
            if sanitized.startswith("$"):
                sanitized = sanitized[1:]
            if sanitized.startswith("."):
                sanitized = sanitized[1:]
            while sanitized.startswith("_"):
                sanitized = sanitized[1:]
            
            # Special handling for import thunks if they weren't caught by simple lstrip
            if "imp_" in sanitized:
                 # e.g. __imp__execl -> imp__execl -> execl (after lstrip)
                 pass 
            
            if sanitized == name or sanitized.lower() == name.lower():
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
        {"name": "execl", "args": None},
        {"name": "execlp", "args": None},
        {"name": "execle", "args": None},
        {"name": "execv", "args": None},
        {"name": "execve", "args": None},
        {"name": "execvp", "args": None},
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

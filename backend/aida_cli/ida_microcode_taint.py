import json
import sys
from collections import deque


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


def get_badaddr():
    if ida_idaapi and hasattr(ida_idaapi, "BADADDR"):
        return ida_idaapi.BADADDR
    if idc and hasattr(idc, "BADADDR"):
        return idc.BADADDR
    return 0xFFFFFFFFFFFFFFFF

BADADDR = get_badaddr()



# ida_names usage removed
ida_names = None


try:
    import ida_xref
except ImportError:
    ida_xref = None



_mop_visitor_base = ida_hexrays.mop_visitor_t if ida_hexrays else object


class MopUsageVisitor(_mop_visitor_base):
    """Collect reads, writes, and call operands from a microcode instruction."""
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
    """Normalize microcode instructions into read/write/call summaries."""
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

        # Post-process calls to fix missing return values for 'mov dst, call(...)'
        # If this is a move instruction and we found a call but no return value,
        # the move destination is likely the return value.
        opname = self._get_opcode_name(insn.opcode)
        if opname == "mov" and getattr(insn, "d", None):
            for call in calls:
                if call["ret"] is None:
                    call["ret"] = self._mop_entry(insn.d)

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

        callee, callee_name = self._ensure_callee_ea(insn, callee)

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
                    ea = self._resolve_name_ea(helper)
                    if ea is not None:
                        res["ea"] = ea
        return res

    def _resolve_name_ea(self, name):
        if not name:
            return None
        if idc:
            try:
                ea = idc.get_name_ea_simple(name)
                if ea != BADADDR:
                    return ea
            except Exception:
                pass

        for candidate in (name, "_" + name, "__imp_" + name, "__imp__" + name, "." + name):
            if idc:
                try:
                    ea = idc.get_name_ea_simple(candidate)
                    if ea != BADADDR:
                        return ea
                except Exception:
                    pass
        return None

    def _resolve_callsite_ea(self, insn_ea):
        if not insn_ea or insn_ea == BADADDR:
            return None
        if idautils:
            refs = list(idautils.CodeRefsFrom(insn_ea, 0))
            if refs:
                return refs[0]
        if idc:
            try:
                value = idc.get_operand_value(insn_ea, 0)
            except Exception:
                value = None
            if value and value != BADADDR:
                return value
        return None

    def _ensure_callee_ea(self, insn, callee):
        callee_ea = None
        callee_name = None
        if callee:
            callee_ea = callee.get("ea")
            callee_name = callee.get("text")
        if callee_ea is None and callee_name:
            callee_ea = self._resolve_name_ea(callee_name)
        if callee_ea is None:
            callee_ea = self._resolve_callsite_ea(getattr(insn, "ea", None))
        if callee_ea is not None:
            ida_name = None
            if ida_funcs:
                ida_name = ida_funcs.get_func_name(callee_ea)
            if not ida_name and idc:
                try:
                    ida_name = idc.get_name(callee_ea)
                except Exception:
                    pass
            callee_name = ida_name or callee_name or ""
            if callee is None:
                callee = {"key": f"callee:{callee_ea}", "text": callee_name, "ea": callee_ea}
            else:
                callee["ea"] = callee_ea
                if callee_name:
                    callee["text"] = callee_name
        return callee, callee_name

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
            if insn:
                if insn.opcode == ida_hexrays.m_add:
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

                # Handle Load (Dereference) - m_ldx
                # This maps *ptr to load:ptr_key
                if hasattr(ida_hexrays, "m_ldx") and insn.opcode == ida_hexrays.m_ldx:
                    addr_key = self._mop_key(insn.r)
                    if addr_key:
                        return f"load:{addr_key}"
        
        return f"expr:{self._safe_dstr(mop)}"


def analyze_function(pfn, maturity):
    """Extract microcode summaries for a single function."""
    hf = ida_hexrays.hexrays_failure_t()
    mbr = ida_hexrays.mba_ranges_t(pfn)
    mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_WARNINGS, maturity)

    if not mba:
        return None

    analyzer = MicrocodeAnalyzer(mba)
    func_name = ida_funcs.get_func_name(pfn.start_ea)
    
    # Extract argument variables
    func_args = []
    return_vars = []
    if mba.vars:
        try:
            # Robust iteration: lvars_t is a sequence in IDAPython
            for i, v in enumerate(mba.vars):
                if v.is_arg_var:
                    func_args.append({
                        "lvar_idx": i,
                        "name": v.name,
                        "width": v.width
                    })
                # Check for return variable candidates (heuristic)
                # Note: v.is_result_var might not exist in all IDA versions, checking name as fallback
                is_result = False
                if hasattr(v, "is_result_var") and v.is_result_var:
                    is_result = True
                elif v.name and (v.name == "result" or v.name.startswith("retvar")):
                    is_result = True
                
                if is_result:
                    return_vars.append(i)

        except Exception as e:
            # Fallback or silence if iteration fails
            pass

    output = {
        "function": func_name,
        "ea": hex(pfn.start_ea),
        "maturity": maturity,
        "args": func_args,
        "return_vars": return_vars,
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


class TaintState:
    """Track taint labels and their origins for operand keys."""
    def __init__(self):
        self.taint = {}
        self.origins = {}
        self.aliases = {}

    def get_taint(self, key):
        if not key:
            return set()

        # Handle load:ptr keys (dereference)
        if key.startswith("load:"):
            ptr_key = key[5:]
            # If ptr points to target, then *ptr is target
            if ptr_key in self.aliases:
                target = self.aliases[ptr_key]
                return self.get_taint(target)

        labels = self.taint.get(key, set())
        if not labels and key in self.aliases:
            # Check if alias target is tainted
            target = self.aliases[key]
            labels = self.taint.get(target, set())
        return labels

    def get_origins(self, key):
        if not key:
            return set()

        # Handle load:ptr keys (dereference)
        if key.startswith("load:"):
            ptr_key = key[5:]
            if ptr_key in self.aliases:
                target = self.aliases[ptr_key]
                return self.get_origins(target)

        origins = self.origins.get(key, set())
        if not origins and key in self.aliases:
            target = self.aliases[key]
            origins = self.origins.get(target, set())
        return origins

    def add_alias(self, ptr, target):
        if ptr and target and ptr != target:
            self.aliases[ptr] = target

    def add_taint(self, key, labels, origins):
        if not key:
            return
        existing = self.taint.setdefault(key, set())
        existing.update(labels)
        if origins:
            origin_set = self.origins.setdefault(key, set())
            origin_set.update(origins)


class EngineLogger:
    """Structured logging helper for taint tracing and debugging."""

    def __init__(self, logger=None, verbose=False):
        self._logger = logger
        self._verbose = verbose

    def debug(self, event, **fields):
        self._emit("DEBUG", event, fields, verbose_only=True)

    def info(self, event, **fields):
        self._emit("INFO", event, fields)

    def warn(self, event, **fields):
        self._emit("WARN", event, fields)

    def error(self, event, **fields):
        self._emit("ERROR", event, fields)

    def _emit(self, level, event, fields, verbose_only=False):
        if verbose_only and not self._verbose:
            return
        message = self._format_message(event, fields)
        if self._logger and hasattr(self._logger, "log"):
            self._logger.log(message, level=level)
        else:
            print(f"[{level}] {message}")
            sys.stdout.flush()

    def _format_message(self, event, fields):
        formatted = self._format_event(event, fields)
        if formatted:
            return formatted
        parts = [f"{event}"]
        for key in sorted(fields.keys()):
            parts.append(f"{key}={self._format_value(fields[key])}")
        return " ".join(parts)

    def _format_value(self, value):
        if isinstance(value, (list, tuple, set)):
            items = list(value)
            head = items[:8]
            suffix = ",..." if len(items) > 8 else ""
            return "[" + ",".join(str(x) for x in head) + suffix + "]"
        if isinstance(value, dict):
            items = []
            for key in sorted(value.keys()):
                items.append(f"{key}={self._format_value(value[key])}")
            return ",".join(items)
        return str(value)

    def _format_event(self, event, fields):
        if event == "scan.global.callers":
            return f"callers sources={fields.get('sources')} sinks={fields.get('sinks')}"
        if event == "scan.global.missing_callers":
            return "callers missing"
        if event == "scan.global.no_path":
            return "call-chain none"
        if event == "scan.global.chain":
            return f"call-chain functions={fields.get('functions')}"
        if event == "scan.global.path":
            return f"call-chain {fields.get('path')}"
        if event == "scan.function.start":
            return f"function {fields.get('function')} insns={fields.get('insn_count')}"
        if event == "taint.source":
            return (
                f"taint source label={fields.get('label')} "
                f"ea={fields.get('ea')} func={fields.get('function')} "
                f"target={fields.get('target')} key={fields.get('key')}"
            )
        if event == "taint.flow":
            return (
                f"taint flow ea={fields.get('ea')} reads={self._format_value(fields.get('reads'))} "
                f"writes={self._format_value(fields.get('writes'))} "
                f"labels={self._format_value(fields.get('labels'))} "
                f"origins={self._format_value(fields.get('origins'))}"
            )
        if event == "taint.call.in":
            return (
                f"taint call-in caller={fields.get('caller')} callee={fields.get('callee')} "
                f"args={self._format_value(fields.get('args'))} labels={self._format_value(fields.get('labels'))} "
                f"origins={self._format_value(fields.get('origins'))}"
            )
        if event == "taint.call.propagate":
            return (
                f"taint call-prop caller={fields.get('caller')} callee={fields.get('callee')} "
                f"from={self._format_value(fields.get('from_args'))} "
                f"to={self._format_value(fields.get('to_args'))} "
                f"labels={self._format_value(fields.get('labels'))} "
                f"ret={fields.get('ret_key')}"
            )
        if event == "taint.call.ret":
            return (
                f"taint call-ret caller={fields.get('caller')} callee={fields.get('callee')} "
                f"ret={fields.get('ret_key')} labels={self._format_value(fields.get('labels'))} "
                f"origins={self._format_value(fields.get('origins'))}"
            )
        if event == "taint.sink.hit":
            return (
                f"taint sink func={fields.get('function')} callee={fields.get('callee')} "
                f"args={self._format_value(fields.get('args'))} "
                f"labels={self._format_value(fields.get('labels'))} "
                f"sources={self._format_value(fields.get('sources'))}"
            )
        return None


class MicrocodeTaintEngine:
    """Run taint propagation over microcode summaries using rule sets."""

    def __init__(self, ruleset, logger=None, verbose=False):
        self.ruleset = ruleset
        self.logger = EngineLogger(logger=logger, verbose=verbose)

    def scan_function(self, func_info):
        """Run taint propagation for a single function summary."""
        state = TaintState()

        # Inject Symbolic Taint for Arguments (Sink Proxy Detection)
        args = func_info.get("args", [])
        for arg in args:
            lvar_idx = arg.get("lvar_idx")
            if lvar_idx is not None:
                key = f"lvar:{lvar_idx}"
                sym_label = f"SYM:ARG:{lvar_idx}"
                state.add_taint(key, {sym_label}, set())

        findings = []
        insns = func_info.get("insns", [])
        self.logger.info("scan.function.start", function=func_info.get("function"), insn_count=len(insns))
        for insn in insns:
            if self.logger._verbose:
                self.logger.debug("scan.insn", ea=insn.get("ea"), text=insn.get("text"), opcode=insn.get("opcode"), writes=self.logger._format_value(insn.get("writes")), reads=self.logger._format_value(insn.get("reads")))
            self._process_instruction(state, insn, func_info, findings)
        return findings, state

    def resolve_rules(self):
        """Resolve rule symbol names to addresses in the current IDB."""
        if not idc:
            self.logger.warn("rules.resolve.unavailable")
            return
        self.logger.info("rules.resolve.start")
        for rule in self._iter_rules():
            name = rule.get("name")
            if not name:
                continue
            ea = self._resolve_rule_ea(name)
            if ea is not None:
                rule["ea"] = ea
                self.logger.debug("rules.resolve.hit", name=name, ea=hex(ea))

    def scan_global(self, maturity):
        """Find reachable call chains between sources and sinks, then scan them."""
        self.resolve_rules()

        source_callers = set()
        sink_callers = set()

        self._collect_callers(self.ruleset.sources, source_callers)
        self._collect_callers(self.ruleset.sinks, sink_callers)
        self.logger.info("scan.global.callers", sources=len(source_callers), sinks=len(sink_callers))

        if not source_callers or not sink_callers:
            self.logger.warn("scan.global.missing_callers")
            return []

        chain_functions, raw_chains = self._find_call_chain(source_callers, sink_callers)
        if not chain_functions:
            self.logger.warn("scan.global.no_path")
            return []

        self.logger.info("scan.global.chain", functions=len(chain_functions))
        
        # Format call chains for output
        formatted_chains = []
        for path in raw_chains:
            chain_info = []
            for ea in path:
                chain_info.append({
                    "ea": hex(ea),
                    "name": ida_funcs.get_func_name(ea) or f"sub_{ea:x}"
                })
            formatted_chains.append(chain_info)
        
        # Sort functions by dependency (Callees first) to support cross-function taint propagation
        sorted_chain = self._sort_call_chain(chain_functions)
        
        findings = []
        for ea in sorted_chain:
            func = ida_funcs.get_func(ea)
            if not func:
                continue
            func_info = analyze_function(func, maturity)
            if func_info:
                f_findings, state = self.scan_function(func_info)
                
                # Separate real findings from proxy findings
                real_findings = []
                proxy_findings = []
                for f in f_findings:
                    if f.get("type") == "sink_proxy":
                        proxy_findings.append(f)
                    else:
                        # Check if finding only has symbolic taint (internal noise)
                        labels = f.get("taint_labels", [])
                        has_real = False
                        for label in labels:
                            if not label.startswith("SYM:ARG:"):
                                has_real = True
                                break
                        if has_real or not labels:
                            real_findings.append(f)

                findings.extend(real_findings)
                self._generate_summary(func_info, state, proxy_findings)

        # Attach call chains to findings
        for finding in findings:
            finding["call_chains"] = formatted_chains

        return findings

    def _sort_call_chain(self, chain_functions):
        """Perform topological sort (Post-Order) on the call graph subset."""
        visited = set()
        sorted_list = []
        
        def visit(u):
            visited.add(u)
            func = ida_funcs.get_func(u)
            if func:
                # Find all callees that are also in our chain
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

    def _generate_summary(self, func_info, state, proxy_findings=None):
        """Generate dynamic taint rules based on function analysis results."""
        func_ea_str = func_info.get("ea")
        if not func_ea_str:
            return
        func_ea = int(func_ea_str, 16)
        func_name = func_info.get("function")
        
        is_source = False
        tainted_out_args = []
        
        self.logger.debug("summary.gen.start", function=func_name)

        # 1. Check Return Value Taint
        # If the function returns a value derived from a tainted source, mark it as a dynamic source.
        # Microcode 'ret' instruction usually takes no operands (uses return registers implicitely).
        # We need to check if the return register (e.g., R0/X0) is tainted at the end of the function.
        is_source = False
        tainted_out_args = []
        for insn in func_info.get("insns", []):
            if insn.get("opcode") == "ret":
                self.logger.debug("summary.gen.ret_insn", ea=insn.get("ea"), reads=insn.get("reads"))
                # Check reads of ret
                for read in insn.get("reads", []):
                    key = self._op_key(read.get("op"))
                    taint = state.get_taint(key)
                    if taint:
                        self.logger.debug("summary.gen.ret_taint", key=key, labels=list(taint))
                        is_source = True
                        break
        
        # 1.5 Check Return Variable Taint (Fallback)
        if not is_source:
             for lvar_idx in func_info.get("return_vars", []):
                 key = f"lvar:{lvar_idx}"
                 taint = state.get_taint(key)
                 if taint:
                     self.logger.debug("summary.gen.ret_var_taint", key=key, labels=list(taint))
                     is_source = True
                     break

        # 2. Check Out-Arg Taint (Pointer Parameters)
        args_map = {a["lvar_idx"]: i for i, a in enumerate(func_info.get("args", []))}
        
        for lvar_idx, arg_pos in args_map.items():
            key = f"addr:lvar:{lvar_idx}"
            taint = state.get_taint(key)
            if taint:
                self.logger.debug("summary.gen.arg_taint", arg_idx=arg_pos, key=key, labels=list(taint))
                tainted_out_args.append(arg_pos)
                is_source = True

        if is_source:
            self.logger.info("rules.dynamic.add", function=func_name, ret=is_source, out_args=tainted_out_args)
            new_rule = {
                "ea": func_ea,
                "name": func_name,
                "label": f"Dynamic:{func_name}",
                "out_args": tainted_out_args,
                "ret": True 
            }
            # Add to sources
            self.ruleset.sources.append(new_rule)
        else:
            self.logger.debug("summary.gen.no_taint", function=func_name)

        # 3. Register Dynamic Sinks (Sink Proxies)
        if proxy_findings:
            proxy_args = set()
            for pf in proxy_findings:
                for arg in pf.get("proxy_args", []):
                    proxy_args.add(arg)
            
            if proxy_args:
                self.logger.info("rules.dynamic.add_sink", function=func_name, args=list(proxy_args))
                # Use the first proxy finding to inherit properties
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


    def _process_instruction(self, state, insn, func_info, findings):
        """Apply instruction-level taint propagation and call handling."""
        
        # Heuristic: If this is a mov instruction (op_4) and we have a call with no return value,
        # assume the mov destination is the return value.
        calls = insn.get("calls", [])
        opcode = insn.get("opcode")
        writes = insn.get("writes", [])
        reads = insn.get("reads", [])

        if calls and (opcode == "op_4" or opcode == "mov"):
            if writes:
                for call in calls:
                    if call.get("ret") is None:
                        call["ret"] = writes[0].get("op")

        # Alias Analysis: Detect pointer aliases (mov &y, x)
        if (opcode == "op_4" or opcode == "mov") and len(writes) == 1:
            w_key = self._op_key(writes[0].get("op"))
            for r in reads:
                r_key = self._op_key(r.get("op"))
                if r_key and r_key.startswith("addr:") and w_key:
                    target = r_key[5:]
                    state.add_alias(w_key, target)
                    if self.logger._verbose:
                        self.logger.debug("alias.add", ptr=w_key, target=target)

        read_labels, read_origins, read_keys = self._collect_reads(state, insn.get("reads", []))

        # Alias Store: Propagate taint through pointers (stx val, seg, ptr)
        if (opcode == "op_1" or opcode == "stx") and read_labels:
            for r in reads:
                r_key = self._op_key(r.get("op"))
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
            key = self._op_key(write.get("op"))
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
            key = self._op_key(read.get("op"))
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
            key = self._op_key(args[idx])
            labels.update(state.get_taint(key))
            origins.update(state.get_origins(key))
        return labels, origins

    def _rule_matches(self, rule, callee, callee_ea=None):
        if "ea" not in rule:
            # Fallback: Check regex
            if "regex" in rule and callee:
                match = rule["regex"].match(callee)
                return match
            return False
        if callee_ea is None:
            return False
        return rule["ea"] == callee_ea

    def _op_key(self, op):
        if not op:
            return None
        key = op.get("key")
        if key:
            return key
        text = op.get("text")
        return text or None

    def _resolve_rule_ea(self, name):
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

    def _collect_callers(self, rules, caller_set):
        for rule in rules:
            ea = rule.get("ea")
            if not ea:
                continue
            for ref in idautils.CodeRefsTo(ea, 0):
                func = ida_funcs.get_func(ref)
                if func:
                    caller_set.add(func.start_ea)

    def _find_call_chain(self, source_callers, sink_callers):
        """
        Search for paths between sources and sinks in the call graph.
        Handles both:
        1. Downstream flow: SourceCaller -> ... -> SinkCaller (Arg propagation)
        2. Upstream flow: SinkCaller -> ... -> SourceCaller (Return propagation)
        """
        chain_functions = set()
        all_paths = []
        
        # 1. Search Source -> Sink (Standard forward flow)
        self.logger.info("scan.global.bfs.fwd", sources=len(source_callers), sinks=len(sink_callers))
        fwd_nodes, fwd_paths = self._bfs_search(source_callers, sink_callers, "Forward")
        chain_functions.update(fwd_nodes)
        all_paths.extend(fwd_paths)
        
        # 2. Search Sink -> Source (Return taint flow, e.g. A calls B(source), A calls Sink)
        # This handles the case where the "Coordinator" (A) calls the Source Wrapper (B)
        self.logger.info("scan.global.bfs.rev", sources=len(source_callers), sinks=len(sink_callers))
        rev_nodes, rev_paths = self._bfs_search(sink_callers, source_callers, "Reverse")
        chain_functions.update(rev_nodes)
        
        # For reverse paths (Sink -> Source), we should reverse them back to Source -> Sink order for display
        for path in rev_paths:
            all_paths.append(path[::-1])
        
        return chain_functions, all_paths

    def _bfs_search(self, start_nodes, end_nodes, direction_name):
        """Reusable BFS with robustness checks."""
        MAX_DEPTH = 10
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
            
            if len(path) >= MAX_DEPTH:
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
                        # Filter Thunks/Libs unless they are targets
                        if f.flags & (ida_funcs.FUNC_THUNK | ida_funcs.FUNC_LIB):
                            if callee_ea not in end_nodes:
                                continue
                        callees.add(callee_ea)
                        
            for callee in callees:
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))
                    
        return found_nodes, found_paths

    def _resolve_callee(self, call):
        callee = call.get("callee_name") or ""
        target = call.get("target")
        callee_ea = target.get("ea") if target else None
        if callee_ea is None and callee:
            callee_ea = self._resolve_rule_ea(callee)
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
                key = self._op_key(args[idx])
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
                key = self._op_key(ret)
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
                key = self._op_key(args[idx])
                state.add_taint(key, labels, origins)
                if key:
                    to_keys.append(key)
            ret_key = None
            if rule.get("to_ret"):
                ret_key = self._op_key(ret)
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
            key = self._op_key(ret)
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
                key = self._op_key(args[idx])
                t = state.get_taint(key)
                if self.logger._verbose:
                     self.logger.debug("sink.check", index=idx, key=key, taint=list(t))
                if not t:
                    continue
                
                # Check for Sink Proxy (Symbolic Taint)
                for label in t:
                    if label.startswith("SYM:ARG:"):
                        try:
                            findings.append({
                                "type": "sink_proxy",
                                "proxy_args": [int(label.split(":")[2])],
                                "sink_rule": rule
                            })
                        except:
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

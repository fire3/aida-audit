#!/home/fire3/opt/miniconda3/bin/python
import sys
import os
import argparse
import re
import json
import hashlib

# Add backend to sys.path to allow importing aida_cli modules
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.join(current_dir, "..", "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    import idapro
except ImportError:
    idapro = None

try:
    import idalib
except ImportError:
    pass

import idaapi
import ida_hexrays
import ida_lines
import ida_funcs
import ida_auto
import ida_loader
import ida_entry
import ida_segment

# Import aida_cli utils
try:
    from aida_cli import ida_utils
except ImportError:
    # Fallback if we can't import ida_utils (e.g. strict environment)
    # We will define a simple dummy logger if needed
    ida_utils = None

class OperandNormalizer:
    def __init__(self, mba):
        self.mba = mba
        self.imagebase = idaapi.get_imagebase()

    def normalize(self, mop, *, max_depth=6):
        return self._normalize_mop(mop, depth=0, max_depth=max_depth)

    def _normalize_mop(self, mop, *, depth, max_depth):
        if not mop:
            return None

        if depth >= max_depth:
            return {
                "schema": "aida.microcode.mop.v1",
                "t": self._to_int(getattr(mop, "t", None)),
                "kind": self._mop_kind(self._to_int(getattr(mop, "t", None))),
                "size": self._to_int(getattr(mop, "size", None)),
                "value": {"truncated": True},
                "text": self._safe_dstr(mop),
                "uid": None,
            }

        t = self._to_int(getattr(mop, "t", None))
        kind = self._mop_kind(t)
        size = self._to_int(getattr(mop, "size", None))
        text = self._safe_dstr(mop)

        value = self._normalize_mop_value(mop, kind=kind, depth=depth, max_depth=max_depth)
        core = {"t": t, "kind": kind, "size": size, "value": value}
        uid = hashlib.sha1(self._canonical_json(core).encode("utf-8")).hexdigest()

        return {
            "schema": "aida.microcode.mop.v1",
            "t": t,
            "kind": kind,
            "size": size,
            "value": value,
            "text": text,
            "uid": uid,
        }

    def _canonical_json(self, obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def _safe_dstr(self, obj):
        try:
            s = obj.dstr()
            # FIX: Handle SWIG proxy objects for mnumber_t explicitly
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

    def _hx(self, x):
        xi = self._to_int(x)
        return None if xi is None else hex(xi)

    def _get_hexrays_const(self, name):
        return getattr(ida_hexrays, name, None)

    def _mop_kind(self, t):
        type_map = {
            self._get_hexrays_const("mop_z"): "none",
            self._get_hexrays_const("mop_r"): "register",
            self._get_hexrays_const("mop_n"): "number_const",
            self._get_hexrays_const("mop_str"): "string_const",
            self._get_hexrays_const("mop_d"): "insn_result",
            self._get_hexrays_const("mop_S"): "stack_var",
            self._get_hexrays_const("mop_v"): "global_var",
            self._get_hexrays_const("mop_b"): "basic_block",
            self._get_hexrays_const("mop_f"): "arg_list",
            self._get_hexrays_const("mop_l"): "local_var",
            self._get_hexrays_const("mop_a"): "operand_address",
            self._get_hexrays_const("mop_h"): "helper",
            self._get_hexrays_const("mop_c"): "mcases",
            self._get_hexrays_const("mop_fn"): "float_const",
            self._get_hexrays_const("mop_p"): "operand_pair",
            self._get_hexrays_const("mop_sc"): "scattered",
        }

        for k, v in type_map.items():
            if k is None:
                continue
            if t == k:
                return v
        return f"unknown_{t}" if t is not None else "unknown"

    def _normalize_mop_value(self, mop, *, kind, depth, max_depth):
        if depth >= max_depth:
            return {"truncated": True, "text": self._safe_dstr(mop)}

        t = self._to_int(getattr(mop, "t", None))
        if t == self._get_hexrays_const("mop_z"):
            return None

        if kind == "register":
            mreg = self._to_int(getattr(mop, "r", None))
            name = None
            try:
                if mreg is not None and hasattr(ida_hexrays, "get_mreg_name"):
                    name = ida_hexrays.get_mreg_name(mreg, self._to_int(getattr(mop, "size", 0)) or 0)
            except Exception:
                name = None
            return {"mreg": mreg, "name": name}

        if kind == "number_const":
            nnn = getattr(mop, "nnn", None)
            if nnn is None:
                return {"text": self._safe_dstr(mop)}
            value = None
            try:
                value = self._to_int(getattr(nnn, "value", None))
            except Exception:
                value = None
            
            text = self._safe_dstr(nnn)
            # Fallback if dstr returned SWIG proxy string
            if "ida_hexrays.mnumber_t" in text and value is not None:
                text = str(value)
                
            return {
                "value": value,
                "text": text,
            }

        if kind == "string_const":
            for attr in ("cstr", "str", "s"):
                try:
                    v = getattr(mop, attr, None)
                    if v:
                        return {"value": str(v)}
                except Exception:
                    pass
            return {"text": self._safe_dstr(mop)}

        if kind == "stack_var":
            sval = getattr(mop, "s", None)
            off = None
            name = None
            try:
                off = self._to_int(getattr(sval, "off", None))
            except Exception:
                off = None
            try:
                name = getattr(sval, "name", None)
            except Exception:
                name = None
            return {"off": off, "off_hex": self._hx(off), "name": name, "text": self._safe_dstr(mop)}

        if kind == "global_var":
            g = getattr(mop, "g", None)
            ea = None
            try:
                ea = self._to_int(getattr(g, "ea", None))
            except Exception:
                pass
            
            if ea is None:
                ea = self._to_int(g)

            name = None
            try:
                if ea is not None and ea != idaapi.BADADDR:
                    name = idaapi.get_name(ea)
            except Exception:
                pass
                
            return {
                "ea": ea,
                "ea_hex": self._hx(ea),
                "ea_off": (ea - self.imagebase) if (ea is not None and self.imagebase is not None and ea != idaapi.BADADDR) else None,
                "name": name,
            }

        if kind == "basic_block":
            b = getattr(mop, "b", None)
            try:
                return {
                    "serial": self._to_int(getattr(b, "serial", None)),
                    "start": self._to_int(getattr(b, "start", None)),
                    "end": self._to_int(getattr(b, "end", None)),
                }
            except Exception:
                return {"text": self._safe_dstr(mop)}

        if kind == "insn_result":
            # For value normalization, we might want to represent it briefly or recurse?
            # To avoid infinite loops or huge JSON in "value", we might limit depth
            # But here we just return a placeholder or simple structure
            # The full recursion is handled by MicrocodeAnalyzer for CPG
            return {"nested_insn_opcode": self._to_int(getattr(mop.d, "opcode", None))}

        if kind == "arg_list":
            f = getattr(mop, "f", None)
            if f is None:
                return {"text": self._safe_dstr(mop)}
            args = []
            try:
                for a in f:
                    # normalize each arg
                    # a is mop_t
                    args.append(self.normalize(a, max_depth=max_depth-1))
            except Exception:
                return {"text": self._safe_dstr(mop)}
            return {"args": args}

        if kind == "local_var":
            lval = getattr(mop, "l", None)
            idx = None
            name = None
            try:
                idx = self._to_int(getattr(lval, "idx", None))
            except Exception:
                idx = None
            try:
                name = getattr(lval, "name", None)
            except Exception:
                name = None
            return {"idx": idx, "name": name, "text": self._safe_dstr(mop)}

        if kind == "operand_address":
            aval = getattr(mop, "a", None)
            if aval is None:
                return {"text": self._safe_dstr(mop)}
            # We want to represent the inner operand
            inner = None
            try:
                inner = getattr(aval, "x", None)
            except Exception:
                inner = None
            if inner is None and hasattr(aval, "t"):
                inner = aval
            
            if inner is not None:
                 return {"inner": self.normalize(inner, max_depth=max_depth-1)}
            return {"text": self._safe_dstr(mop)}

        if kind == "helper":
            h = getattr(mop, "helper", None)
            if h is None:
                h = getattr(mop, "h", None)
            return {"name": str(h) if h is not None else None, "text": self._safe_dstr(mop)}

        if kind == "mcases":
            return {"text": self._safe_dstr(mop)}

        if kind == "float_const":
            fn = getattr(mop, "fnum", None)
            if fn is None:
                fn = getattr(mop, "fn", None)
            return {"value": str(fn) if fn is not None else None, "text": self._safe_dstr(mop)}

        if kind == "operand_pair":
            pair = getattr(mop, "pair", None)
            if pair is None:
                pair = getattr(mop, "p", None)
            if pair is None:
                return {"text": self._safe_dstr(mop)}
            lo = getattr(pair, "lo", None)
            hi = getattr(pair, "hi", None)
            if lo is None:
                lo = getattr(pair, "l", None)
            if hi is None:
                hi = getattr(pair, "h", None)
            res = {}
            if lo is not None:
                res["lo"] = self.normalize(lo, max_depth=max_depth-1)
            if hi is not None:
                res["hi"] = self.normalize(hi, max_depth=max_depth-1)
            return res

        if kind == "scattered":
            return {"text": self._safe_dstr(mop)}

        return {"text": self._safe_dstr(mop)}


class MopUsageVisitor(ida_hexrays.mop_visitor_t):
    def __init__(self, analyzer, reads, writes, calls):
        ida_hexrays.mop_visitor_t.__init__(self)
        self.analyzer = analyzer
        self.reads = reads
        self.writes = writes
        self.calls = calls
        self.seen_reads = set()
        self.seen_writes = set()
        self.seen_calls = set()

    def visit_mop(self, mop, type_id, is_target):
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

            op = self.analyzer.normalizer.normalize(mop)
            if op is None:
                return 0

            role = "dst" if is_target else "src"
            key = (role, op.get("uid"), access_mode)
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
        self.normalizer = OperandNormalizer(mba)

    def analyze_instruction(self, insn):
        reads, writes, calls = self._analyze_minsn(insn)

        opname = self._get_opcode_name(insn.opcode)

        return {
            "text": self.normalizer._safe_dstr(insn),
            "opcode": opname,
            "reads": reads,
            "writes": writes,
            "calls": calls
        }

    def _is_arg_list(self, mop):
        return mop is not None and getattr(mop, "t", None) == ida_hexrays.mop_f

    def _is_none_mop(self, mop):
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
            return self.normalizer.normalize(arg.mop)
        if hasattr(arg, "arg"):
            return self.normalizer.normalize(arg.arg)
        return self.normalizer.normalize(arg)

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
            for mop, is_target in ((getattr(insn, "d", None), True), (getattr(insn, "l", None), False), (getattr(insn, "r", None), False)):
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
            callee = self.normalizer.normalize(callee_mop)

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

        ret = self.normalizer.normalize(ret_mop) if not self._is_none_mop(ret_mop) else None

        callee_name = None
        if callee and callee.get("value"):
            callee_name = callee["value"].get("name")
        if callee_name is None and callee:
            callee_name = callee.get("text")
        
        calls.append({
            "kind": opname,
            "callee_name": callee_name,
            "target": callee,
            "args": args,
            "ret": ret
        })

    def _get_opcode_name(self, opcode):
        if hasattr(ida_hexrays, "get_mcode_name"):
            return ida_hexrays.get_mcode_name(opcode)
        return f"op_{opcode}"

    def _is_call_opcode(self, opcode):
        calls = []
        if hasattr(ida_hexrays, "m_call"): calls.append(ida_hexrays.m_call)
        if hasattr(ida_hexrays, "m_icall"): calls.append(ida_hexrays.m_icall)
        if opcode in calls: return True
        return "call" in self._get_opcode_name(opcode).lower()

    def _is_store_opcode(self, opcode):
        name = self._get_opcode_name(opcode)
        if name.startswith("m_st"): return True
        if hasattr(ida_hexrays, "m_st") and opcode == ida_hexrays.m_st: return True
        return False


def get_maturity_level(level_name):
    levels = {
        "MMAT_GENERATED": ida_hexrays.MMAT_GENERATED,
        "MMAT_PREOPTIMIZED": ida_hexrays.MMAT_PREOPTIMIZED,
        "MMAT_LOCOPT": ida_hexrays.MMAT_LOCOPT,
        "MMAT_CALLS": ida_hexrays.MMAT_CALLS,
        "MMAT_GLBOPT1": ida_hexrays.MMAT_GLBOPT1,
        "MMAT_GLBOPT2": ida_hexrays.MMAT_GLBOPT2,
        "MMAT_GLBOPT3": ida_hexrays.MMAT_GLBOPT3,
        "MMAT_LVARS": ida_hexrays.MMAT_LVARS,
    }
    return levels.get(level_name, ida_hexrays.MMAT_LVARS)

def analyze_function(pfn, maturity, dump_microcode=False):
    hf = ida_hexrays.hexrays_failure_t()
    mbr = ida_hexrays.mba_ranges_t(pfn)
    mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_WARNINGS, maturity)
    
    if not mba:
        # Try full decompilation if gen_microcode fails?
        # Sometimes decompile() works where gen_microcode might need more setup?
        # But gen_microcode is what was used.
        return None

    analyzer = MicrocodeAnalyzer(mba)
    func_name = ida_funcs.get_func_name(pfn.start_ea)

    if dump_microcode:
        print(f"[microcode] {func_name} @ {hex(pfn.start_ea)}", file=sys.stderr)
        for i in range(mba.qty):
            block = mba.get_mblock(i)
            curr = block.head
            insn_idx = 0
            while curr:
                ea_str = hex(curr.ea) if curr.ea != idaapi.BADADDR else "BADADDR"
                text = analyzer.normalizer._safe_dstr(curr)
                opcode = analyzer._get_opcode_name(curr.opcode)
                print(f"  B{i} I{insn_idx} {ea_str} {opcode} {text}", file=sys.stderr)
                curr = curr.next
                insn_idx += 1
    
    output = {
        "function": func_name,
        "ea": hex(pfn.start_ea),
        "maturity": maturity,
        "insns": []
    }

    for i in range(mba.qty):
        block = mba.get_mblock(i)
        curr = block.head
        insn_idx = 0
        while curr:
            ea_str = hex(curr.ea) if curr.ea != idaapi.BADADDR else "BADADDR"
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
                    "calls": cpg_info["calls"]
                }
                output["insns"].append(insn_entry)
            except Exception as e:
                if dump_microcode:
                    print(f"[error] {func_name} {ea_str} {e}", file=sys.stderr)
            
            curr = curr.next
            insn_idx += 1
            
    return output

def main():
    parser = argparse.ArgumentParser(description="Extract Microcode using idalib")
    parser.add_argument("target", help="Target binary or IDB file")
    parser.add_argument("--func", "-f", help="Function name regex pattern", default=".*")
    parser.add_argument("--maturity", "-m", help="Microcode maturity level", default="MMAT_LVARS")
    parser.add_argument("--dump-microcode", action="store_true", help="Print raw microcode per function")
    
    args = parser.parse_args()
    
    # Initialize helpers
    logger = None
    if ida_utils:
        logger = ida_utils.Logger(verbose=True)
    
    if idapro:
        try:
            if logger:
                logger.log(f"Opening database: {args.target}")
            else:
                print(f"Opening database: {args.target}", file=sys.stderr)
            
            # Use run_auto_analysis=True as in aida_cli
            idapro.open_database(args.target, run_auto_analysis=True)
        except Exception as e:
            msg = f"Error opening database: {e}"
            if logger:
                logger.log(msg, level="ERROR")
            else:
                print(msg, file=sys.stderr)
            sys.exit(1)
    elif 'idalib' in sys.modules:
        # Fallback to direct idalib usage if idapro wrapper is missing but idalib is present
        try:
            print(f"Opening database with idalib: {args.target}", file=sys.stderr)
            idalib.open_database(args.target)
        except Exception as e:
            print(f"Error opening database: {e}", file=sys.stderr)
            sys.exit(1)

    if logger:
        logger.log("Waiting for auto-analysis...")
        monitor = ida_utils.AutoAnalysisMonitor(logger.log)
        monitor.hook()
    else:
        print("Waiting for auto-analysis...", file=sys.stderr)
        monitor = None

    ida_auto.auto_wait()
    
    # Double check if we have functions. If not, try to force analysis or wait more.
    func_count = ida_funcs.get_func_qty()
    if func_count == 0:
        msg = "Warning: No functions found after auto_wait. Attempting to force analysis..."
        if logger:
            logger.log(msg)
        else:
            print(msg, file=sys.stderr)
            
        ida_auto.set_auto_state(True)
        
        # Plan analysis for all segments
        seg = ida_segment.get_first_seg()
        while seg:
             ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)
             seg = ida_segment.get_next_seg(seg.start_ea)
        
        ida_auto.auto_wait()
        func_count = ida_funcs.get_func_qty()
        if logger:
            logger.log(f"Function count after forced analysis: {func_count}")

    if monitor:
        monitor.unhook()
    
    if not ida_hexrays.init_hexrays_plugin():
        msg = "Hex-Rays decompiler not available"
        if logger:
            logger.log(msg, level="ERROR")
        else:
            print(msg, file=sys.stderr)
        return

    maturity = get_maturity_level(args.maturity)
    pattern = re.compile(args.func)
    
    results = []
    
    # Iterate all functions
    for i in range(ida_funcs.get_func_qty()):
        pfn = ida_funcs.getn_func(i)
        if not pfn:
            continue
            
        name = ida_funcs.get_func_name(pfn.start_ea)
        if not pattern.search(name):
            continue
            
        try:
            res = analyze_function(pfn, maturity, dump_microcode=args.dump_microcode)
            if res:
                results.append(res)
        except Exception as e:
            print(f"Failed to analyze {name}: {e}", file=sys.stderr)
            
    print(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()

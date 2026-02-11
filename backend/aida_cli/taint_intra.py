import time
import uuid
from dataclasses import dataclass, field

from . import ida_utils
from .rule_matcher import RuleMatcher

try:
    import ida_hexrays
    import ida_funcs
    import ida_nalt
    import ida_segment
    import ida_idaapi
    import idc
except ImportError:
    ida_hexrays = None
    ida_funcs = None
    ida_nalt = None
    ida_segment = None
    ida_idaapi = None
    idc = None

def _get_badaddr():
    if ida_idaapi and hasattr(ida_idaapi, "BADADDR"):
        return ida_idaapi.BADADDR
    if idc and hasattr(idc, "BADADDR"):
        return idc.BADADDR
    return None

BADADDR = _get_badaddr()


UNKNOWN_ALIAS = object()


@dataclass
class CallArgInfo:
    call_ea: int
    callee: str
    arg_index: int
    is_sink: bool
    arg_size: int

    def to_dict(self):
        return {
            "call_ea": self.call_ea,
            "callee": self.callee,
            "arg_index": self.arg_index,
            "is_sink": self.is_sink,
            "arg_size": self.arg_size,
        }


@dataclass
class StepRecord:
    insn_ea: int
    mcode: int
    from_key: str
    to_key: str
    block_serial: int
    reason: str

    def to_dict(self):
        return {
            "insn_ea": self.insn_ea,
            "mcode": self.mcode,
            "from_key": self.from_key,
            "to_key": self.to_key,
            "block_serial": self.block_serial,
            "reason": self.reason,
        }


@dataclass
class TaintedObjAttrs:
    is_local_var: bool = False
    is_stack_spill: bool = False
    is_global_var: bool = False
    is_func_param: bool = False
    is_func_retval: bool = False
    call_arg_positions: list = field(default_factory=list)
    is_ptr: bool = False
    points_to_tainted: bool = False
    is_cond_checked: bool = False
    sanitized_by: str = None

    def merge(self, other):
        merged = TaintedObjAttrs()
        merged.is_local_var = self.is_local_var or other.is_local_var
        merged.is_stack_spill = self.is_stack_spill or other.is_stack_spill
        merged.is_global_var = self.is_global_var or other.is_global_var
        merged.is_func_param = self.is_func_param or other.is_func_param
        merged.is_func_retval = self.is_func_retval or other.is_func_retval
        merged.is_ptr = self.is_ptr or other.is_ptr
        merged.points_to_tainted = self.points_to_tainted or other.points_to_tainted
        merged.is_cond_checked = self.is_cond_checked or other.is_cond_checked
        merged.sanitized_by = self.sanitized_by or other.sanitized_by
        merged.call_arg_positions = list(self.call_arg_positions) + list(other.call_arg_positions)
        return merged

    def to_dict(self):
        return {
            "is_local_var": self.is_local_var,
            "is_stack_spill": self.is_stack_spill,
            "is_global_var": self.is_global_var,
            "is_func_param": self.is_func_param,
            "is_func_retval": self.is_func_retval,
            "call_arg_positions": [c.to_dict() for c in self.call_arg_positions],
            "is_ptr": self.is_ptr,
            "points_to_tainted": self.points_to_tainted,
            "is_cond_checked": self.is_cond_checked,
            "sanitized_by": self.sanitized_by,
        }


@dataclass
class TaintedObject:
    key: str
    taint_id: str
    source_ea: int
    source_func: str
    mop_type: int
    size_bytes: int
    propagation_depth: int
    propagation_chain: list
    attrs: TaintedObjAttrs

    def clone(self):
        return TaintedObject(
            key=self.key,
            taint_id=self.taint_id,
            source_ea=self.source_ea,
            source_func=self.source_func,
            mop_type=self.mop_type,
            size_bytes=self.size_bytes,
            propagation_depth=self.propagation_depth,
            propagation_chain=list(self.propagation_chain),
            attrs=self.attrs,
        )

    def merge(self, other):
        merged_chain = self._merge_chain(self.propagation_chain, other.propagation_chain)
        return TaintedObject(
            key=self.key,
            taint_id=self.taint_id,
            source_ea=self.source_ea,
            source_func=self.source_func,
            mop_type=self.mop_type,
            size_bytes=max(self.size_bytes, other.size_bytes),
            propagation_depth=max(self.propagation_depth, other.propagation_depth),
            propagation_chain=merged_chain,
            attrs=self.attrs.merge(other.attrs),
        )

    def _merge_chain(self, a, b):
        seen = set()
        merged = []
        for step in list(a) + list(b):
            key = (step.insn_ea, step.mcode, step.from_key, step.to_key, step.block_serial, step.reason)
            if key in seen:
                continue
            seen.add(key)
            merged.append(step)
        return merged

    def to_dict(self):
        return {
            "key": self.key,
            "taint_id": self.taint_id,
            "source_ea": self.source_ea,
            "source_func": self.source_func,
            "mop_type": self.mop_type,
            "size_bytes": self.size_bytes,
            "propagation_depth": self.propagation_depth,
            "propagation_chain": [s.to_dict() for s in self.propagation_chain],
            "attrs": self.attrs.to_dict(),
        }


class TaintState:
    def __init__(self):
        self.tainted = {}
        self.alias = {}

    def clone(self):
        cloned = TaintState()
        cloned.tainted = {k: v.clone() for k, v in self.tainted.items()}
        cloned.alias = {k: set(v) if isinstance(v, set) else v for k, v in self.alias.items()}
        return cloned

    def equals(self, other):
        if set(self.tainted.keys()) != set(other.tainted.keys()):
            return False
        if set(self.alias.keys()) != set(other.alias.keys()):
            return False
        for key, val in self.tainted.items():
            other_val = other.tainted.get(key)
            if other_val is None:
                return False
            if val.propagation_depth != other_val.propagation_depth:
                return False
            if val.attrs.to_dict() != other_val.attrs.to_dict():
                return False
        for key, val in self.alias.items():
            other_val = other.alias.get(key)
            if val is UNKNOWN_ALIAS or other_val is UNKNOWN_ALIAS:
                if val is not other_val:
                    return False
                continue
            if set(val) != set(other_val):
                return False
        return True

    def merge(self, other):
        for key, other_obj in other.tainted.items():
            if key not in self.tainted:
                self.tainted[key] = other_obj.clone()
            else:
                self.tainted[key] = self.tainted[key].merge(other_obj)
        for key, other_alias in other.alias.items():
            if key not in self.alias:
                if other_alias is UNKNOWN_ALIAS:
                    self.alias[key] = UNKNOWN_ALIAS
                else:
                    self.alias[key] = set(other_alias)
            else:
                if self.alias[key] is UNKNOWN_ALIAS or other_alias is UNKNOWN_ALIAS:
                    self.alias[key] = UNKNOWN_ALIAS
                else:
                    self.alias[key].update(other_alias)

    def snapshot(self):
        return {
            "tainted": {k: v.to_dict() for k, v in self.tainted.items()},
            "alias": {
                k: "Unknown" if v is UNKNOWN_ALIAS else sorted(list(v))
                for k, v in self.alias.items()
            },
        }


class IntraTaintScanner:
    def __init__(self, ruleset, logger=None, include_pass_results=False, max_iterations_multiplier=3, debug=False):
        self.ruleset = ruleset
        self.logger = logger or ida_utils.Logger(verbose=False)
        self.include_pass_results = include_pass_results
        self.max_iterations_multiplier = max_iterations_multiplier
        self.debug = debug
        self._init_mcode_constants()
        self.matcher = RuleMatcher(self.logger)

    def scan_paths(self, paths, maturity=None):
        funcs = self._collect_functions_from_paths(paths)
        results = []
        for ea in funcs:
            report = self.scan_function(ea, maturity=maturity)
            if report:
                results.append(report)
        return results

    def scan_function(self, func_ea, maturity=None):
        if self.debug and self.logger:
             self.logger.log(f"DEBUG: Scanning function at {func_ea:x}")
        if ida_funcs is None or ida_hexrays is None:
            self.logger.log("IDA Hex-Rays environment not available", level="ERROR")
            return None
        func = ida_funcs.get_func(func_ea)
        if not func:
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: No function found at {func_ea:x}")
            return None
        if maturity is None:
            maturity = self._default_maturity()
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: Maturity level: {maturity}")
        mba = self._build_mba(func, maturity)
        if mba is None:
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: Failed to build microcode for {func_ea:x}")
            return None
        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: Analyzing function {func_name}")
        start_time = time.time()
        init_result, worklist, in_states, out_states, cfg_edges, lvar_meta, initial_taints = self._pass0_init(mba, func_name)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: Pass0 complete - {len(initial_taints)} initial taints, {len(cfg_edges)} CFG edges")
        converged_result, block_summaries = self._pass1_iterate(mba, func_name, worklist, in_states, out_states, cfg_edges)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: Pass1 complete - converged: {converged_result.get('converged')}, iterations: {converged_result.get('total_iterations')}")
        refined_db = self._pass2_refine(mba, func_name, converged_result, lvar_meta)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: Pass2 complete - {len(refined_db.get('tainted_objects', []))} refined objects")
        report = self._pass3_report(mba, func, func_name, maturity, converged_result, refined_db, block_summaries, start_time)
        if self.include_pass_results:
            report["pass_results"] = {
                "init_result": init_result,
                "converged_result": converged_result,
                "refined_taint_db": refined_db,
            }
        return report

    def _collect_functions_from_paths(self, paths):
        result = []
        seen = set()
        for path in paths or []:
            nodes = path.get("nodes") if isinstance(path, dict) else None
            if not nodes and hasattr(path, "paths"):
                nodes = []
                for p in path.paths:
                    nodes.extend(p.get("nodes", []))
            for node in nodes or []:
                ea_str = node.get("ea")
                if not ea_str:
                    continue
                try:
                    ea = int(ea_str, 16)
                except Exception:
                    continue
                if ea in seen:
                    continue
                seen.add(ea)
                result.append(ea)
        return result

    def _init_mcode_constants(self):
        self.mop_r = getattr(ida_hexrays, "mop_r", None)
        self.mop_S = getattr(ida_hexrays, "mop_S", None)
        self.mop_l = getattr(ida_hexrays, "mop_l", None)
        self.mop_v = getattr(ida_hexrays, "mop_v", None)
        self.mop_n = getattr(ida_hexrays, "mop_n", None)
        self.mop_d = getattr(ida_hexrays, "mop_d", None)
        self.mop_f = getattr(ida_hexrays, "mop_f", None)
        self.mop_a = getattr(ida_hexrays, "mop_a", None)
        self.mop_h = getattr(ida_hexrays, "mop_h", None)
        self.mop_z = getattr(ida_hexrays, "mop_z", None)
        self.m_mov = getattr(ida_hexrays, "m_mov", None)
        self.m_add = getattr(ida_hexrays, "m_add", None)
        self.m_sub = getattr(ida_hexrays, "m_sub", None)
        self.m_and = getattr(ida_hexrays, "m_and", None)
        self.m_or = getattr(ida_hexrays, "m_or", None)
        self.m_xor = getattr(ida_hexrays, "m_xor", None)
        self.m_mul = getattr(ida_hexrays, "m_mul", None)
        self.m_shl = getattr(ida_hexrays, "m_shl", None)
        self.m_shr = getattr(ida_hexrays, "m_shr", None)
        self.m_ldx = getattr(ida_hexrays, "m_ldx", None)
        self.m_stx = getattr(ida_hexrays, "m_stx", None)
        self.m_call = getattr(ida_hexrays, "m_call", None)
        self.m_icall = getattr(ida_hexrays, "m_icall", None)
        self.m_jnz = getattr(ida_hexrays, "m_jnz", None)
        self.m_jz = getattr(ida_hexrays, "m_jz", None)
        self.m_jg = getattr(ida_hexrays, "m_jg", None)
        self.m_jge = getattr(ida_hexrays, "m_jge", None)
        self.m_jl = getattr(ida_hexrays, "m_jl", None)
        self.m_jle = getattr(ida_hexrays, "m_jle", None)
        self.m_jtbl = getattr(ida_hexrays, "m_jtbl", None)

    def _default_maturity(self):
        if ida_hexrays is None:
            return None
        return getattr(ida_hexrays, "MMAT_LVARS", None)

    def _build_mba(self, func, maturity):
        try:
            failure = ida_hexrays.hexrays_failure_t()
        except Exception:
            failure = None
        try:
            return ida_hexrays.gen_microcode(func, failure, maturity, ida_hexrays.DECOMP_NO_WAIT)
        except Exception:
            pass
        try:
            return ida_hexrays.gen_microcode(func.start_ea, func.end_ea, failure, maturity, ida_hexrays.DECOMP_NO_WAIT)
        except Exception:
            pass
        try:
            cfunc = ida_hexrays.decompile(func)
            return getattr(cfunc, "mba", None)
        except Exception:
            return None

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
                    continue
        return None

    def _iter_block_links(self, block, attr_name):
        links = getattr(block, attr_name, None)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _iter_block_links - block head={getattr(block.head, 'ea', 0):x}, attr={attr_name}, links={type(links)}")
        if links is None:
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _iter_block_links - links is None")
            return []
        if callable(links):
            if attr_name == "succ":
                if hasattr(block, "nsucc"):
                    nsucc = block.nsucc() if callable(block.nsucc) else block.nsucc
                    try:
                        n = nsucc() if callable(nsucc) else int(nsucc)
                    except Exception:
                        n = 0
                    items = []
                    for i in range(n):
                        try:
                            items.append(block.succ(i))
                        except Exception:
                            continue
                    if self.debug and self.logger:
                        self.logger.log(f"DEBUG: _iter_block_links - nsucc={n}, items={items}")
                    return items
            elif attr_name == "pred":
                if hasattr(block, "npred"):
                    npred = block.npred() if callable(block.npred) else block.npred
                    try:
                        n = npred() if callable(npred) else int(npred)
                    except Exception:
                        n = 0
                    items = []
                    for i in range(n):
                        try:
                            items.append(block.pred(i))
                        except Exception:
                            continue
                    if self.debug and self.logger:
                        self.logger.log(f"DEBUG: _iter_block_links - npred={n}, items={items}")
                    return items
            try:
                links = links()
            except Exception as e:
                if self.debug and self.logger:
                    self.logger.log(f"DEBUG: _iter_block_links - callable failed: {e}")
                return []
        if links is None:
            return []
        try:
            return list(links)
        except Exception as e:
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _iter_block_links - list() failed: {e}")
            pass
        size = getattr(links, "size", None)
        at = getattr(links, "at", None)
        if at is None:
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _iter_block_links - at is None")
            return []
        try:
            count = size() if callable(size) else int(size)
        except Exception:
            count = 0
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _iter_block_links - count={count}")
        items = []
        for i in range(count):
            try:
                items.append(at(i))
            except Exception:
                continue
        return items

    def _pass0_init(self, mba, func_name):
        block_count = getattr(mba, "qty", 0)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _pass0_init - block_count={block_count}")
        in_states = {}
        out_states = {}
        cfg_edges = []
        pred_map = {}
        for i in range(block_count):
            block = mba.get_mblock(i)
            in_states[i] = TaintState()
            out_states[i] = TaintState()
            succs = list(self._iter_block_links(block, "succ"))
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _pass0_init - block {i}: head={getattr(block.head, 'ea', 0):x}, succs={succs}")
            for succ in succs:
                cfg_edges.append((i, int(succ)))
                if succ not in pred_map:
                    pred_map[succ] = []
                pred_map[succ].append(i)
                if self.debug and self.logger:
                    self.logger.log(f"DEBUG: _pass0_init - CFG edge: {i} -> {succ}")
        entry_serial = 0
        for i in range(block_count):
            block = mba.get_mblock(i)
            head_ea = getattr(block.head, 'ea', 0)
            if head_ea != 0:
                entry_serial = i
                if self.debug and self.logger:
                    self.logger.log(f"DEBUG: _pass0_init - found entry block: {i}, head={head_ea:x}")
                break
        lvar_meta = self._build_lvar_meta(mba)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _pass0_init - lvar_meta: {lvar_meta}")
        initial_taints = self._init_param_taints(mba, func_name)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _pass0_init - initial_taints count: {len(initial_taints)}")
        if initial_taints:
            in_states[entry_serial].tainted.update({t.key: t for t in initial_taints})
            out_states[entry_serial].tainted.update({t.key: t for t in initial_taints})
        worklist = [entry_serial]
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _pass0_init - entry_serial={entry_serial}, initial worklist={worklist}")
        init_result = {
            "block_count": block_count,
            "entry_serial": entry_serial,
            "In": {k: v.snapshot() for k, v in in_states.items()},
            "Out": {k: v.snapshot() for k, v in out_states.items()},
            "initial_taints": [t.to_dict() for t in initial_taints],
            "worklist": list(worklist),
            "cfg_edges": cfg_edges,
            "lvar_meta": lvar_meta,
        }
        return init_result, worklist, in_states, out_states, cfg_edges, lvar_meta, initial_taints

    def _build_lvar_meta(self, mba):
        meta = {}
        if not hasattr(mba, "vars"):
            return meta
        vars_obj = mba.vars
        if vars_obj is None:
            return meta
        
        try:
            var_count = len(vars_obj)
        except Exception:
            var_count = 0
        
        for i in range(var_count):
            try:
                lvar = vars_obj[i]
            except Exception:
                continue
            idx = i
            if idx is None:
                continue
            is_arg = self._is_lvar_arg(lvar)
            meta[idx] = {
                "name": getattr(lvar, "name", None),
                "type": str(getattr(lvar, "type", "")),
                "size": getattr(lvar, "width", None),
                "is_arg": is_arg,
            }
        return meta

    def _init_param_taints(self, mba, func_name):
        taints = []
        if not hasattr(mba, "vars"):
            return taints
        vars_obj = mba.vars
        if vars_obj is None:
            return taints
        
        try:
            var_count = len(vars_obj)
        except Exception:
            var_count = 0
        
        for i in range(var_count):
            try:
                lvar = vars_obj[i]
            except Exception:
                continue
            if not self._is_lvar_arg(lvar):
                continue
            idx = i
            key = f"lvar:{idx}"
            attrs = TaintedObjAttrs(
                is_local_var=True,
                is_func_param=True,
            )
            size = getattr(lvar, "width", 0)
            taints.append(
                TaintedObject(
                    key=key,
                    taint_id=str(uuid.uuid4()),
                    source_ea=getattr(mba, "entry_ea", 0),
                    source_func=func_name,
                    mop_type=self.mop_l,
                    size_bytes=size,
                    propagation_depth=0,
                    propagation_chain=[],
                    attrs=attrs,
                )
            )
        return taints

    def _pass1_iterate(self, mba, func_name, worklist, in_states, out_states, cfg_edges):
        all_findings = []
        all_tainted_objects = {}
        block_iterations = {i: 0 for i in range(getattr(mba, "qty", 0))}
        block_summaries = {}
        max_iterations = max(1, getattr(mba, "qty", 0) * self.max_iterations_multiplier)
        total_iterations = 0
        converged = True
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _pass1_iterate starting - max_iterations={max_iterations}")
            self.logger.log(f"DEBUG: mba.qty={mba.qty}, block_count={getattr(mba, 'qty', 0)}")
            for i in range(getattr(mba, "qty", 0)):
                block = mba.get_mblock(i)
                self.logger.log(f"DEBUG: Block {i}: head={getattr(block.head, 'ea', 0):x}, tail={getattr(block.tail, 'ea', 0):x}")
                insn = block.head
                while insn:
                    self.logger.log(f"DEBUG:   insn at {getattr(insn, 'ea', 0):x}, opcode={getattr(insn, 'opcode', None)}")
                    insn = insn.next
        while worklist:
            block_serial = worklist.pop(0)
            block = mba.get_mblock(block_serial)
            block_iterations[block_serial] += 1
            total_iterations += 1
            if total_iterations > max_iterations:
                converged = False
                if self.debug and self.logger:
                    self.logger.log(f"DEBUG: _pass1_iterate - exceeded max iterations, stopping")
                break
            in_state = TaintState()
            pred_links = list(self._iter_block_links(block, "pred"))
            valid_pred_found = False
            for pred in pred_links:
                pred_block = mba.get_mblock(int(pred))
                pred_head_ea = getattr(pred_block.head, 'ea', 0)
                if pred_head_ea == 0:
                    continue
                valid_pred_found = True
                in_state.merge(out_states[int(pred)])
            if not valid_pred_found and block_serial in out_states:
                in_state = out_states[block_serial].clone()
            out_state = in_state.clone()
            new_findings = []
            taint_gen = set()
            taint_kill = set()
            new_sources = set()
            insn = block.head
            while insn:
                out_state, insn_findings, gen_keys, kill_keys, source_eas = self._apply_transfer(
                    mba, block_serial, out_state, insn, func_name
                )
                for key in gen_keys:
                    taint_gen.add(key)
                for key in kill_keys:
                    taint_kill.add(key)
                for ea in source_eas:
                    new_sources.add(ea)
                if insn_findings:
                    new_findings.extend(insn_findings)
                insn = insn.next
            for key, obj in out_state.tainted.items():
                all_tainted_objects[key] = obj.clone()
            all_findings.extend(new_findings)
            state_changed = not out_state.equals(out_states[block_serial])
            in_states[block_serial] = in_state
            if state_changed:
                out_states[block_serial] = out_state
                for succ in self._iter_block_links(block, "succ"):
                    succ_idx = int(succ)
                    if succ_idx not in worklist:
                        worklist.append(succ_idx)
            block_summaries[block_serial] = {
                "block_serial": block_serial,
                "in_taint_keys": sorted(in_state.tainted.keys()),
                "out_taint_keys": sorted(out_state.tainted.keys()),
                "new_sources": sorted(list(new_sources)),
                "sink_hits": new_findings,
                "taint_gen": sorted(list(taint_gen)),
                "taint_kill": sorted(list(taint_kill)),
            }
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _pass1_iterate - block {block_serial}: gen={len(taint_gen)}, kill={len(taint_kill)}, findings={len(new_findings)}, changed={state_changed}")
        cfg_coverage = self._calc_cfg_taint_coverage(mba, out_states)
        converged_result = {
            "converged": converged,
            "total_iterations": total_iterations,
            "Out": {k: v.snapshot() for k, v in out_states.items()},
            "In_final": {k: v.snapshot() for k, v in in_states.items()},
            "all_tainted_objects": [v.to_dict() for v in all_tainted_objects.values()],
            "all_findings": self._dedupe_findings(all_findings),
            "cfg_taint_coverage": cfg_coverage,
        }
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _pass1_iterate complete - converged={converged}, total_iterations={total_iterations}, findings={len(all_findings)}")
        return converged_result, block_summaries

    def _apply_transfer(self, mba, block_serial, state, insn, func_name):
        opcode = getattr(insn, "opcode", None)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _apply_transfer - block={block_serial}, opcode={opcode}, ea={getattr(insn, 'ea', 0):x}")
            insn_text = self._safe_dstr(insn)
            self.logger.log(f"DEBUG: _apply_transfer - insn={insn_text}")
            if insn_text and "execl" in insn_text.lower():
                self.logger.log(f"DEBUG: _apply_transfer - execl_insn opcode={opcode} ea={getattr(insn, 'ea', 0):x} insn={insn_text}")
            if self.m_call is not None:
                self.logger.log(f"DEBUG: _apply_transfer - m_call value={self.m_call}")
            else:
                self.logger.log(f"DEBUG: _apply_transfer - m_call is None")
            if self.m_icall is not None:
                self.logger.log(f"DEBUG: _apply_transfer - m_icall value={self.m_icall}")
        findings = []
        gen_keys = set()
        kill_keys = set()
        new_sources = set()
        if opcode == self.m_mov:
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _apply_transfer - m_mov")
            l_key, l_obj = self._resolve_mop_taint(state, insn.l)
            d_key = self._mop_key(insn.d)
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _apply_transfer - l_key={l_key}, l_obj={'Yes' if l_obj else 'No'}, d_key={d_key}")
            if l_obj:
                self._taint_key(state, d_key, l_obj, insn, block_serial, "DATA_MOVE")
                gen_keys.add(d_key)
            else:
                if d_key and d_key in state.tainted:
                    self._untaint_key(state, d_key)
                    kill_keys.add(d_key)
            self._propagate_alias(state, insn.d, insn.l)
        elif opcode in (self.m_add, self.m_sub, self.m_and, self.m_or, self.m_xor, self.m_mul, self.m_shl, self.m_shr):
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _apply_transfer - arithmetic op")
            l_key, l_obj = self._resolve_mop_taint(state, insn.l)
            r_key, r_obj = self._resolve_mop_taint(state, insn.r)
            d_key = self._mop_key(insn.d)
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _apply_transfer - l_key={l_key}, r_key={r_key}, d_key={d_key}, l_obj={'Yes' if l_obj else 'No'}, r_obj={'Yes' if r_obj else 'No'}")
            if l_obj or r_obj:
                base_obj = l_obj or r_obj
                chain = []
                if l_obj:
                    chain.extend(l_obj.propagation_chain)
                if r_obj:
                    chain.extend(r_obj.propagation_chain)
                obj = self._build_taint_from(base_obj, d_key, insn, block_serial, "ARITHMETIC", chain)
                state.tainted[d_key] = obj
                gen_keys.add(d_key)
            else:
                if d_key and d_key in state.tainted:
                    self._untaint_key(state, d_key)
                    kill_keys.add(d_key)
            self._alias_arithmetic(state, insn.d, insn.l, insn.r)
        elif opcode == self.m_ldx:
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _apply_transfer - m_ldx")
            d_key = self._mop_key(insn.d)
            addr_key = self._resolve_addr_key(insn.l, insn.r)
            targets = state.alias.get(addr_key, UNKNOWN_ALIAS)
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _apply_transfer - d_key={d_key}, addr_key={addr_key}, targets={targets}")
            if targets is UNKNOWN_ALIAS:
                if d_key:
                    obj = self._build_new_taint(d_key, insn, block_serial, func_name, "ALIAS_MAY")
                    state.tainted[d_key] = obj
                    obj.attrs.is_ptr = self._is_pointer_sized(insn.d)
                    gen_keys.add(d_key)
            else:
                tainted_targets = [state.tainted.get(t) for t in targets if t in state.tainted]
                if self.debug and self.logger:
                    self.logger.log(f"DEBUG: _apply_transfer - tainted_targets count={len(tainted_targets)}")
                if tainted_targets:
                    src = max(tainted_targets, key=lambda o: o.propagation_depth)
                    obj = self._build_taint_from(src, d_key, insn, block_serial, "MEM_LOAD", src.propagation_chain)
                    obj.attrs.is_ptr = self._is_pointer_sized(insn.d)
                    state.tainted[d_key] = obj
                    gen_keys.add(d_key)
        elif opcode == self.m_stx:
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _apply_transfer - m_stx")
            addr_key = self._resolve_addr_key(insn.d, insn.l)
            targets = state.alias.get(addr_key, UNKNOWN_ALIAS)
            r_key, r_obj = self._resolve_mop_taint(state, insn.r)
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _apply_transfer - addr_key={addr_key}, targets={targets}, r_obj={'Yes' if r_obj else 'No'}")
            if r_obj:
                if targets is UNKNOWN_ALIAS:
                    targets = [addr_key]
                for target in targets:
                    obj = self._build_taint_from(r_obj, target, insn, block_serial, "MEM_STORE", r_obj.propagation_chain)
                    obj.attrs.is_stack_spill = self._mop_type(insn.d) == self.mop_S
                    state.tainted[target] = obj
                    gen_keys.add(target)
            else:
                if targets is not UNKNOWN_ALIAS and len(targets) == 1:
                    target = next(iter(targets))
                    if target in state.tainted:
                        self._untaint_key(state, target)
                        kill_keys.add(target)
        if opcode in (self.m_call, self.m_icall):
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _apply_transfer - m_call at {getattr(insn, 'ea', 0):x}")
            call_findings, gen_call, kill_call, call_sources = self._handle_call(state, insn, block_serial, func_name)
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _apply_transfer - m_call findings={len(call_findings)}, gen_call={sorted(gen_call) if gen_call else []}, kill_call={sorted(kill_call) if kill_call else []}, call_sources={sorted(call_sources) if call_sources else []}")
            findings.extend(call_findings)
            gen_keys.update(gen_call)
            kill_keys.update(kill_call)
            new_sources.update(call_sources)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _apply_transfer - complete: gen_keys={sorted(gen_keys)}, kill_keys={sorted(kill_keys)}")
        return state, findings, gen_keys, kill_keys, new_sources

    def _handle_call(self, state, insn, block_serial, func_name):
        findings = []
        gen_keys = set()
        kill_keys = set()
        new_sources = set()
        callee_mop, _, _ = self._select_call_operands(insn.l, insn.r, insn.d)
        callee_name, callee_ea = self._callee_info(callee_mop)
        if self.debug and self.logger:
             self.logger.log(f"DEBUG: _handle_call visiting {callee_name} at {getattr(insn, 'ea', 0):x}")
             self.logger.log(f"DEBUG: _handle_call callee_mop={self._safe_dstr(callee_mop)}")
        args = self._call_args(insn)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _handle_call - {len(args)} arguments")
        call_is_sink = self._matches_any(self.ruleset.sinks, callee_name, callee_ea)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _handle_call - callee={callee_name}, call_is_sink={call_is_sink}")
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _handle_call - {len(args)} arguments, args={[(self._mop_key(a), self._mop_type(a)) for a in args]}")
        for idx, arg in enumerate(args):
            key, obj = self._resolve_mop_taint(state, arg)
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _handle_call - arg[{idx}] key={key}, obj={'Yes' if obj else 'No'}")
            if obj:
                obj.attrs.call_arg_positions.append(
                    CallArgInfo(
                        call_ea=getattr(insn, "ea", 0),
                        callee=callee_name or "",
                        arg_index=idx,
                        is_sink=call_is_sink,
                        arg_size=self._mop_size(arg),
                    )
                )
                if call_is_sink:
                    findings.append(
                        {
                            "source_ea": obj.source_ea,
                            "source_func": obj.source_func,
                            "sink_ea": getattr(insn, "ea", 0),
                            "sink_func": callee_name,
                            "sink_arg_index": idx,
                            "taint_key": key,
                            "propagation_chain": [s.to_dict() for s in obj.propagation_chain],
                        }
                    )
        for rule in self.ruleset.sources:
            if not self._rule_matches(rule, callee_name, callee_ea):
                continue
            if self.logger:
                 self.logger.log(f"DEBUG: Matched source rule {rule.get('name')} for {callee_name}")
            
            arg_indexes = rule.get("args") or []
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _handle_call - source rule={rule}, arg_indexes={arg_indexes}, args_count={len(args)}, insn.d={insn.d}")
                self.logger.log(f"DEBUG: _handle_call - args details: {[(self._mop_key(a), self._mop_type(a)) for a in args]}")
            if arg_indexes:
                for idx in arg_indexes:
                    if idx < 0 or idx >= len(args):
                        if self.logger:
                            self.logger.log(f"DEBUG: _handle_call - arg index {idx} out of range")
                        continue
                    arg = args[idx]
                    if self._mop_type(arg) == self.mop_a:
                        arg = getattr(arg, "a", None) or arg
                    key = self._mop_key(arg)
                    if self.logger:
                        self.logger.log(f"DEBUG: _handle_call - source arg[{idx}] key={key}, mop_type={self._mop_type(arg)}")
                    if key:
                        obj = self._build_new_taint(key, insn, block_serial, callee_name or func_name, "CALL_RET_OUT")
                        obj.attrs.is_func_param = True
                        obj.attrs.is_ptr = self._is_pointer_sized(arg)
                        state.tainted[key] = obj
                        gen_keys.add(key)
                        if self.logger:
                            self.logger.log(f"DEBUG: _handle_call - marked source arg[{idx}] key={key}")
            if rule.get("ret") and insn.d:
                out_key = self._mop_key(insn.d)
                if out_key:
                    obj = self._build_new_taint(out_key, insn, block_serial, callee_name or func_name, "CALL_RET_OUT")
                    obj.attrs.is_func_retval = True
                    obj.attrs.is_ptr = self._is_pointer_sized(insn.d)
                    state.tainted[out_key] = obj
                    gen_keys.add(out_key)
                    if self.logger:
                        self.logger.log(f"DEBUG: _handle_call - marked source retval key={out_key}")
            new_sources.add(getattr(insn, "ea", 0))
        for rule in self.ruleset.propagators:
            if not self._rule_matches(rule, callee_name, callee_ea):
                continue
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _handle_call - matched propagator rule: {rule.get('name')}")
            src_indexes = rule.get("from_args") or []
            dst_indexes = rule.get("to_args")
            if dst_indexes is None:
                dst_indexes = []
            for src_idx in src_indexes:
                if src_idx < 0 or src_idx >= len(args):
                    continue
                src_key, src_obj = self._resolve_mop_taint(state, args[src_idx])
                if not src_obj:
                    continue
                if rule.get("ret") and insn.d:
                    dst_key = self._mop_key(insn.d)
                    obj = self._build_taint_from(src_obj, dst_key, insn, block_serial, "CALL_ARG_IN", src_obj.propagation_chain)
                    obj.attrs.is_func_retval = True
                    state.tainted[dst_key] = obj
                    gen_keys.add(dst_key)
                for dst_idx in dst_indexes:
                    if dst_idx < 0 or dst_idx >= len(args):
                        continue
                    dst_key = self._mop_key(args[dst_idx])
                    obj = self._build_taint_from(src_obj, dst_key, insn, block_serial, "CALL_ARG_IN", src_obj.propagation_chain)
                    state.tainted[dst_key] = obj
                    gen_keys.add(dst_key)
        for rule in getattr(self.ruleset, "sanitizers", []) or []:
            if not self._rule_matches(rule, callee_name, callee_ea):
                continue
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _handle_call - matched sanitizer rule: {rule.get('name')}")
            if insn.d:
                d_key = self._mop_key(insn.d)
                if d_key and d_key in state.tainted:
                    self._untaint_key(state, d_key)
                    kill_keys.add(d_key)
            for arg in args:
                key, obj = self._resolve_mop_taint(state, arg)
                if obj:
                    obj.attrs.sanitized_by = callee_name
        if not self._callee_is_known(callee_name, callee_ea):
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _handle_call - unknown callee, applying default arg in")
            if any(self._resolve_mop_taint(state, a)[1] for a in args):
                if insn.d:
                    d_key = self._mop_key(insn.d)
                    if d_key:
                        base_obj = self._resolve_mop_taint(state, args[0])[1]
                        obj = self._build_taint_from(base_obj, d_key, insn, block_serial, "CALL_ARG_IN", base_obj.propagation_chain if base_obj else [])
                        state.tainted[d_key] = obj
                        gen_keys.add(d_key)
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _handle_call complete - gen_keys={sorted(gen_keys)}, kill_keys={sorted(kill_keys)}, findings={len(findings)}")
        return findings, gen_keys, kill_keys, new_sources

    def _pass2_refine(self, mba, func_name, converged_result, lvar_meta):
        tainted_objects = {t["key"]: self._dict_to_taint(t) for t in converged_result.get("all_tainted_objects", [])}
        self._mark_param_taints(tainted_objects, lvar_meta)
        self._mark_cond_checks(mba, tainted_objects)
        self._mark_global_taints(tainted_objects)
        self._mark_points_to_tainted(converged_result, tainted_objects)
        refined = list(tainted_objects.values())
        return {
            "tainted_objects": [t.to_dict() for t in refined],
            "param_taints": [t.to_dict() for t in refined if t.attrs.is_func_param],
            "global_taints": [t.to_dict() for t in refined if t.attrs.is_global_var],
            "ptr_taints": [t.to_dict() for t in refined if t.attrs.is_ptr],
            "sink_arg_taints": [
                t.to_dict()
                for t in refined
                if any(info.is_sink for info in t.attrs.call_arg_positions)
            ],
        }

    def _pass3_report(self, mba, func, func_name, maturity, converged_result, refined_db, block_summaries, start_time):
        refined_map = {t["key"]: t for t in refined_db.get("tainted_objects", [])}
        findings = []
        for finding in converged_result.get("all_findings", []):
            key = finding.get("taint_key")
            taint_obj = refined_map.get(key)
            if not taint_obj:
                continue
            severity = self._evaluate_severity(taint_obj)
            chain = taint_obj.get("propagation_chain", [])
            findings.append(
                {
                    "finding_id": str(uuid.uuid4()),
                    "severity": severity,
                    "source_ea": finding.get("source_ea"),
                    "source_func": finding.get("source_func"),
                    "sink_ea": finding.get("sink_ea"),
                    "sink_func": finding.get("sink_func"),
                    "sink_arg_index": finding.get("sink_arg_index"),
                    "taint_object": taint_obj,
                    "propagation_chain": chain,
                    "chain_length": len(chain),
                    "intermediate_funcs": self._extract_intermediate_funcs(taint_obj),
                    "is_cond_checked": taint_obj.get("attrs", {}).get("is_cond_checked", False),
                    "sanitized_by": taint_obj.get("attrs", {}).get("sanitized_by"),
                }
            )
        findings.sort(key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f["severity"], 3))
        stats = self._build_stats(mba=mba, converged_result=converged_result, findings=findings)
        report = {
            "func_ea": func.start_ea,
            "func_name": func_name,
            "analysis_time_ms": int((time.time() - start_time) * 1000),
            "maturity": maturity,
            "converged": converged_result.get("converged", True),
            "findings": findings,
            "tainted_objects": refined_db.get("tainted_objects", []),
            "block_summaries": block_summaries,
            "stats": stats,
        }
        return report

    def _dict_to_taint(self, data):
        attrs = data.get("attrs", {})
        call_args = [CallArgInfo(**c) for c in attrs.get("call_arg_positions", [])]
        obj_attrs = TaintedObjAttrs(
            is_local_var=attrs.get("is_local_var", False),
            is_stack_spill=attrs.get("is_stack_spill", False),
            is_global_var=attrs.get("is_global_var", False),
            is_func_param=attrs.get("is_func_param", False),
            is_func_retval=attrs.get("is_func_retval", False),
            call_arg_positions=call_args,
            is_ptr=attrs.get("is_ptr", False),
            points_to_tainted=attrs.get("points_to_tainted", False),
            is_cond_checked=attrs.get("is_cond_checked", False),
            sanitized_by=attrs.get("sanitized_by"),
        )
        chain = [StepRecord(**s) for s in data.get("propagation_chain", [])]
        return TaintedObject(
            key=data.get("key"),
            taint_id=data.get("taint_id"),
            source_ea=data.get("source_ea"),
            source_func=data.get("source_func"),
            mop_type=data.get("mop_type"),
            size_bytes=data.get("size_bytes"),
            propagation_depth=data.get("propagation_depth"),
            propagation_chain=chain,
            attrs=obj_attrs,
        )

    def _build_stats(self, mba, converged_result, findings):
        total_insns = 0
        tainted_insns = 0
        for i in range(getattr(mba, "qty", 0)):
            block = mba.get_mblock(i)
            insn = block.head
            while insn:
                total_insns += 1
                if self._insn_taints(converged_result, insn):
                    tainted_insns += 1
                insn = insn.next
        highs = sum(1 for f in findings if f["severity"] == "HIGH")
        meds = sum(1 for f in findings if f["severity"] == "MEDIUM")
        lows = sum(1 for f in findings if f["severity"] == "LOW")
        return {
            "total_insns": total_insns,
            "tainted_insns": tainted_insns,
            "total_tainted_objects": len(converged_result.get("all_tainted_objects", [])),
            "live_tainted_objects": len(converged_result.get("Out", {}).get(getattr(mba, "qty", 1) - 1, {}).get("tainted", {})),
            "findings_high": highs,
            "findings_medium": meds,
            "findings_low": lows,
            "alias_unknown_count": self._alias_unknown_count(converged_result),
            "worklist_iterations": converged_result.get("total_iterations", 0),
        }

    def _insn_taints(self, converged_result, insn):
        for entry in converged_result.get("all_tainted_objects", []):
            if any(s.get("insn_ea") == getattr(insn, "ea", None) for s in entry.get("propagation_chain", [])):
                return True
        return False

    def _alias_unknown_count(self, converged_result):
        count = 0
        for state in converged_result.get("Out", {}).values():
            for val in state.get("alias", {}).values():
                if val == "Unknown":
                    count += 1
        return count

    def _calc_cfg_taint_coverage(self, mba, out_states):
        total = 0
        tainted = 0
        for i in range(getattr(mba, "qty", 0)):
            block = mba.get_mblock(i)
            insn = block.head
            while insn:
                total += 1
                if out_states[i].tainted:
                    tainted += 1
                insn = insn.next
        return float(tainted) / float(total) if total else 0.0

    def _dedupe_findings(self, findings):
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("sink_ea"), f.get("sink_arg_index"), f.get("taint_key"), f.get("source_ea"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)
        return unique

    def _evaluate_severity(self, taint_obj):
        attrs = taint_obj.get("attrs", {})
        if attrs.get("sanitized_by"):
            return "LOW"
        if attrs.get("is_cond_checked"):
            return "MEDIUM"
        return "HIGH"

    def _extract_intermediate_funcs(self, taint_obj):
        names = []
        for info in taint_obj.get("attrs", {}).get("call_arg_positions", []):
            callee = info.get("callee")
            if callee and callee not in names:
                names.append(callee)
        return names

    def _mark_param_taints(self, tainted_objects, lvar_meta):
        for key, obj in tainted_objects.items():
            if key.startswith("lvar:"):
                try:
                    idx = int(key.split(":")[1])
                except Exception:
                    continue
                if lvar_meta.get(idx, {}).get("is_arg"):
                    obj.attrs.is_func_param = True

    def _mark_cond_checks(self, mba, tainted_objects):
        cond_ops = {self.m_jnz, self.m_jz, self.m_jg, self.m_jge, self.m_jl, self.m_jle, self.m_jtbl}
        for i in range(getattr(mba, "qty", 0)):
            block = mba.get_mblock(i)
            insn = block.head
            while insn:
                if getattr(insn, "opcode", None) in cond_ops:
                    for mop in [getattr(insn, "l", None), getattr(insn, "r", None), getattr(insn, "d", None)]:
                        key = self._mop_key(mop)
                        obj = tainted_objects.get(key)
                        if obj:
                            obj.attrs.is_cond_checked = True
                insn = insn.next

    def _mark_global_taints(self, tainted_objects):
        for key, obj in tainted_objects.items():
            if not key or not key.startswith("global:"):
                continue
            try:
                ea = int(key.split(":")[1], 16)
            except Exception:
                continue
            if self._is_global_ea(ea):
                obj.attrs.is_global_var = True

    def _mark_points_to_tainted(self, converged_result, tainted_objects):
        alias_union = {}
        for state in converged_result.get("Out", {}).values():
            for key, val in state.get("alias", {}).items():
                if val == "Unknown":
                    alias_union[key] = UNKNOWN_ALIAS
                elif key not in alias_union:
                    alias_union[key] = set(val)
                else:
                    if alias_union[key] is UNKNOWN_ALIAS:
                        continue
                    alias_union[key].update(val)
        for key, obj in tainted_objects.items():
            if not obj.attrs.is_ptr:
                continue
            targets = alias_union.get(key)
            if targets is UNKNOWN_ALIAS:
                obj.attrs.points_to_tainted = True
                continue
            if targets:
                if any(t in tainted_objects for t in targets):
                    obj.attrs.points_to_tainted = True

    def _callee_info(self, mop):
        if mop is None:
            return None, None
        ea = None
        mop_t = self._mop_type(mop)
        if mop_t == self.mop_v:
            ea = self._mop_addr(mop)
        elif mop_t == self.mop_h:
            helper = getattr(mop, "helper", None)
            if helper:
                ea = self._resolve_name_ea(helper)
                return helper, ea
        elif mop_t == self.mop_d:
            inner = getattr(mop, "d", None)
            if inner is not None:
                inner_ea = getattr(inner, "ea", None)
                if inner_ea is not None:
                    ea = inner_ea
        if ea is None and hasattr(mop, "g"):
            ea = getattr(mop, "g", None)
        name = None
        if ea is not None and ida_funcs:
            name = ida_funcs.get_func_name(ea) or idc.get_name(ea) if idc else None
        if name:
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _callee_info - resolved name={name} at ea={ea:x}")
            return name, ea
        if hasattr(mop, "d"):
            d = getattr(mop, "d", None)
            if d is not None and hasattr(d, "g"):
                indirect_ea = getattr(d, "g", None)
                if indirect_ea is not None and ida_funcs:
                    indirect_name = ida_funcs.get_func_name(indirect_ea) or idc.get_name(indirect_ea) if idc else None
                    if indirect_name:
                        if self.debug and self.logger:
                            self.logger.log(f"DEBUG: _callee_info - resolved indirect name={indirect_name} at ea={indirect_ea:x}")
                        return indirect_name, indirect_ea
        return None, ea

    def _is_arg_list(self, mop):
        if ida_hexrays is None:
            return False
        return mop is not None and getattr(mop, "t", None) == self.mop_f

    def _is_none_mop(self, mop):
        if ida_hexrays is None:
            return mop is None
        return mop is None or getattr(mop, "t", None) == self.mop_z

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
        if callable(obj):
            try:
                obj = obj()
            except Exception:
                return []
        try:
            return list(obj)
        except Exception:
            pass
        if hasattr(obj, "args"):
            args = getattr(obj, "args")
            if callable(args):
                try:
                    return list(args())
                except Exception:
                    return []
            try:
                return list(args)
            except Exception:
                pass
        if hasattr(obj, "f"):
            f = getattr(obj, "f", None)
            if callable(f):
                try:
                    f = f()
                except Exception:
                    f = None
            if f is not None:
                if hasattr(f, "args"):
                    try:
                        return list(f.args)
                    except Exception:
                        pass
                try:
                    return list(f)
                except Exception:
                    pass
        return []

    def _normalize_call_arg(self, arg):
        if arg is None:
            return None
        if hasattr(arg, "mop"):
            return arg.mop
        if hasattr(arg, "arg"):
            return arg.arg
        return arg

    def _call_args(self, insn_or_mop):
        if insn_or_mop is None:
            return []
        if hasattr(insn_or_mop, "l") or hasattr(insn_or_mop, "opcode"):
            insn = insn_or_mop
            l = getattr(insn, "l", None)
            r = getattr(insn, "r", None)
            d = getattr(insn, "d", None)
            _, arg_list_mop, _ = self._select_call_operands(l, r, d)
            args = []
            if hasattr(insn, "args") and getattr(insn, "args", None):
                for arg in self._iter_call_args(insn.args):
                    mop = self._normalize_call_arg(arg)
                    if mop is not None:
                        args.append(mop)
            if arg_list_mop:
                for arg in self._iter_call_args(arg_list_mop):
                    mop = self._normalize_call_arg(arg)
                    if mop is not None and mop not in args:
                        args.append(mop)
            return args
        args = []
        for arg in self._iter_call_args(insn_or_mop):
            mop = self._normalize_call_arg(arg)
            if mop is not None:
                args.append(mop)
        return args

    def _mop_key(self, mop):
        if mop is None:
            return None
        mop_t = self._mop_type(mop)
        if mop_t == self.mop_r:
            return f"reg:{getattr(mop, 'r', None)}"
        if mop_t == self.mop_S:
            off = self._stack_offset(mop)
            return f"stack:{off}"
        if mop_t == self.mop_l:
            idx = self._lvar_idx(mop)
            return f"lvar:{idx}"
        if mop_t == self.mop_v:
            ea = self._mop_addr(mop)
            return f"global:{hex(ea) if ea is not None else '0x0'}"
        if mop_t == self.mop_a:
            inner_key = self._mop_key(getattr(mop, "a", None))
            return f"addr:{inner_key}" if inner_key else "addr:unknown"
        if mop_t == self.mop_n:
            return None
        if mop_t == self.mop_d:
            insn = getattr(mop, "d", None)
            if insn is None:
                return None
            opcode = getattr(insn, "opcode", None)
            if opcode in (self.m_add, self.m_sub):
                l_key = self._mop_key(getattr(insn, "l", None))
                r_key = self._mop_key(getattr(insn, "r", None))
                def is_var(key):
                    return key and (key.startswith("lvar:") or key.startswith("reg:") or key.startswith("stack:") or key.startswith("global:") or key.startswith("addr:"))
                if is_var(l_key):
                    return l_key
                if is_var(r_key):
                    return r_key
            return self._mop_key(getattr(insn, "l", None)) or self._mop_key(getattr(insn, "r", None))
        return None

    def _mop_type(self, mop):
        return getattr(mop, "t", None)

    def _mop_addr(self, mop):
        return getattr(mop, "g", None) or getattr(mop, "a", None)

    def _stack_offset(self, mop):
        if hasattr(mop, "s"):
            s = getattr(mop, "s")
            if hasattr(s, "off"):
                return s.off
        return getattr(mop, "off", None)

    def _lvar_idx(self, mop):
        if hasattr(mop, "l"):
            l = getattr(mop, "l")
            if hasattr(l, "idx"):
                return l.idx
        return getattr(mop, "idx", None)

    def _mop_size(self, mop):
        return getattr(mop, "size", 0) or getattr(mop, "width", 0)

    def _is_lvar_arg(self, lvar):
        if hasattr(lvar, "is_arg_var"):
            try:
                flag = lvar.is_arg_var
                if callable(flag):
                    flag = flag()
                if bool(flag):
                    return True
            except Exception:
                pass
        if hasattr(lvar, "is_stk_var"):
            try:
                flag = lvar.is_stk_var
                if callable(flag):
                    flag = flag()
                flag = bool(flag)
            except Exception:
                flag = False
            if not flag:
                return False
            try:
                loc = lvar.location
                if hasattr(loc, "stkoff"):
                    stkoff = loc.stkoff() if callable(loc.stkoff) else loc.stkoff
                    if stkoff > 0:
                        return True
            except Exception:
                return False
        return False

    def _resolve_mop_taint(self, state, mop):
        if mop is None:
            return None, None
        print(f"DEBUG: _resolve_mop_taint - mop_type={self._mop_type(mop)}, key={self._mop_key(mop)}, state.tainted.keys={list(state.tainted.keys())}")
        if self._mop_type(mop) == self.mop_a:
            inner = getattr(mop, "a", None)
            inner_key, inner_obj = self._resolve_mop_taint(state, inner)
            if inner_obj:
                return inner_key, inner_obj
        if self._mop_type(mop) == self.mop_d:
            return self._resolve_insn_taint(state, mop.d)
        key = self._mop_key(mop)
        if key and key in state.tainted:
            print(f"DEBUG: _resolve_mop_taint - FOUND key={key}")
            return key, state.tainted[key]
        print(f"DEBUG: _resolve_mop_taint - NOT FOUND key={key}")
        return key, None

    def _resolve_insn_taint(self, state, insn):
        if insn is None:
            return None, None
        op = getattr(insn, "opcode", None)
        if op == self.m_mov:
            return self._resolve_mop_taint(state, insn.l)
        if op in (self.m_add, self.m_sub, self.m_and, self.m_or, self.m_xor, self.m_mul, self.m_shl, self.m_shr):
            l_key, l_obj = self._resolve_mop_taint(state, insn.l)
            r_key, r_obj = self._resolve_mop_taint(state, insn.r)
            return l_key or r_key, l_obj or r_obj
        if op == self.m_call:
            r_key, r_obj = self._resolve_mop_taint(state, insn.r)
            d_key, d_obj = self._resolve_mop_taint(state, insn.d)
            return r_key or d_key, r_obj or d_obj
        return None, None

    def _resolve_addr_key(self, base_mop, off_mop):
        base_key = self._mop_key(base_mop)
        if base_key is None:
            return None
        if off_mop and self._mop_type(off_mop) == self.mop_n:
            return base_key
        return base_key

    def _propagate_alias(self, state, d, l):
        d_key = self._mop_key(d)
        l_key = self._mop_key(l)
        if not d_key or not l_key:
            return
        if l_key in state.alias:
            state.alias[d_key] = set(state.alias[l_key]) if state.alias[l_key] is not UNKNOWN_ALIAS else UNKNOWN_ALIAS
        else:
            state.alias[d_key] = UNKNOWN_ALIAS

    def _alias_arithmetic(self, state, d, l, r):
        d_key = self._mop_key(d)
        l_key = self._mop_key(l)
        if not d_key or not l_key:
            return
        if self._is_pointer_sized(l) and self._mop_type(r) == self.mop_n:
            if l_key in state.alias and state.alias[l_key] is not UNKNOWN_ALIAS:
                state.alias[d_key] = set(state.alias[l_key])
            else:
                state.alias[d_key] = UNKNOWN_ALIAS
        else:
            state.alias[d_key] = UNKNOWN_ALIAS

    def _taint_key(self, state, key, src_obj, insn, block_serial, reason):
        if not key or not src_obj:
            return
        if self.debug and self.logger:
            self.logger.log(f"DEBUG: _taint_key - key={key}, reason={reason}, src_key={src_obj.key}")
        obj = self._build_taint_from(src_obj, key, insn, block_serial, reason, src_obj.propagation_chain)
        state.tainted[key] = obj

    def _untaint_key(self, state, key):
        if key in state.tainted:
            if self.debug and self.logger:
                self.logger.log(f"DEBUG: _untaint_key - key={key}")
            del state.tainted[key]

    def _build_new_taint(self, key, insn, block_serial, source_func, reason):
        return TaintedObject(
            key=key,
            taint_id=str(uuid.uuid4()),
            source_ea=getattr(insn, "ea", 0),
            source_func=source_func,
            mop_type=self._mop_type(getattr(insn, "d", None)),
            size_bytes=self._mop_size(getattr(insn, "d", None)),
            propagation_depth=1,
            propagation_chain=[
                StepRecord(
                    insn_ea=getattr(insn, "ea", 0),
                    mcode=getattr(insn, "opcode", 0),
                    from_key=key,
                    to_key=key,
                    block_serial=block_serial,
                    reason=reason,
                )
            ],
            attrs=TaintedObjAttrs(),
        )

    def _build_taint_from(self, src_obj, dst_key, insn, block_serial, reason, chain):
        if src_obj is None:
            return self._build_new_taint(dst_key, insn, block_serial, "", reason)
        new_chain = list(chain)
        new_chain.append(
            StepRecord(
                insn_ea=getattr(insn, "ea", 0),
                mcode=getattr(insn, "opcode", 0),
                from_key=src_obj.key,
                to_key=dst_key,
                block_serial=block_serial,
                reason=reason,
            )
        )
        obj = TaintedObject(
            key=dst_key,
            taint_id=src_obj.taint_id,
            source_ea=src_obj.source_ea,
            source_func=src_obj.source_func,
            mop_type=src_obj.mop_type,
            size_bytes=src_obj.size_bytes,
            propagation_depth=src_obj.propagation_depth + 1,
            propagation_chain=new_chain,
            attrs=src_obj.attrs,
        )
        if self._is_pointer_sized(getattr(insn, "d", None)):
            obj.attrs.is_ptr = True
        return obj

    def _source_out_keys(self, rule, d, args):
        out = []
        arg_indexes = rule.get("args") or []
        for idx in arg_indexes:
            if idx < 0 or idx >= len(args):
                continue
            arg = args[idx]
            if self._mop_type(arg) == self.mop_a:
                arg = getattr(arg, "a", None) or arg
            key = self._mop_key(arg)
            if key:
                out.append((key, arg))
        if rule.get("ret") and d is not None:
            key = self._mop_key(d)
            if key:
                out.append((key, d))
        return out

    def _matches_any(self, rules, callee_name, callee_ea):
        for rule in rules or []:
            if self._rule_matches(rule, callee_name, callee_ea):
                return True
        return False

    def _rule_matches(self, rule, callee_name, callee_ea):
        if rule.get("ea") is not None and callee_ea is not None:
            return rule.get("ea") == callee_ea
        name = rule.get("name")
        if name:
            callee_norm = self.matcher.normalize_name(callee_name)
            if callee_norm is None and callee_ea is not None:
                ida_name = None
                if ida_funcs:
                    ida_name = ida_funcs.get_func_name(callee_ea)
                if not ida_name and idc:
                    try:
                        ida_name = idc.get_name(callee_ea)
                    except Exception:
                        ida_name = None
                callee_norm = self.matcher.normalize_name(ida_name)
            if callee_norm and self.matcher.normalize_name(name) == callee_norm:
                return True
        regex = rule.get("regex")
        if regex and callee_name:
            try:
                return bool(regex.search(callee_name))
            except Exception:
                return False
        return False

    def _callee_is_known(self, callee_name, callee_ea):
        if callee_name:
            return True
        if callee_ea is not None and callee_ea != 0:
            return True
        return False

    def _is_pointer_sized(self, mop):
        size = self._mop_size(mop)
        ptr_size = 8
        if ida_idaapi and hasattr(ida_idaapi, "get_inf_structure"):
            inf = ida_idaapi.get_inf_structure()
            if inf.is_64bit():
                ptr_size = 8
            else:
                ptr_size = 4
        return size == ptr_size

    def _is_global_ea(self, ea):
        if ida_segment is None or ea is None:
            return False
        seg = ida_segment.getseg(ea)
        if not seg:
            return False
        name = ida_segment.get_segm_name(seg) if ida_segment else None
        if not name and ida_nalt:
            name = ida_nalt.get_segm_name(ea)
        return name in (".data", ".bss")

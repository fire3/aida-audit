from .constants import (
    ida_hexrays,
    idc,
    ida_funcs,
    idautils,
    ida_idaapi,
    BADADDR,
)
from .common import MicroCodeUtils


_mop_visitor_base = ida_hexrays.mop_visitor_t if ida_hexrays else object


class MopUsageVisitor(_mop_visitor_base):
    def __init__(self, analyzer, reads, writes, calls):
        if ida_hexrays:
            ida_hexrays.mop_visitor_t.__init__(self)
        self.analyzer = analyzer
        self.utils = analyzer.utils
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
                if inner is not None and self.utils.is_call_opcode(inner.opcode):
                    key = id(inner)
                    if key not in self.seen_calls:
                        self.seen_calls.add(key)
                        self.analyzer._record_call(inner, self.calls)

            if t in (ida_hexrays.mop_c, ida_hexrays.mop_sc, ida_hexrays.mop_f, ida_hexrays.mop_d):
                return 0

            access_mode = None
            if t == ida_hexrays.mop_a:
                access_mode = "addr"

            op = self.utils.mop_entry(mop)
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
        self.utils = MicroCodeUtils()

    def analyze_instruction(self, insn):
        reads, writes, calls = self._analyze_minsn(insn)
        opname = self.utils.get_opcode_name(insn.opcode)
        return {
            "text": self.utils.safe_dstr(insn),
            "opcode": opname,
            "reads": reads,
            "writes": writes,
            "calls": calls,
        }

    def _analyze_minsn(self, insn):
        reads = []
        writes = []
        calls = []

        if self.utils.is_call_opcode(insn.opcode):
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

        opname = self.utils.get_opcode_name(insn.opcode)
        if opname == "mov" and getattr(insn, "d", None):
            for call in calls:
                if call["ret"] is None:
                    call["ret"] = self.utils.mop_entry(insn.d)

        return reads, writes, calls

    def _record_call(self, insn, calls):
        opname = self.utils.get_opcode_name(insn.opcode)
        l = getattr(insn, "l", None)
        r = getattr(insn, "r", None)
        d = getattr(insn, "d", None)

        callee_mop, arg_list_mop, ret_mop = self.utils.select_call_operands(l, r, d)

        callee = None
        if not self.utils.is_none_mop(callee_mop):
            callee = self.utils.mop_entry(callee_mop)

        args = []
        arg_sources = []
        if hasattr(insn, "args") and insn.args:
            arg_sources.append(insn.args)
        if arg_list_mop:
            arg_sources.append(arg_list_mop)
        for src in arg_sources:
            for arg in self.utils.iter_call_args(src):
                norm = self.utils.normalize_call_arg(arg)
                if norm is not None:
                    args.append(norm)

        ret = self.utils.mop_entry(ret_mop) if not self.utils.is_none_mop(ret_mop) else None

        callee, callee_name = self.utils.ensure_callee_ea(insn, callee)

        calls.append(
            {
                "kind": opname,
                "callee_name": callee_name,
                "target": callee,
                "args": args,
                "ret": ret,
            }
        )


def analyze_function(pfn, maturity):
    hf = ida_hexrays.hexrays_failure_t()
    mbr = ida_hexrays.mba_ranges_t(pfn)
    mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_WARNINGS, maturity)

    if not mba:
        return None

    analyzer = MicrocodeAnalyzer(mba)
    func_name = ida_funcs.get_func_name(pfn.start_ea)

    func_args = []
    return_vars = []
    if mba.vars:
        try:
            for i, v in enumerate(mba.vars):
                if v.is_arg_var:
                    func_args.append({
                        "lvar_idx": i,
                        "name": v.name,
                        "width": v.width
                    })
                is_result = False
                if hasattr(v, "is_result_var") and v.is_result_var:
                    is_result = True
                elif v.name and (v.name == "result" or v.name.startswith("retvar")):
                    is_result = True

                if is_result:
                    return_vars.append(i)

        except Exception:
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

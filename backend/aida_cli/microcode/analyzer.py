from .constants import (
    ida_hexrays,
    idc,
    ida_funcs,
    idautils,
    ida_nalt,
    ida_ida,
    ida_idaapi,
    ida_typeinf,
    BADADDR,
)
from .common import (
    OperandAttr,
    RegisterAttr,
    LocalVarAttr,
    StackAttr,
    GlobalAttr,
    ImmediateAttr,
    StringAttr,
    AddressAttr,
    LoadAttr,
    StoreAttr,
    ExpressionAttr,
    OperandInfo,
    CallInfo,
    InsnInfo,
    ArgInfo,
    BlockInfo,
    FuncInfo,
)
from .utils import MicroCodeUtils
from dataclasses import dataclass, field
from typing import Optional, Dict, List
import sys
import re


_mop_visitor_base = ida_hexrays.mop_visitor_t if ida_hexrays else object


class MopUsageVisitor(_mop_visitor_base):
    """遍历 mop 使用情况，输出读/写/调用列表条目。"""
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

    def _visit_inner_operands(self, insn):
        l = getattr(insn, "l", None)
        r = getattr(insn, "r", None)
        d = getattr(insn, "d", None)
        if l is not None:
            self.visit_mop(l, None, False)
        if r is not None:
            self.visit_mop(r, None, False)
        if l is None and r is None and d is not None:
            self.visit_mop(d, None, False)

    def visit_mop(self, mop, type_id, is_target):
        if ida_hexrays is None:
            return 0
        try:
            t = getattr(mop, "t", None)
            if t == ida_hexrays.mop_d:
                inner = getattr(mop, "d", None)
                if inner is not None:
                    if self.utils.is_call_opcode(inner.opcode):
                        key = id(inner)
                        if key not in self.seen_calls:
                            self.seen_calls.add(key)
                            self.analyzer._record_call(inner, self.calls)
                    self._visit_inner_operands(inner)
                return 0

            if t == ida_hexrays.mop_f:
                for arg_wrapper in self.utils.iter_call_args(mop):
                    arg_mop = self.utils.extract_arg_mop(arg_wrapper)
                    if arg_mop:
                        self.visit_mop(arg_mop, type_id, False)
                return 0

            access_mode = None
            if t == ida_hexrays.mop_a:
                access_mode = "addr"

            op = self.utils.mop_to_attr(mop)
            if op is None:
                return 0

            role = "dst" if is_target else "src"
            text = self.utils.safe_dstr(mop) if mop else ""
            mop_type = getattr(mop, "t", None)
            width = getattr(mop, "size", None)
            try:
                if width is not None:
                    width = int(width)
            except Exception:
                width = None
            if width is not None and width <= 0:
                width = None
            entry = OperandInfo(
                role=role,
                attr=op,
                text=text,
                access_mode=access_mode,
                mop_type=mop_type,
                width=width,
                bit_width=width,
            )
            self.analyzer._enrich_operand_entry(entry)

            if is_target:
                key = (role, op, access_mode, text, mop_type, width)
                if key not in self.seen_writes:
                    self.seen_writes.add(key)
                    self.writes.append(entry)
            else:
                key = (role, op, access_mode, text, mop_type, width)
                if key not in self.seen_reads:
                    self.seen_reads.add(key)
                    self.reads.append(entry)
        except Exception:
            pass
        return 0


class MicrocodeInstructionAnalyzer:
    """指令分析器，输出 {"text","opcode","reads","writes","calls"} 结构。"""
    def __init__(self, mba, utils=None):
        self.mba = mba
        self.utils = utils or MicroCodeUtils()

    def analyze_instruction(self, insn):
        reads, writes, calls = self._analyze_minsn(insn)
        opname = self.utils.get_effective_opcode_name(insn.opcode, insn)
        return InsnInfo(
            opcode=opname,
            opcode_id=getattr(insn, "opcode", 0),
            category=self.utils.get_opcode_category(opname),
            is_float=self.utils.is_float_opcode(opname),
            op_size=self._get_insn_size(insn),
            op_type=self.utils.get_opcode_type(opname),
            signed=self._get_signed_flag(insn, opname),
            flags_read=self._get_flags_read(opname),
            flags_write=self._get_flags_write(opname, insn),
            text=self.utils.safe_dstr(insn),
            reads=reads,
            writes=writes,
            calls=calls,
        )

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
        self._ensure_basic_operands(visitor, insn)

        opname = self.utils.get_effective_opcode_name(insn.opcode, insn)
        if self.utils.is_move_opcode(opname) and getattr(insn, "d", None):
            for call in calls:
                if call.ret is None:
                    call.ret = self.utils.mop_to_attr(insn.d)

        if self.utils.is_store_opcode(opname):
            self._record_store(insn, writes)

        calls = self._dedupe_calls(calls)
        return reads, writes, calls

    def _record_call(self, insn, calls):
        opname = self.utils.get_effective_opcode_name(insn.opcode, insn)
        l = getattr(insn, "l", None)
        r = getattr(insn, "r", None)
        d = getattr(insn, "d", None)

        callee_mop, arg_list_mop, ret_mop = self.utils.select_call_operands(l, r, d)

        callee = self.utils.mop_to_attr(callee_mop) if not self.utils.is_none_mop(callee_mop) else None

        args = []
        arg_sources = []
        if hasattr(insn, "args") and insn.args:
            arg_sources.append(insn.args)
        if arg_list_mop:
            arg_sources.append(arg_list_mop)
        for src in arg_sources:
            for arg in self.utils.iter_call_args(src):
                arg_mop = self.utils.extract_arg_mop(arg)
                if arg_mop is None:
                    continue
                loc = self.utils.mop_to_attr(arg_mop)
                if loc is not None:
                    args.append(loc)

        ret = self.utils.mop_to_attr(ret_mop) if not self.utils.is_none_mop(ret_mop) else None

        callee_name = None
        callee_ea = None
        if callee:
            if isinstance(callee, GlobalAttr):
                callee_ea = callee.ea
            elif isinstance(callee, ExpressionAttr):
                callee_name = self.utils._get_func_name_from_helper(callee.expr)
                if callee_name is None:
                    callee_name = callee.expr
            elif isinstance(callee, ImmediateAttr):
                callee_ea = callee.value
            elif isinstance(callee, RegisterAttr):
                pass
            elif isinstance(callee, LocalVarAttr):
                pass
            if callee_ea and idc:
                try:
                    callee_name = idc.get_name(callee_ea)
                except Exception:
                    pass
            if callee_ea is None and callee_name and idc:
                try:
                    lookup_name = callee_name
                    if lookup_name.startswith("$"):
                        lookup_name = lookup_name.lstrip("$")
                    if hasattr(idc, "get_name_ea"):
                        ea = idc.get_name_ea(BADADDR, lookup_name)
                    elif hasattr(idc, "get_name_ea_simple"):
                        ea = idc.get_name_ea_simple(lookup_name)
                    else:
                        ea = None
                    if ea not in (None, BADADDR):
                        callee_ea = ea
                except Exception:
                    pass
            if callee_ea is None and callee_name:
                callee_ea = self._resolve_import_ea(callee_name)

        calls.append(
            CallInfo(
                kind=opname,
                callee_name=callee_name,
                callee_ea=callee_ea,
                target=callee,
                args=args,
                ret=ret,
                arg_order=list(range(len(args))),
                call_conv=self._get_call_conv(insn, callee_ea, callee_name),
                ret_width=self._get_ret_width(ret_mop, insn, callee_ea, callee_name),
            )
        )

    def _get_insn_size(self, insn):
        size = getattr(insn, "size", None)
        try:
            if size is not None:
                size = int(size)
                if size > 0:
                    return size
        except Exception:
            return None
        sizes = []
        for mop in (getattr(insn, "d", None), getattr(insn, "l", None), getattr(insn, "r", None)):
            sizes.extend(self._collect_mop_sizes(mop))
        if sizes:
            size = max(sizes)
            if size > 0:
                return size
        text = self.utils.safe_dstr(insn) or ""
        for m in re.findall(r'\.(\d+)', text):
            try:
                sizes.append(int(m))
            except Exception:
                pass
        if sizes:
            size = max(sizes)
            if size > 0:
                return size
        if self.utils.get_opcode_category(self.utils.get_effective_opcode_name(insn.opcode, insn)) == "call":
            ptr_size = self._get_ptr_size()
            if ptr_size:
                return ptr_size
        return None

    def _get_signed_flag(self, insn, opname: str) -> Optional[bool]:
        signed = getattr(insn, "is_signed", None)
        if signed is not None:
            try:
                return bool(signed)
            except Exception:
                return None
        hint = self.utils.get_opcode_signed_hint(opname)
        if hint is not None:
            return hint
        token = opname
        text = self.utils.safe_dstr(insn) or ""
        if text:
            token = text.strip().split()[0].lower()
            token = token.split(".")[0]
        if token.startswith("j"):
            if token in ("jl", "jle", "jg", "jge"):
                return True
            if token in ("jb", "jbe", "ja", "jae"):
                return False
            return False
        return None

    def _get_flags_read(self, opname: str) -> Optional[bool]:
        category = self.utils.get_opcode_category(opname)
        if opname.startswith("j") or opname.startswith("set") or opname.startswith("cmov"):
            return True
        if category in ("branch", "cmp"):
            return True
        return None

    def _get_flags_write(self, opname: str, insn=None) -> Optional[bool]:
        category = self.utils.get_opcode_category(opname)
        if category in ("arith", "logic", "cmp", "float", "vector"):
            return True
        if opname.startswith(("cmp", "test", "tst", "set", "cmov", "add", "sub", "mul", "div", "and", "or", "xor", "shl", "shr", "sar", "rol", "ror", "neg", "inc", "dec", "adc", "sbb")):
            return True
        if insn is not None:
            text = self.utils.safe_dstr(insn) or ""
            if text:
                token = text.strip().split()[0].lower()
                token = token.split(".")[0]
                if token.startswith(("cmp", "test", "tst", "set", "cmov", "add", "sub", "mul", "div", "and", "or", "xor", "shl", "shr", "sar", "rol", "ror", "neg", "inc", "dec", "adc", "sbb")):
                    return True
        return None

    def _get_call_conv(self, insn, callee_ea=None, callee_name=None) -> Optional[str]:
        for key in ("cconv", "cc", "call_conv"):
            val = getattr(insn, key, None)
            if val:
                try:
                    return str(val)
                except Exception:
                    return None
        if idc and callee_ea:
            try:
                t = idc.get_type(callee_ea)
                conv = self._parse_call_conv(t)
                if conv:
                    return conv
            except Exception:
                pass
        if ida_typeinf and callee_ea:
            conv = self._get_call_conv_from_tinfo(callee_ea)
            if conv:
                return conv
        if idc and callee_ea and ida_typeinf:
            try:
                if hasattr(idc, "FUNCATTR_CC"):
                    cc = idc.get_func_attr(callee_ea, idc.FUNCATTR_CC)
                else:
                    cc = None
                conv = self._cc_to_name(cc)
                if conv:
                    return conv
            except Exception:
                pass
        if idc and callee_name:
            try:
                lookup_name = callee_name
                if lookup_name.startswith("$"):
                    lookup_name = lookup_name.lstrip("$")
                if hasattr(idc, "get_name_ea"):
                    ea = idc.get_name_ea(BADADDR, lookup_name)
                elif hasattr(idc, "get_name_ea_simple"):
                    ea = idc.get_name_ea_simple(lookup_name)
                else:
                    ea = None
                if ea not in (None, BADADDR):
                    t = idc.get_type(ea)
                    conv = self._parse_call_conv(t)
                    if conv:
                        return conv
            except Exception:
                pass
        if callee_name:
            conv = self._parse_call_conv(callee_name)
            if conv:
                return conv
        return None

    def _get_ret_width(self, ret_mop, insn=None, callee_ea=None, callee_name=None) -> Optional[int]:
        if ret_mop is None:
            size = None
            if insn is not None:
                size = getattr(insn, "size", None)
            try:
                if size is not None:
                    size = int(size)
                    if size > 0:
                        return size
            except Exception:
                return None
            if callee_ea and ida_typeinf:
                ret = self._get_ret_width_from_tinfo(callee_ea)
                if ret:
                    return ret
            if callee_name:
                ret = self._get_ret_width_from_type_str(callee_name)
                if ret:
                    return ret
            return None
        size = getattr(ret_mop, "size", None)
        try:
            if size is not None:
                size = int(size)
                if size > 0:
                    return size
        except Exception:
            return None
        text = self.utils.safe_dstr(ret_mop) or ""
        match = re.search(r'\.(\d+)', text)
        if match:
            try:
                return int(match.group(1))
            except Exception:
                return None
        if callee_ea and ida_typeinf:
            ret = self._get_ret_width_from_tinfo(callee_ea)
            if ret:
                return ret
        if callee_name:
            ret = self._get_ret_width_from_type_str(callee_name)
            if ret:
                return ret
        return None

    def _dedupe_calls(self, calls: List[CallInfo]) -> List[CallInfo]:
        seen = set()
        result = []
        for call in calls:
            key = (
                call.kind,
                call.callee_name,
                call.callee_ea,
                call.target,
                tuple(call.args),
                call.ret,
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(call)
        return result

    def _cc_to_name(self, cc) -> Optional[str]:
        if cc is None or ida_typeinf is None:
            return None
        mapping = {
            getattr(ida_typeinf, "CM_CC_CDECL", None): "cdecl",
            getattr(ida_typeinf, "CM_CC_STDCALL", None): "stdcall",
            getattr(ida_typeinf, "CM_CC_FASTCALL", None): "fastcall",
            getattr(ida_typeinf, "CM_CC_THISCALL", None): "thiscall",
            getattr(ida_typeinf, "CM_CC_VECTORCALL", None): "vectorcall",
            getattr(ida_typeinf, "CM_CC_SPECIAL", None): "usercall",
            getattr(ida_typeinf, "CM_CC_SYSV", None): "sysv",
            getattr(ida_typeinf, "CM_CC_SYSV64", None): "sysv64",
        }
        return mapping.get(cc)

    def _get_call_conv_from_tinfo(self, callee_ea) -> Optional[str]:
        if ida_typeinf is None:
            return None
        try:
            tinfo = ida_typeinf.tinfo_t()
            if not ida_typeinf.get_tinfo(tinfo, callee_ea):
                return None
            if tinfo.is_funcptr():
                tinfo = tinfo.get_pointed_object()
            if not tinfo.is_func():
                return None
            fti = ida_typeinf.func_type_data_t()
            if not tinfo.get_func_details(fti):
                return None
            return self._cc_to_name(getattr(fti, "cc", None))
        except Exception:
            return None

    def _get_ret_width_from_tinfo(self, callee_ea) -> Optional[int]:
        if ida_typeinf is None:
            return None
        try:
            tinfo = ida_typeinf.tinfo_t()
            if not ida_typeinf.get_tinfo(tinfo, callee_ea):
                return None
            if tinfo.is_funcptr():
                tinfo = tinfo.get_pointed_object()
            if not tinfo.is_func():
                return None
            fti = ida_typeinf.func_type_data_t()
            if not tinfo.get_func_details(fti):
                return None
            ret = getattr(fti, "rettype", None)
            if ret is None:
                return None
            size = ret.get_size()
            if size and size > 0:
                return int(size)
        except Exception:
            return None
        return None

    def _resolve_import_ea(self, name: str) -> Optional[int]:
        if ida_nalt is None:
            return None
        base = name.lstrip("$")
        base = base.replace("@", "")
        candidates = {base, base.lstrip("_"), base.replace("__imp_", ""), base.replace("_imp__", "")}
        try:
            qty = ida_nalt.get_import_module_qty()
        except Exception:
            qty = 0
        if not qty:
            return None
        for i in range(qty):
            try:
                def _cb(ea, n, _ord):
                    if not n:
                        return True
                    if n in candidates or n.lstrip("_") in candidates:
                        raise StopIteration(int(ea))
                    return True
                ida_nalt.enum_import_names(i, _cb)
            except StopIteration as e:
                return int(e.value)
            except Exception:
                continue
        return None

    def _get_ret_width_from_type_str(self, type_str: str) -> Optional[int]:
        if not type_str:
            return None
        s = type_str.lower()
        if "(" in s:
            s = s.split("(", 1)[0]
        s = s.replace("__cdecl", "").replace("__stdcall", "").replace("__fastcall", "").replace("__thiscall", "").replace("__vectorcall", "").replace("__usercall", "").replace("__userpurge", "")
        s = s.strip()
        if "*" in s:
            return self._get_ptr_size()
        if "void" in s:
            return None
        if "char" in s:
            return 1
        if "short" in s or "int16" in s:
            return 2
        if "long long" in s or "int64" in s:
            return 8
        if "size_t" in s or "ssize_t" in s:
            return self._get_ptr_size()
        if "int" in s or "long" in s:
            ptr = self._get_ptr_size()
            if "long" in s and ptr == 8:
                return 8
            return 4
        if "float" in s:
            return 4
        if "double" in s:
            return 8
        return None

    def _get_ptr_size(self) -> Optional[int]:
        if ida_ida is None:
            return None
        try:
            if hasattr(ida_ida, "inf_is_64bit") and ida_ida.inf_is_64bit():
                return 8
            if hasattr(ida_ida, "inf_is_32bit_exactly") and ida_ida.inf_is_32bit_exactly():
                return 4
            if hasattr(ida_ida, "idainfo_is_64bit") and ida_ida.idainfo_is_64bit():
                return 8
            if hasattr(ida_ida, "idainfo_is_32bit") and ida_ida.idainfo_is_32bit():
                return 4
        except Exception:
            return None
        return None

    def _record_store(self, insn, writes):
        d = getattr(insn, "d", None)
        l = getattr(insn, "l", None)
        r = getattr(insn, "r", None)
        addr_attr = self.utils.mop_to_attr(d) if d is not None else None
        value_attr = None
        if l is not None:
            value_attr = self.utils.mop_to_attr(l)
        if value_attr is None and r is not None:
            value_attr = self.utils.mop_to_attr(r)
        mem_size = self._get_insn_size(insn)
        if addr_attr is None:
            return
        store_attr = StoreAttr(ptr=addr_attr, value=value_attr, mem_size=mem_size)
        if mem_size is not None and mem_size <= 0:
            mem_size = None
        writes[:] = [
            w for w in writes if not (w.role == "dst" and w.attr == addr_attr)
        ]
        entry = OperandInfo(
            role="dst",
            attr=store_attr,
            text=self.utils.safe_dstr(d) if d is not None else "",
            access_mode="store",
            mop_type=getattr(d, "t", None) if d is not None else None,
            width=mem_size,
            bit_width=mem_size,
            mem_size=mem_size,
            is_pointer=True,
        )
        self._enrich_operand_entry(entry)
        writes.append(entry)

    def _ensure_basic_operands(self, visitor: MopUsageVisitor, insn):
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

    def _collect_mop_sizes(self, mop):
        sizes = []
        if mop is None or ida_hexrays is None:
            return sizes
        size = getattr(mop, "size", None)
        try:
            if size is not None:
                size = int(size)
                if size > 0:
                    sizes.append(size)
        except Exception:
            pass
        t = getattr(mop, "t", None)
        if t == ida_hexrays.mop_d:
            inner = getattr(mop, "d", None)
            if inner is not None:
                inner_size = getattr(inner, "size", None)
                try:
                    if inner_size is not None:
                        inner_size = int(inner_size)
                        if inner_size > 0:
                            sizes.append(inner_size)
                except Exception:
                    pass
                for inner_mop in (getattr(inner, "d", None), getattr(inner, "l", None), getattr(inner, "r", None)):
                    sizes.extend(self._collect_mop_sizes(inner_mop))
        return sizes

    def _parse_call_conv(self, type_str: Optional[str]) -> Optional[str]:
        if not type_str:
            return None
        s = type_str.lower()
        for key in ("__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "__usercall", "__userpurge"):
            if key in s:
                return key.lstrip("_")
        return None

    def _enrich_operand_entry(self, entry: OperandInfo):
        attr = entry.attr
        if isinstance(attr, ImmediateAttr):
            entry.value_raw = attr.raw if attr.raw is not None else attr.value
            entry.value_float = attr.fvalue
        if isinstance(attr, AddressAttr):
            entry.is_pointer = True
            entry.base = attr.base or attr.inner
            entry.offset = attr.offset
        if isinstance(attr, LoadAttr):
            entry.is_pointer = True
            entry.mem_size = attr.mem_size
        if isinstance(attr, StoreAttr):
            entry.is_pointer = True
            entry.mem_size = attr.mem_size


class CFGBuilder:
    JUMP_OPCODES = frozenset({"goto", "jmp"})
    CONDITIONAL_JUMP_OPCODES = frozenset({
        "jz",
        "jnz",
        "jc",
        "jnc",
        "jo",
        "jno",
        "js",
        "jns",
        "jg",
        "jge",
        "jl",
        "jle",
        "ja",
        "jae",
        "jb",
        "jbe",
        "jp",
        "jnp",
        "jpe",
        "jpo",
    })

    def __init__(self, mba):
        self.mba = mba
        self.utils = MicroCodeUtils()
        self.blocks = {}
        self.block_insns = {}

    def build(self):
        self._collect_blocks()
        self._connect_blocks()
        return self.blocks

    def _collect_blocks(self):
        for block_id in range(self.mba.qty):
            block = self.mba.get_mblock(block_id)
            start_ea = getattr(block, "start_ea", 0)
            end_ea = getattr(block, "end_ea", 0)
            self.blocks[block_id] = BlockInfo(
                block_id=block_id,
                start_ea=start_ea,
                end_ea=end_ea,
            )

        for block_id in range(self.mba.qty):
            block = self.mba.get_mblock(block_id)
            curr = block.head
            insn_idx = 0
            while curr:
                if block_id not in self.block_insns:
                    self.block_insns[block_id] = []
                self.block_insns[block_id].append((insn_idx, curr))
                curr = curr.next
                insn_idx += 1

    def _connect_blocks(self):
        block_ids = sorted(self.blocks.keys())

        for block_id in block_ids:
            if block_id not in self.block_insns:
                continue

            insns = self.block_insns[block_id]
            if not insns:
                continue

            last_idx, last_insn = insns[-1]
            opcode_name = self.utils.get_effective_opcode_name(last_insn.opcode, last_insn)

            if opcode_name in self.JUMP_OPCODES:
                targets = self._get_jump_targets(last_insn)
                self.blocks[block_id].successors.extend(targets)

            elif opcode_name in self.CONDITIONAL_JUMP_OPCODES or (opcode_name.startswith("j") and opcode_name not in self.JUMP_OPCODES):
                targets = self._get_jump_targets(last_insn)
                self.blocks[block_id].successors.extend(targets)
                next_block = self._get_next_block(block_ids, block_id)
                if next_block is not None:
                    self.blocks[block_id].successors.append(next_block)

            else:
                next_block = self._get_next_block(block_ids, block_id)
                if next_block is not None:
                    self.blocks[block_id].successors.append(next_block)

        for block_id in block_ids:
            for succ_id in self.blocks[block_id].successors:
                if succ_id in self.blocks:
                    if block_id not in self.blocks[succ_id].predecessors:
                        self.blocks[succ_id].predecessors.append(block_id)

    def _get_jump_targets(self, insn):
        targets = []
        for mop in (getattr(insn, "d", None), getattr(insn, "l", None), getattr(insn, "r", None)):
            if mop is None:
                continue
            target = self.utils.mop_to_attr(mop)
            if target is not None and hasattr(target, "block_id"):
                targets.append(target.block_id)
        if targets:
            return targets
        text = self.utils.safe_dstr(insn) or ""
        for match in re.findall(r'@(\d+)', text):
            try:
                targets.append(int(match))
            except Exception:
                pass
        return targets

    def _get_next_block(self, block_ids, current):
        try:
            idx = block_ids.index(current)
            if idx + 1 < len(block_ids):
                return block_ids[idx + 1]
        except ValueError:
            pass
        return None


class MicrocodeFunctionAnalyzer:
    def __init__(self, mba, utils=None, instruction_analyzer=None):
        self.mba = mba
        self.utils = utils or MicroCodeUtils()
        self.instruction_analyzer = instruction_analyzer or MicrocodeInstructionAnalyzer(
            mba, self.utils
        )
        self.block_insns = {}

    def analyze_function(self, pfn, maturity):
        func_name = ida_funcs.get_func_name(pfn.start_ea)
        func_args, return_vars = self._collect_signature_vars()

        cfg_builder = CFGBuilder(self.mba)
        cfg_blocks = cfg_builder.build()
        self.block_insns = cfg_builder.block_insns

        exit_blocks = [bid for bid, b in cfg_blocks.items() if not b.successors]
        entry_block = 0
        if cfg_blocks:
            entry_block = min(cfg_blocks.keys())

        insns = []
        for block_id in range(self.mba.qty):
            if block_id not in self.block_insns:
                continue
            insns_in_block = self.block_insns[block_id]
            for idx_in_block, (insn_idx, insn) in enumerate(insns_in_block):
                try:
                    insn_entry = self._build_insn_entry(block_id, insn_idx, insn)
                    self._populate_jump_info(insn_entry, insn, block_id, cfg_blocks)
                    insns.append(insn_entry)
                except Exception:
                    pass

        return FuncInfo(
            function=func_name,
            ea=hex(pfn.start_ea),
            maturity=maturity,
            args=func_args,
            return_vars=return_vars,
            insns=insns,
            cfg_blocks=cfg_blocks,
            entry_block=entry_block,
            exit_blocks=exit_blocks,
        )

    def _collect_signature_vars(self):
        func_args = []
        return_vars = []
        if self.mba.vars:
            try:
                for i, v in enumerate(self.mba.vars):
                    if v.is_arg_var:
                        func_args.append(ArgInfo(lvar_idx=i, name=v.name, width=v.width))
                    is_result = False
                    if hasattr(v, "is_result_var") and v.is_result_var:
                        is_result = True
                    elif v.name and (v.name == "result" or v.name.startswith("retvar")):
                        is_result = True
                    if is_result:
                        return_vars.append(i)
            except Exception:
                pass
        return func_args, return_vars

    def _iter_instructions(self):
        for block_id in range(self.mba.qty):
            block = self.mba.get_mblock(block_id)
            curr = block.head
            insn_idx = 0
            while curr:
                yield block_id, insn_idx, curr
                curr = curr.next
                insn_idx += 1

    def _build_insn_entry(self, block_id, insn_idx, insn):
        ea_str = hex(insn.ea)
        cpg_info = self.instruction_analyzer.analyze_instruction(insn)
        return InsnInfo(
            block_id=block_id,
            insn_idx=insn_idx,
            ea=ea_str,
            opcode=cpg_info.opcode,
            opcode_id=cpg_info.opcode_id,
            category=cpg_info.category,
            is_float=cpg_info.is_float,
            op_size=cpg_info.op_size,
            op_type=cpg_info.op_type,
            signed=cpg_info.signed,
            flags_read=cpg_info.flags_read,
            flags_write=cpg_info.flags_write,
            text=cpg_info.text,
            reads=cpg_info.reads,
            writes=cpg_info.writes,
            calls=cpg_info.calls,
        )

    def _populate_jump_info(self, insn_entry: InsnInfo, insn, block_id: int, cfg_blocks: dict):
        opcode_name = self.utils.get_effective_opcode_name(insn.opcode, insn)
        category = self.utils.get_opcode_category(opcode_name)
        is_unconditional = opcode_name in CFGBuilder.JUMP_OPCODES or category == "jump"
        is_conditional = opcode_name in CFGBuilder.CONDITIONAL_JUMP_OPCODES or (opcode_name.startswith("j") and opcode_name not in CFGBuilder.JUMP_OPCODES)

        if is_unconditional:
            targets = self._extract_jump_targets(insn)
            insn_entry.jump_targets = targets
            insn_entry.is_conditional = False
            insn_entry.jump_kind = opcode_name

        elif is_conditional:
            targets = self._extract_jump_targets(insn)
            insn_entry.jump_targets = targets
            insn_entry.is_conditional = True
            insn_entry.jump_kind = opcode_name
            insn_entry.condition = self._get_condition_expr(insn)

        if block_id in cfg_blocks:
            successors = cfg_blocks[block_id].successors
            if successors and not insn_entry.jump_targets:
                insn_entry.fallthrough_block = successors[0]

    def _get_condition_expr(self, insn) -> str:
        l = getattr(insn, "l", None)
        r = getattr(insn, "r", None)
        if l is not None:
            return self.utils.safe_dstr(l) or ""
        if r is not None:
            return self.utils.safe_dstr(r) or ""
        return ""

    def _extract_jump_targets(self, insn):
        targets = self._extract_jump_targets_from_mops(insn)
        if not targets:
            targets = self._extract_jump_targets_from_text(insn)
        return targets

    def _extract_jump_targets_from_mops(self, insn):
        targets = []
        for mop in (getattr(insn, "d", None), getattr(insn, "l", None), getattr(insn, "r", None)):
            if mop is None:
                continue
            target = self.utils.mop_to_attr(mop)
            if target is not None and hasattr(target, "block_id"):
                targets.append(target.block_id)
        return targets

    def _extract_jump_targets_from_text(self, insn):
        text = self.utils.safe_dstr(insn) or ""
        targets = []
        for match in re.findall(r'@(\d+)', text):
            try:
                targets.append(int(match))
            except Exception:
                pass
        return targets


class MicrocodeAnalyzer(MicrocodeInstructionAnalyzer):
    """兼容包装类，输出与 MicrocodeInstructionAnalyzer 一致。"""
    def __init__(self, mba):
        super().__init__(mba)


_ANALYZER_DEBUG = False


def set_debug(enabled=True):
    global _ANALYZER_DEBUG
    _ANALYZER_DEBUG = enabled


def analyze_function(pfn, maturity):
    """
    分析单个函数并返回其污点分析所需的信息。

    Returns:
        FuncInfo: 函数分析结果 dataclass，包含以下字段:
            - function: str, 函数名称
            - ea: str, 函数起始地址 (十六进制)
            - maturity: int, 成熟度级别
            - args: list[ArgInfo], 参数列表
            - return_vars: list[int], 返回值变量索引
            - insns: list[InsnInfo], 指令列表
        None: 如果分析失败
    """
    hf = ida_hexrays.hexrays_failure_t()
    mbr = ida_hexrays.mba_ranges_t(pfn)
    mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_WARNINGS, maturity)

    if not mba:
        return None

    analyzer = MicrocodeFunctionAnalyzer(mba)
    return analyzer.analyze_function(pfn, maturity)

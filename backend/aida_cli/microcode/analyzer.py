from .constants import (
    ida_hexrays,
    idc,
    ida_funcs,
    idautils,
    ida_idaapi,
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
                    
                    # Recurse into nested instruction
                    if hasattr(inner, "for_all_ops"):
                        inner.for_all_ops(self)
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
            entry = OperandInfo(
                role=role,
                attr=op,
                text=text,
                access_mode=access_mode,
                mop_type=mop_type,
                width=width,
                bit_width=width,
            )
            self._enrich_operand_entry(entry)

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
        opname = self.utils.get_opcode_name(insn.opcode)
        return InsnInfo(
            opcode=opname,
            opcode_id=getattr(insn, "opcode", 0),
            category=self.utils.get_opcode_category(opname),
            is_float=self.utils.is_float_opcode(opname),
            op_size=self._get_insn_size(insn),
            op_type=self.utils.get_opcode_type(opname),
            signed=self._get_signed_flag(insn, opname),
            flags_read=self._get_flags_read(opname),
            flags_write=self._get_flags_write(opname),
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

        opname = self.utils.get_opcode_name(insn.opcode)
        if self.utils.is_move_opcode(opname) and getattr(insn, "d", None):
            for call in calls:
                if call.ret is None:
                    call.ret = self.utils.mop_to_attr(insn.d)

        if self.utils.is_store_opcode(opname):
            self._record_store(insn, writes)

        return reads, writes, calls

    def _record_call(self, insn, calls):
        opname = self.utils.get_opcode_name(insn.opcode)
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

        calls.append(
            CallInfo(
                kind=opname,
                callee_name=callee_name,
                callee_ea=callee_ea,
                target=callee,
                args=args,
                ret=ret,
                arg_order=list(range(len(args))),
                call_conv=self._get_call_conv(insn),
                ret_width=self._get_ret_width(ret_mop),
            )
        )

    def _get_insn_size(self, insn):
        size = getattr(insn, "size", None)
        try:
            if size is not None:
                return int(size)
        except Exception:
            return None
        return None

    def _get_signed_flag(self, insn, opname: str) -> Optional[bool]:
        signed = getattr(insn, "is_signed", None)
        if signed is not None:
            try:
                return bool(signed)
            except Exception:
                return None
        return self.utils.get_opcode_signed_hint(opname)

    def _get_flags_read(self, opname: str) -> Optional[bool]:
        if opname.startswith("j"):
            return True
        return None

    def _get_flags_write(self, opname: str) -> Optional[bool]:
        category = self.utils.get_opcode_category(opname)
        if category in ("arith", "logic", "cmp", "float", "vector"):
            return True
        return None

    def _get_call_conv(self, insn) -> Optional[str]:
        for key in ("cconv", "cc", "call_conv"):
            val = getattr(insn, key, None)
            if val:
                try:
                    return str(val)
                except Exception:
                    return None
        return None

    def _get_ret_width(self, ret_mop) -> Optional[int]:
        if ret_mop is None:
            return None
        size = getattr(ret_mop, "size", None)
        try:
            if size is not None:
                return int(size)
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
            opcode_name = self.utils.get_opcode_name(last_insn.opcode)

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
        d = getattr(insn, "d", None)
        if d is not None:
            target = self.utils.mop_to_attr(d)
            if target is not None and hasattr(target, "block_id"):
                targets.append(target.block_id)
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
        opcode_name = self.utils.get_opcode_name(insn.opcode)

        if opcode_name in CFGBuilder.JUMP_OPCODES:
            targets = []
            d = getattr(insn, "d", None)
            if d is not None:
                target = self.utils.mop_to_attr(d)
                if target is not None and hasattr(target, "block_id"):
                    targets.append(target.block_id)
            insn_entry.jump_targets = targets
            insn_entry.is_conditional = False
            insn_entry.jump_kind = "jump"

        elif opcode_name in CFGBuilder.CONDITIONAL_JUMP_OPCODES or (opcode_name.startswith("j") and opcode_name not in CFGBuilder.JUMP_OPCODES):
            targets = []
            d = getattr(insn, "d", None)
            if d is not None:
                target = self.utils.mop_to_attr(d)
                if target is not None and hasattr(target, "block_id"):
                    targets.append(target.block_id)
            insn_entry.jump_targets = targets
            insn_entry.is_conditional = True
            insn_entry.jump_kind = "branch"
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

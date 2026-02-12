from .constants import (
    ida_hexrays,
    idc,
    ida_funcs,
    idautils,
    ida_idaapi,
    BADADDR,
)
from .common import MicroCodeUtils, OperandLocation, RegisterLocation, LocalVarLocation, StackLocation, GlobalLocation, ImmediateLocation, StringLocation, AddressLocation, LoadLocation, ExpressionLocation
from dataclasses import dataclass, field
from typing import Optional
import sys


@dataclass
class OperandInfo:
    """指令操作数 (reads/writes 列表元素)"""
    role: str = ""                  # "src" (读取) 或 "dst" (写入)
    location: Optional[OperandLocation] = None
    text: str = ""
    access_mode: Optional[str] = None  # 可选: "addr" 表示地址访问

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        loc = self.location.to_string(indent + 1) if self.location else "None"
        return f"{prefix}OperandInfo(\n{prefix}  role={self.role!r},\n{prefix}  location={loc},\n{prefix}  text={self.text!r},\n{prefix}  access_mode={self.access_mode!r}\n{prefix})"


@dataclass
class CallInfo:
    """函数调用信息 (calls 列表元素)"""
    kind: str = ""                      # 操作码类型 (call/jmp)
    callee_name: Optional[str] = None   # 被调用函数名
    target: Optional[OperandLocation] = None    # 调用目标
    args: list = field(default_factory=list)    # OperandLocation 列表
    ret: Optional[OperandLocation] = None       # 返回值存储位置

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        tgt = self.target.to_string(indent + 1) if self.target else "None"
        args_str = ",\n".join(a.to_string(indent + 1) if a else "None" for a in self.args)
        ret_str = self.ret.to_string(indent + 1) if self.ret else "None"
        return f"{prefix}CallInfo(\n{prefix}  kind={self.kind!r},\n{prefix}  callee_name={self.callee_name!r},\n{prefix}  target={tgt},\n{prefix}  args=[\n{args_str}\n{prefix}  ],\n{prefix}  ret={ret_str}\n{prefix})"


@dataclass
class InsnInfo:
    """指令信息 (insns 列表元素)"""
    block_id: int = 0
    insn_idx: int = 0
    ea: str = ""              # 十六进制地址
    opcode: str = ""          # 操作码名称
    text: str = ""            # 文本表示
    reads: list = field(default_factory=list)    # OperandInfo 列表
    writes: list = field(default_factory=list)   # OperandInfo 列表
    calls: list = field(default_factory=list)    # CallInfo 列表

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        reads_str = ",\n".join(r.to_string(indent + 1) for r in self.reads) if self.reads else ""
        writes_str = ",\n".join(w.to_string(indent + 1) for w in self.writes) if self.writes else ""
        calls_str = ",\n".join(c.to_string(indent + 1) for c in self.calls) if self.calls else ""
        return f"{prefix}InsnInfo(\n{prefix}  block_id={self.block_id},\n{prefix}  insn_idx={self.insn_idx},\n{prefix}  ea={self.ea!r},\n{prefix}  opcode={self.opcode!r},\n{prefix}  text={self.text!r},\n{prefix}  reads=[\n{reads_str}\n{prefix}  ],\n{prefix}  writes=[\n{writes_str}\n{prefix}  ],\n{prefix}  calls=[\n{calls_str}\n{prefix}  ]\n{prefix})"


@dataclass
class ArgInfo:
    """函数参数信息"""
    lvar_idx: int = 0
    name: str = ""
    width: int = 0

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}ArgInfo(lvar_idx={self.lvar_idx}, name={self.name!r}, width={self.width})"


@dataclass
class FuncInfo:
    """
    函数分析结果 (analyze_function 返回类型)

    Attributes:
        function: 函数名称
        ea: 函数起始地址 (十六进制字符串，如 "0x401000")
        maturity: microcode 成熟度级别
        args: 函数参数列表
        return_vars: 返回值变量的 lvar_idx 列表
        insns: 指令列表
    """
    function: str = ""
    ea: str = ""
    maturity: int = 0
    args: list = field(default_factory=list)     # ArgInfo 列表
    return_vars: list = field(default_factory=list)  # int 列表
    insns: list = field(default_factory=list)    # InsnInfo 列表

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        args_str = ",\n".join(a.to_string(indent + 1) for a in self.args) if self.args else ""
        insns_str = ",\n".join(i.to_string(indent + 1) for i in self.insns) if self.insns else ""
        return f"{prefix}FuncInfo(\n{prefix}  function={self.function!r},\n{prefix}  ea={self.ea!r},\n{prefix}  maturity={self.maturity},\n{prefix}  args=[\n{args_str}\n{prefix}  ],\n{prefix}  return_vars={self.return_vars},\n{prefix}  insns=[\n{insns_str}\n{prefix}  ]\n{prefix})"


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

            op = self.utils.mop_to_location(mop)
            if op is None:
                return 0

            role = "dst" if is_target else "src"
            entry = OperandInfo(role=role, location=op, access_mode=access_mode)

            if is_target:
                if role not in self.seen_writes:
                    self.seen_writes.add(role)
                    self.writes.append(entry)
            else:
                if role not in self.seen_reads:
                    self.seen_reads.add(role)
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
        if opname == "mov" and getattr(insn, "d", None):
            for call in calls:
                if call.ret is None:
                    call.ret = self.utils.mop_entry(insn.d)

        return reads, writes, calls

    def _record_call(self, insn, calls):
        opname = self.utils.get_opcode_name(insn.opcode)
        l = getattr(insn, "l", None)
        r = getattr(insn, "r", None)
        d = getattr(insn, "d", None)

        callee_mop, arg_list_mop, ret_mop = self.utils.select_call_operands(l, r, d)

        callee = self.utils.mop_to_location(callee_mop) if not self.utils.is_none_mop(callee_mop) else None

        args = []
        arg_sources = []
        if hasattr(insn, "args") and insn.args:
            arg_sources.append(insn.args)
        if arg_list_mop:
            arg_sources.append(arg_list_mop)
        for src in arg_sources:
            for arg in self.utils.iter_call_args(src):
                loc = self.utils.mop_to_location(arg)
                if loc is not None:
                    args.append(loc)

        ret = self.utils.mop_to_location(ret_mop) if not self.utils.is_none_mop(ret_mop) else None

        callee_name = None
        callee_ea = None
        if callee:
            if isinstance(callee, GlobalLocation):
                callee_ea = callee.ea
            elif isinstance(callee, ExpressionLocation):
                callee_name = self.utils._get_func_name_from_helper(callee.expr)
                if callee_name is None:
                    callee_name = callee.expr
            elif isinstance(callee, ImmediateLocation):
                callee_ea = callee.value
            elif isinstance(callee, RegisterLocation):
                pass
            elif isinstance(callee, LocalVarLocation):
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
                target=callee,
                args=args,
                ret=ret,
            )
        )


class MicrocodeFunctionAnalyzer:
    """函数分析器，输出函数级 dict（包含 args/return_vars/insns）。"""
    def __init__(self, mba, utils=None, instruction_analyzer=None):
        self.mba = mba
        self.utils = utils or MicroCodeUtils()
        self.instruction_analyzer = instruction_analyzer or MicrocodeInstructionAnalyzer(
            mba, self.utils
        )

    def analyze_function(self, pfn, maturity):
        func_name = ida_funcs.get_func_name(pfn.start_ea)
        func_args, return_vars = self._collect_signature_vars()
        insns = []
        for block_id, insn_idx, insn in self._iter_instructions():
            try:
                insn_entry = self._build_insn_entry(block_id, insn_idx, insn)
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
            text=cpg_info.text,
            reads=cpg_info.reads,
            writes=cpg_info.writes,
            calls=cpg_info.calls,
        )


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
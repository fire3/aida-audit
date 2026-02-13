from .constants import (
    ida_hexrays,
    idc,
    ida_funcs,
    idautils,
    ida_idaapi,
    BADADDR,
)
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Union, Optional, List, Dict, List


class AttrType:
    """操作数属性类型枚举"""
    REGISTER = "register"
    LOCAL_VAR = "local_var"
    STACK = "stack"
    GLOBAL = "global"
    IMMEDIATE = "immediate"
    STRING = "string"
    ADDRESS = "address"
    LOAD = "load"
    STORE = "store"
    BLOCK = "block"
    EXPRESSION = "expression"
    HELPER_FUNC = "helper_func"
    FLOAT_IMMEDIATE = "float_immediate"
    CAST = "cast"


class OperandAttr(ABC):
    """
    操作数属性抽象基类 (ADT 模式)
    """

    @property
    @abstractmethod
    def attr_type(self) -> str:
        pass

    @abstractmethod
    def to_string(self, indent: int = 0) -> str:
        """转换为可打印的字符串"""
        pass


@dataclass(frozen=True, eq=True)
class RegisterAttr(OperandAttr):
    """寄存器属性"""
    reg_id: int

    @property
    def attr_type(self) -> str:
        return AttrType.REGISTER

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}RegisterAttr(reg_id={self.reg_id})"


@dataclass(frozen=True, eq=True)
class LocalVarAttr(OperandAttr):
    """局部变量属性 (按索引)"""
    lvar_idx: int

    @property
    def attr_type(self) -> str:
        return AttrType.LOCAL_VAR

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}LocalVarAttr(lvar_idx={self.lvar_idx})"


@dataclass(frozen=True, eq=True)
class StackAttr(OperandAttr):
    """栈偏移属性"""
    offset: int

    @property
    def attr_type(self) -> str:
        return AttrType.STACK

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}StackAttr(offset={self.offset})"


@dataclass(frozen=True, eq=True)
class GlobalAttr(OperandAttr):
    """全局地址属性"""
    ea: int

    @property
    def attr_type(self) -> str:
        return AttrType.GLOBAL

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}GlobalAttr(ea={hex(self.ea)})"


@dataclass(frozen=True, eq=True)
class ImmediateAttr(OperandAttr):
    """立即数属性"""
    value: Optional[int] = None
    fvalue: Optional[float] = None
    raw: Optional[int] = None
    text: str = ""

    @property
    def attr_type(self) -> str:
        return AttrType.IMMEDIATE

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}ImmediateAttr(value={self.value}, fvalue={self.fvalue}, raw={self.raw}, text={self.text!r})"


@dataclass(frozen=True, eq=True)
class StringAttr(OperandAttr):
    """字符串常量属性"""
    value: str

    @property
    def attr_type(self) -> str:
        return AttrType.STRING

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}StringAttr(value={self.value!r})"


@dataclass(frozen=True, eq=True)
class AddressAttr(OperandAttr):
    """地址引用属性 (指向另一属性)"""
    inner: OperandAttr
    base: Optional[OperandAttr] = None
    offset: Optional[OperandAttr] = None

    @property
    def attr_type(self) -> str:
        return AttrType.ADDRESS

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        inner_dump = self.inner.to_string(indent + 1)
        base_dump = self.base.to_string(indent + 1) if self.base else "None"
        offset_dump = self.offset.to_string(indent + 1) if self.offset else "None"
        return f"{prefix}AddressAttr(\n{prefix}  inner={inner_dump}\n{prefix}  base={base_dump}\n{prefix}  offset={offset_dump}\n{prefix})"


@dataclass(frozen=True, eq=True)
class LoadAttr(OperandAttr):
    """内存解引用属性 (load ptr)"""
    ptr: OperandAttr
    mem_size: Optional[int] = None

    @property
    def attr_type(self) -> str:
        return AttrType.LOAD

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        ptr_dump = self.ptr.to_string(indent + 1)
        return f"{prefix}LoadAttr(\n{prefix}  ptr={ptr_dump}\n{prefix}  mem_size={self.mem_size!r}\n{prefix})"


@dataclass(frozen=True, eq=True)
class StoreAttr(OperandAttr):
    ptr: OperandAttr
    value: Optional[OperandAttr] = None
    mem_size: Optional[int] = None

    @property
    def attr_type(self) -> str:
        return AttrType.STORE

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        ptr_dump = self.ptr.to_string(indent + 1)
        value_dump = self.value.to_string(indent + 1) if self.value else "None"
        return f"{prefix}StoreAttr(\n{prefix}  ptr={ptr_dump}\n{prefix}  value={value_dump}\n{prefix}  mem_size={self.mem_size!r}\n{prefix})"


@dataclass(frozen=True, eq=True)
class BlockAttr(OperandAttr):
    block_id: int

    @property
    def attr_type(self) -> str:
        return AttrType.BLOCK

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}BlockAttr(block_id={self.block_id})"


@dataclass(frozen=True, eq=True)
class HelperFuncAttr(OperandAttr):
    """Helper 函数引用属性 (如 $sub_1020, $__gmon_start__)"""
    name: str
    ea: Optional[int] = None

    @property
    def attr_type(self) -> str:
        return AttrType.HELPER_FUNC

    @staticmethod
    def normalize_name(name: str) -> str:
        """标准化全局变量名称，去除SSA后缀（如 .8{2} -> _CWE78_badData）"""
        import re
        normalized = re.sub(r'\.8\{\d+\}$', '', name)
        return normalized.lstrip('_')

    def get_global_key(self) -> str:
        """获取用于 global_taints 的标准化的键"""
        return self.normalize_name(self.name)

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}HelperFuncAttr(name={self.name!r}, ea={self.ea})"


@dataclass(frozen=True, eq=True)
class FloatImmediateAttr(OperandAttr):
    """浮点数立即数属性"""
    value: float
    text: str = ""

    @property
    def attr_type(self) -> str:
        return AttrType.FLOAT_IMMEDIATE

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}FloatImmediateAttr(value={self.value}, text={self.text!r})"


@dataclass(frozen=True, eq=True)
class CastAttr(OperandAttr):
    """类型转换属性 (xdu/xds 等类型转换)"""
    cast_type: str
    size: int
    src: Optional[OperandAttr] = None

    @property
    def attr_type(self) -> str:
        return AttrType.CAST

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        src_dump = self.src.to_string(indent + 1) if self.src else "None"
        return f"{prefix}CastAttr(cast_type={self.cast_type!r}, size={self.size}, src={src_dump})"


@dataclass(frozen=True, eq=True)
class ExpressionAttr(OperandAttr):
    """复杂表达式属性 (不可分解)"""
    expr: str

    @property
    def attr_type(self) -> str:
        return AttrType.EXPRESSION

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}ExpressionAttr(expr={self.expr!r})"


OperandAttrList = Union[
    RegisterAttr,
    LocalVarAttr,
    StackAttr,
    GlobalAttr,
    ImmediateAttr,
    StringAttr,
    AddressAttr,
    LoadAttr,
    StoreAttr,
    BlockAttr,
    HelperFuncAttr,
    FloatImmediateAttr,
    CastAttr,
    ExpressionAttr,
]


@dataclass
class OperandInfo:
    """指令操作数 (reads/writes 列表元素)"""
    role: str = ""
    attr: Optional[OperandAttr] = None
    text: str = ""
    access_mode: Optional[str] = None
    mop_type: Optional[int] = None
    width: Optional[int] = None
    bit_width: Optional[int] = None
    is_pointer: Optional[bool] = None
    mem_size: Optional[int] = None
    base: Optional[OperandAttr] = None
    offset: Optional[OperandAttr] = None
    value_raw: Optional[int] = None
    value_float: Optional[float] = None

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        loc = self.attr.to_string(indent + 1) if self.attr else "None"
        base_dump = self.base.to_string(indent + 1) if self.base else "None"
        offset_dump = self.offset.to_string(indent + 1) if self.offset else "None"
        return f"{prefix}OperandInfo(\n{prefix}  role={self.role!r},\n{prefix}  attr={loc},\n{prefix}  text={self.text!r},\n{prefix}  access_mode={self.access_mode!r},\n{prefix}  mop_type={self.mop_type!r},\n{prefix}  width={self.width!r},\n{prefix}  bit_width={self.bit_width!r},\n{prefix}  is_pointer={self.is_pointer!r},\n{prefix}  mem_size={self.mem_size!r},\n{prefix}  base={base_dump},\n{prefix}  offset={offset_dump},\n{prefix}  value_raw={self.value_raw!r},\n{prefix}  value_float={self.value_float!r}\n{prefix})"


@dataclass
class CallInfo:
    """函数调用信息 (calls 列表元素)"""
    kind: str = ""
    callee_name: Optional[str] = None
    callee_ea: Optional[int] = None
    target: Optional[OperandAttr] = None
    args: list = field(default_factory=list)
    ret: Optional[OperandAttr] = None
    arg_order: list = field(default_factory=list)
    call_conv: Optional[str] = None
    ret_width: Optional[int] = None
    call_site_ea: Optional[int] = None
    caller_func_ea: Optional[int] = None
    caller_arg_vars: list = field(default_factory=list)

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        tgt = self.target.to_string(indent + 1) if self.target else "None"
        args_str = ",\n".join(a.to_string(indent + 1) if a else "None" for a in self.args)
        ret_str = self.ret.to_string(indent + 1) if self.ret else "None"
        caller_args_str = ",\n".join(str(a) for a in self.caller_arg_vars)
        return f"{prefix}CallInfo(\n{prefix}  kind={self.kind!r},\n{prefix}  callee_name={self.callee_name!r},\n{prefix}  callee_ea={self.callee_ea!r},\n{prefix}  target={tgt},\n{prefix}  args=[\n{args_str}\n{prefix}  ],\n{prefix}  ret={ret_str},\n{prefix}  arg_order={self.arg_order!r},\n{prefix}  call_conv={self.call_conv!r},\n{prefix}  ret_width={self.ret_width!r},\n{prefix}  call_site_ea={self.call_site_ea!r},\n{prefix}  caller_func_ea={self.caller_func_ea!r},\n{prefix}  caller_arg_vars=[{caller_args_str}],\n{prefix})"


@dataclass
class InsnInfo:
    """指令信息 (insns 列表元素)"""
    block_id: int = 0
    insn_idx: int = 0
    ea: str = ""
    opcode: str = ""
    opcode_id: int = 0
    category: str = ""
    is_float: bool = False
    op_size: Optional[int] = None
    op_type: Optional[str] = None
    signed: Optional[bool] = None
    flags_read: Optional[bool] = None
    flags_write: Optional[bool] = None
    condition: str = ""
    jump_kind: str = ""
    text: str = ""
    reads: list = field(default_factory=list)
    writes: list = field(default_factory=list)
    calls: list = field(default_factory=list)
    jump_targets: List[int] = field(default_factory=list)
    is_conditional: bool = False
    fallthrough_block: Optional[int] = None

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        reads_str = ",\n".join(r.to_string(indent + 1) for r in self.reads) if self.reads else ""
        writes_str = ",\n".join(w.to_string(indent + 1) for w in self.writes) if self.writes else ""
        calls_str = ",\n".join(c.to_string(indent + 1) for c in self.calls) if self.calls else ""
        return (
            f"{prefix}InsnInfo(\n"
            f"{prefix}  block_id={self.block_id},\n"
            f"{prefix}  insn_idx={self.insn_idx},\n"
            f"{prefix}  ea={self.ea!r},\n"
            f"{prefix}  opcode={self.opcode!r},\n"
            f"{prefix}  opcode_id={self.opcode_id},\n"
            f"{prefix}  category={self.category!r},\n"
            f"{prefix}  is_float={self.is_float},\n"
            f"{prefix}  op_size={self.op_size!r},\n"
            f"{prefix}  op_type={self.op_type!r},\n"
            f"{prefix}  signed={self.signed!r},\n"
            f"{prefix}  flags_read={self.flags_read!r},\n"
            f"{prefix}  flags_write={self.flags_write!r},\n"
            f"{prefix}  condition={self.condition!r},\n"
            f"{prefix}  jump_kind={self.jump_kind!r},\n"
            f"{prefix}  text={self.text!r},\n"
            f"{prefix}  reads=[\n{reads_str}\n{prefix}  ],\n"
            f"{prefix}  writes=[\n{writes_str}\n{prefix}  ],\n"
            f"{prefix}  calls=[\n{calls_str}\n{prefix}  ],\n"
            f"{prefix}  jump_targets={self.jump_targets},\n"
            f"{prefix}  is_conditional={self.is_conditional},\n"
            f"{prefix}  fallthrough_block={self.fallthrough_block}\n"
            f"{prefix})"
        )


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
class BlockInfo:
    """基本块信息"""
    block_id: int = 0
    start_ea: int = 0
    end_ea: int = 0
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return (
            f"{prefix}BlockInfo(\n"
            f"{prefix}  block_id={self.block_id},\n"
            f"{prefix}  start_ea={hex(self.start_ea)},\n"
            f"{prefix}  end_ea={hex(self.end_ea)},\n"
            f"{prefix}  predecessors={self.predecessors},\n"
            f"{prefix}  successors={self.successors}\n"
            f"{prefix})"
        )


@dataclass
class FuncInfo:
    """函数分析结果 (analyze_function 返回类型)"""
    function: str = ""
    ea: str = ""
    maturity: int = 0
    args: list = field(default_factory=list)
    return_vars: list = field(default_factory=list)
    insns: list = field(default_factory=list)
    cfg_blocks: Dict[int, BlockInfo] = field(default_factory=dict)
    entry_block: int = 0
    exit_blocks: List[int] = field(default_factory=list)

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        args_str = ",\n".join(a.to_string(indent + 1) for a in self.args) if self.args else ""
        insns_str = ",\n".join(i.to_string(indent + 1) for i in self.insns) if self.insns else ""
        cfg_str = ",\n".join(b.to_string(indent + 1) for b in self.cfg_blocks.values()) if self.cfg_blocks else ""
        return (
            f"{prefix}FuncInfo(\n"
            f"{prefix}  function={self.function!r},\n"
            f"{prefix}  ea={self.ea!r},\n"
            f"{prefix}  maturity={self.maturity},\n"
            f"{prefix}  args=[\n{args_str}\n{prefix}  ],\n"
            f"{prefix}  return_vars={self.return_vars},\n"
            f"{prefix}  insns=[\n{insns_str}\n{prefix}  ],\n"
            f"{prefix}  cfg_blocks={{\n{cfg_str}\n{prefix}  }},\n"
            f"{prefix}  entry_block={self.entry_block},\n"
            f"{prefix}  exit_blocks={self.exit_blocks}\n"
            f"{prefix})"
        )


__all__ = [
    "AttrType",
    "OperandAttr",
    "RegisterAttr",
    "LocalVarAttr",
    "StackAttr",
    "GlobalAttr",
    "ImmediateAttr",
    "StringAttr",
    "AddressAttr",
    "LoadAttr",
    "StoreAttr",
    "BlockAttr",
    "HelperFuncAttr",
    "FloatImmediateAttr",
    "CastAttr",
    "ExpressionAttr",
    "OperandAttrList",
    "OperandInfo",
    "CallInfo",
    "InsnInfo",
    "ArgInfo",
    "BlockInfo",
    "FuncInfo",
]

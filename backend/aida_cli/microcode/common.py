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
from typing import Union, Optional


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
    EXPRESSION = "expression"


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
    value: int

    @property
    def attr_type(self) -> str:
        return AttrType.IMMEDIATE

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        return f"{prefix}ImmediateAttr(value={self.value})"


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

    @property
    def attr_type(self) -> str:
        return AttrType.ADDRESS

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        inner_dump = self.inner.to_string(indent + 1)
        return f"{prefix}AddressAttr(\n{prefix}  inner={inner_dump}\n{prefix})"


@dataclass(frozen=True, eq=True)
class LoadAttr(OperandAttr):
    """内存解引用属性 (load ptr)"""
    ptr: OperandAttr

    @property
    def attr_type(self) -> str:
        return AttrType.LOAD

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        ptr_dump = self.ptr.to_string(indent + 1)
        return f"{prefix}LoadAttr(\n{prefix}  ptr={ptr_dump}\n{prefix})"


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
    ExpressionAttr,
]


@dataclass
class OperandInfo:
    """指令操作数 (reads/writes 列表元素)"""
    role: str = ""
    attr: Optional[OperandAttr] = None
    text: str = ""
    access_mode: Optional[str] = None

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        loc = self.attr.to_string(indent + 1) if self.attr else "None"
        return f"{prefix}OperandInfo(\n{prefix}  role={self.role!r},\n{prefix}  attr={loc},\n{prefix}  text={self.text!r},\n{prefix}  access_mode={self.access_mode!r}\n{prefix})"


@dataclass
class CallInfo:
    """函数调用信息 (calls 列表元素)"""
    kind: str = ""
    callee_name: Optional[str] = None
    target: Optional[OperandAttr] = None
    args: list = field(default_factory=list)
    ret: Optional[OperandAttr] = None

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
    ea: str = ""
    opcode: str = ""
    text: str = ""
    reads: list = field(default_factory=list)
    writes: list = field(default_factory=list)
    calls: list = field(default_factory=list)

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
    """函数分析结果 (analyze_function 返回类型)"""
    function: str = ""
    ea: str = ""
    maturity: int = 0
    args: list = field(default_factory=list)
    return_vars: list = field(default_factory=list)
    insns: list = field(default_factory=list)

    def to_string(self, indent: int = 0) -> str:
        prefix = "  " * indent
        args_str = ",\n".join(a.to_string(indent + 1) for a in self.args) if self.args else ""
        insns_str = ",\n".join(i.to_string(indent + 1) for i in self.insns) if self.insns else ""
        return f"{prefix}FuncInfo(\n{prefix}  function={self.function!r},\n{prefix}  ea={self.ea!r},\n{prefix}  maturity={self.maturity},\n{prefix}  args=[\n{args_str}\n{prefix}  ],\n{prefix}  return_vars={self.return_vars},\n{prefix}  insns=[\n{insns_str}\n{prefix}  ]\n{prefix})"


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
    "ExpressionAttr",
    "OperandAttrList",
    "OperandInfo",
    "CallInfo",
    "InsnInfo",
    "ArgInfo",
    "FuncInfo",
]

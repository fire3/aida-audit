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

    替代字符串 key，提供类型安全的访问接口。
    """

    @property
    @abstractmethod
    def attr_type(self) -> str:
        pass

    @abstractmethod
    def to_key(self) -> str:
        """转换为字符串键 (兼容旧接口)"""
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

    def to_key(self) -> str:
        return f"reg:{self.reg_id}"

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

    def to_key(self) -> str:
        return f"lvar:{self.lvar_idx}"

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

    def to_key(self) -> str:
        return f"stack:{self.offset}"

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

    def to_key(self) -> str:
        return f"global:{hex(self.ea)}"

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

    def to_key(self) -> str:
        return f"imm:{self.value}"

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

    def to_key(self) -> str:
        return f"str:{self.value}"

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

    def to_key(self) -> str:
        return f"addr:{self.inner.to_key()}"

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

    def to_key(self) -> str:
        return f"load:{self.ptr.to_key()}"

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

    def to_key(self) -> str:
        return f"expr:{self.expr}"

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


class MicroCodeUtils:
    """Microcode 工具集合，输出规范：
    - mop_entry 返回 {"key": str, "text": str, "ea": int?}
    - mop_key/op_key 返回用于污点跟踪的字符串键或 None
    """
    def is_arg_list(self, mop):
        if ida_hexrays is None:
            return False
        return mop is not None and getattr(mop, "t", None) == ida_hexrays.mop_f

    def is_none_mop(self, mop):
        if ida_hexrays is None:
            return mop is None
        return mop is None or getattr(mop, "t", None) == ida_hexrays.mop_z

    def select_call_operands(self, l, r, d):
        arg_list_mop = None
        if self.is_arg_list(r):
            arg_list_mop = r
        elif self.is_arg_list(d):
            arg_list_mop = d
        elif self.is_arg_list(l):
            arg_list_mop = l

        callee = l
        if self.is_none_mop(callee) or self.is_arg_list(callee):
            if r is not None and not self.is_arg_list(r):
                callee = r
            elif d is not None and not self.is_arg_list(d):
                callee = d

        ret_mop = d
        if self.is_none_mop(ret_mop) or ret_mop == arg_list_mop or ret_mop == callee:
            if r is not None and r != arg_list_mop and r != callee and not self.is_none_mop(r):
                ret_mop = r
            elif l is not None and l != arg_list_mop and l != callee and not self.is_none_mop(l):
                ret_mop = l
            else:
                ret_mop = None

        return callee, arg_list_mop, ret_mop

    def iter_call_args(self, obj):
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

    def normalize_call_arg(self, arg):
        if arg is None:
            return None
        if hasattr(arg, "mop"):
            return self.mop_entry(arg.mop)
        if hasattr(arg, "arg"):
            return self.mop_entry(arg.arg)
        return self.mop_entry(arg)

    def get_opcode_name(self, opcode):
        if ida_hexrays and hasattr(ida_hexrays, "get_mcode_name"):
            return ida_hexrays.get_mcode_name(opcode)
        return f"op_{opcode}"

    def is_call_opcode(self, opcode):
        if ida_hexrays is None:
            return False
        calls = []
        if hasattr(ida_hexrays, "m_call"):
            calls.append(ida_hexrays.m_call)
        if hasattr(ida_hexrays, "m_icall"):
            calls.append(ida_hexrays.m_icall)
        if opcode in calls:
            return True
        opcode_name = self.get_opcode_name(opcode)
        if "call" in opcode_name.lower():
            return True
        # Also check for common call patterns on different architectures
        # arm64 might use different opcode values
        if opcode in [0x56, 0x44, 0x6D]:  # Common call opcodes on some architectures
            return True
        return False

    def safe_dstr(self, obj):
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

    def to_int(self, x):
        try:
            if x is None:
                return None
            return int(x)
        except Exception:
            return None

    def mop_entry(self, mop):
        """返回 OperandAttr 而非 OpInfo (新接口)"""
        return self.mop_to_attr(mop)

    def mop_entry_legacy(self, mop):
        """旧接口: 返回 dict (兼容)"""
        key = self.mop_key(mop)
        if key is None:
            return None
        res = {"key": key, "text": self.safe_dstr(mop)}
        if mop and ida_hexrays:
            t = getattr(mop, "t", None)
            if t == ida_hexrays.mop_v:
                g = getattr(mop, "g", None)
                if g:
                    res["ea"] = self.to_int(getattr(g, "ea", None))
            elif t == ida_hexrays.mop_h:
                helper = getattr(mop, "helper", None)
                if helper:
                    ea = self.resolve_name_ea(helper)
                    if ea is not None:
                        res["ea"] = ea
        return res

    def op_key(self, op):
        """获取操作数字符串 key，兼容新旧接口"""
        if not op:
            return None
        if isinstance(op, OperandAttr):
            return op.to_key()
        if hasattr(op, "location") and op.location:
            return op.location.to_key()
        if hasattr(op, "key"):
            return op.key or None
        if isinstance(op, dict):
            key = op.get("key")
            if key:
                return key
            text = op.get("text")
            return text or None
        return None

    def is_move_opcode(self, opcode):
        return opcode in ("op_4", "mov")

    def is_store_opcode(self, opcode):
        return opcode in ("op_1", "stx")

    def is_addr_key(self, key):
        return bool(key) and key.startswith("addr:")

    def strip_addr_key(self, key):
        if not self.is_addr_key(key):
            return None
        return key[5:]

    def resolve_name_ea(self, name):
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

    def resolve_callsite_ea(self, insn_ea):
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

    def ensure_callee_ea(self, insn, callee):
        callee_ea = None
        callee_name = None
        if callee:
            if hasattr(callee, "ea"):
                callee_ea = callee.ea
                callee_name = callee.text if hasattr(callee, "text") else None
            elif isinstance(callee, dict):
                callee_ea = callee.get("ea")
                callee_name = callee.get("text")
        if callee_ea is None and callee_name:
            callee_ea = self.resolve_name_ea(callee_name)
        if callee_ea is None:
            callee_ea = self.resolve_callsite_ea(getattr(insn, "ea", None))
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
        return callee, callee_name

    def mop_key(self, mop):
        if mop is None or ida_hexrays is None:
            return None
        t = getattr(mop, "t", None)
        if t == ida_hexrays.mop_r:
            reg_id = self.to_int(getattr(mop, "r", None))
            return f"reg:{reg_id}"
        if t == ida_hexrays.mop_l:
            lv = getattr(mop, "l", None)
            idx = self.to_int(getattr(lv, "idx", None)) if lv is not None else None
            return f"lvar:{idx}"
        if t == ida_hexrays.mop_S:
            sv = getattr(mop, "s", None)
            if sv is None:
                sv = getattr(mop, "sv", None)
            off = self.to_int(getattr(sv, "off", None)) if sv is not None else None
            return f"stack:{off}"
        if t == ida_hexrays.mop_v:
            g = getattr(mop, "g", None)
            ea = self.to_int(getattr(g, "ea", None)) if g is not None else None
            return f"global:{ea}"
        if t == ida_hexrays.mop_a:
            a = getattr(mop, "a", None)
            inner = self.mop_key(a)
            return f"addr:{inner}" if inner else f"addr:{self.safe_dstr(mop)}"
        if t == ida_hexrays.mop_n:
            n = getattr(mop, "n", None)
            value = self.to_int(getattr(n, "value", None)) if n is not None else None
            return f"const:{value}"
        if t == ida_hexrays.mop_str:
            return f"str:{self.safe_dstr(mop)}"

        if t == ida_hexrays.mop_d:
            insn = getattr(mop, "d", None)
            if insn:
                if insn.opcode == ida_hexrays.m_add:
                    def is_var(k):
                        return k and (k.startswith("lvar:") or k.startswith("reg:") or k.startswith("addr:"))

                    l_key = self.mop_key(insn.l)
                    r_key = self.mop_key(insn.r)

                    if is_var(l_key):
                        return l_key
                    if is_var(r_key):
                        return r_key

                if hasattr(ida_hexrays, "m_ldx") and insn.opcode == ida_hexrays.m_ldx:
                    addr_key = self.mop_key(insn.r)
                    if addr_key:
                        return f"load:{addr_key}"

        return f"expr:{self.safe_dstr(mop)}"

    def _get_func_name_from_helper(self, helper: str) -> Optional[str]:
        """从 helper 名称获取真实函数名，去除 $_ 前缀"""
        if not helper:
            return None
        if helper.startswith("$_"):
            return helper[2:]
        if helper.startswith("$"):
            return None
        return helper

    def mop_to_attr(self, mop) -> Optional[OperandAttr]:
        """将 mop 转换为 OperandAttr (ADT 模式)"""
        if mop is None or ida_hexrays is None:
            return None

        t = getattr(mop, "t", None)

        if t == ida_hexrays.mop_z:
            return None

        if t == ida_hexrays.mop_r:
            reg_id = self.to_int(getattr(mop, "r", None))
            return RegisterAttr(reg_id=reg_id) if reg_id is not None else ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_l:
            lv = getattr(mop, "l", None)
            idx = self.to_int(getattr(lv, "idx", None)) if lv is not None else None
            if idx is not None:
                return LocalVarAttr(lvar_idx=idx)
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_S:
            sv = getattr(mop, "s", None)
            if sv is None:
                sv = getattr(mop, "sv", None)
            off = self.to_int(getattr(sv, "off", None)) if sv is not None else None
            if off is not None:
                return StackAttr(offset=off)
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_v:
            g = getattr(mop, "g", None)
            ea = self.to_int(getattr(g, "ea", None)) if g is not None else None
            if ea is not None:
                return GlobalAttr(ea=ea)
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_a:
            a = getattr(mop, "a", None)
            inner = self.mop_to_attr(a)
            if inner:
                return AddressAttr(inner=inner)
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_n:
            n = getattr(mop, "n", None)
            value = self.to_int(getattr(n, "value", None)) if n is not None else None
            
            # If standard value extraction failed, try parsing from string representation
            if value is None:
                text = self.safe_dstr(mop)
                if text and "#" in text:
                    import re
                    # Match #<value>.<size> or #<value>
                    match = re.search(r'#((?:0x)?[0-9a-fA-F]+)', text)
                    if match:
                        try:
                            value = int(match.group(1), 0)
                        except ValueError:
                            pass

            if value is not None:
                return ImmediateAttr(value=value)
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_str:
            text = self.safe_dstr(mop)
            if text and text.startswith('"') and text.endswith('"'):
                return StringAttr(value=text.strip('"'))
            return StringAttr(value=text)
            
        if t == ida_hexrays.mop_h:
            helper = getattr(mop, "helper", None)
            if helper:
                func_name = self._get_func_name_from_helper(helper)
                if func_name:
                    return ExpressionAttr(expr=func_name)
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_d:
            insn = getattr(mop, "d", None)
            if insn:
                # Arithmetic: add, sub (return the variable part)
                if insn.opcode in (ida_hexrays.m_add, ida_hexrays.m_sub):
                    l_loc = self.mop_to_attr(insn.l)
                    r_loc = self.mop_to_attr(insn.r)
                    if l_loc and l_loc.attr_type != AttrType.IMMEDIATE:
                        return l_loc
                    if r_loc and r_loc.attr_type != AttrType.IMMEDIATE:
                        return r_loc

                if hasattr(ida_hexrays, "m_ldx") and insn.opcode == ida_hexrays.m_ldx:
                    addr_key = self.mop_to_attr(insn.r)
                    if addr_key:
                        return LoadAttr(ptr=addr_key)

        return ExpressionAttr(expr=self.safe_dstr(mop))


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
    "MicroCodeUtils",
]

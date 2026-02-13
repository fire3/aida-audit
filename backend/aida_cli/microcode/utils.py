from .constants import ida_hexrays
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
    BlockAttr,
    HelperFuncAttr,
    ExpressionAttr,
    AttrType,
)
from typing import Optional
import re


class MicroCodeUtils:
    """Microcode 工具集合"""

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

    def extract_arg_mop(self, arg_wrapper):
        if arg_wrapper is None:
            return None
        if hasattr(arg_wrapper, "arg"):
            return arg_wrapper.arg
        if hasattr(arg_wrapper, "mop"):
            return arg_wrapper.mop
        if hasattr(arg_wrapper, "t"):
            return arg_wrapper
        return None

    def get_opcode_name(self, opcode):
        if ida_hexrays and hasattr(ida_hexrays, "get_mcode_name"):
            return ida_hexrays.get_mcode_name(opcode)
        return f"op_{opcode}"

    def get_effective_opcode_name(self, opcode, insn=None, text=None):
        name = self.get_opcode_name(opcode)
        if name and not name.startswith("op_"):
            return name
        if text is None and insn is not None:
            text = self.safe_dstr(insn)
        if text:
            parts = text.strip().split()
            if parts:
                token = parts[0].strip().lower()
                if token:
                    return token
        return name

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
        if opcode in [0x56, 0x44, 0x6D]:
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

    def is_move_opcode(self, opcode):
        return opcode in ("op_4", "mov")

    def is_store_opcode(self, opcode):
        return opcode in ("op_1", "stx")

    def get_opcode_category(self, opcode_name: str) -> str:
        name = (opcode_name or "").lower()
        if not name:
            return ""
        if "call" in name:
            return "call"
        if name in ("jmp", "goto"):
            return "jump"
        if name.startswith("j"):
            return "branch"
        if name in ("mov", "xdu", "xds", "cast"):
            return "move"
        if name in ("ldx", "stx", "ld", "st"):
            return "memory"
        if name in ("and", "or", "xor", "not", "test", "tst"):
            return "logic"
        if name in ("add", "sub", "mul", "div", "mod", "neg", "udiv", "sdiv", "umod", "smod", "shl", "shr", "sar", "rol", "ror", "udiv", "sdiv", "umul", "smul", "udivmod", "sdivmod"):
            return "arith"
        if name in ("fadd", "fsub", "fmul", "fdiv", "fneg", "f2i", "i2f", "f2f", "fcmp", "f2u", "u2f", "ftoi", "itof", "fptosi", "fptoui"):
            return "float"
        if name.startswith("v") and any(k in name for k in ("add", "sub", "mul", "div", "mov", "shl", "shr", "and", "or", "xor", "cmp")):
            return "vector"
        if name in ("cmp", "tst", "set", "sets", "setb", "seta", "setz", "setnz"):
            return "cmp"
        if name in ("ret", "leave"):
            return "ret"
        if name.startswith("f"):
            return "float"
        return ""

    def is_float_opcode(self, opcode_name: str) -> bool:
        return self.get_opcode_category(opcode_name) == "float"

    def get_opcode_type(self, opcode_name: str) -> str:
        category = self.get_opcode_category(opcode_name)
        if category in ("float",):
            return "float"
        if category in ("memory", "call"):
            return "ptr"
        if category in ("vector",):
            return "vector"
        return "int"

    def get_opcode_signed_hint(self, opcode_name: str) -> Optional[bool]:
        name = (opcode_name or "").lower()
        if any(k in name for k in ("sdiv", "smul", "smod", "sar", "setl", "setle", "jlt", "jle")):
            return True
        if any(k in name for k in ("udiv", "umul", "umod", "shr", "setb", "setbe", "ja", "jae")):
            return False
        return None

    def _get_func_name_from_helper(self, helper: str) -> Optional[str]:
        """从 helper 名称获取真实函数名，去除 $_ 前缀"""
        if not helper:
            return None
        if helper.startswith("$_"):
            return helper[2:]
        if helper.startswith("$"):
            return None
        return helper

    def mop_entry(self, mop):
        """返回 OperandAttr (新接口)"""
        return self.mop_to_attr(mop)

    def mop_to_attr(self, mop) -> Optional[OperandAttr]:
        """将 mop 转换为 OperandAttr (ADT 模式)"""
        if mop is None or ida_hexrays is None:
            return None

        t = getattr(mop, "t", None)

        if t == ida_hexrays.mop_z:
            return None

        if t == ida_hexrays.mop_r:
            reg_id = self._to_int(getattr(mop, "r", None))
            return RegisterAttr(reg_id=reg_id) if reg_id is not None else ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_l:
            lv = getattr(mop, "l", None)
            idx = self._to_int(getattr(lv, "idx", None)) if lv is not None else None
            if idx is not None:
                return LocalVarAttr(lvar_idx=idx)
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_S:
            sv = getattr(mop, "s", None)
            if sv is None:
                sv = getattr(mop, "sv", None)
            off = self._to_int(getattr(sv, "off", None)) if sv is not None else None
            if off is not None:
                return StackAttr(offset=off)
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_v:
            g = getattr(mop, "g", None)
            ea = self._to_int(getattr(g, "ea", None)) if g is not None else None
            text = self.safe_dstr(mop)
            if ea is not None:
                return GlobalAttr(ea=ea)
            if text and text.startswith("$"):
                return HelperFuncAttr(name=text)
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_a:
            a = getattr(mop, "a", None)
            inner = self.mop_to_attr(a)
            if inner:
                text = self.safe_dstr(mop)
                offset = None
                if text and text.startswith("&"):
                    addr_part = text[1:]
                    if addr_part.endswith(".8") or addr_part.endswith(".4") or addr_part.endswith(".2") or addr_part.endswith(".1"):
                        addr_part = addr_part.rsplit(".", 1)[0]
                    return AddressAttr(inner=inner, base=inner, offset=offset)
                return AddressAttr(inner=inner, base=inner, offset=None)
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_n:
            n = getattr(mop, "n", None)
            value = self._to_int(getattr(n, "value", None)) if n is not None else None
            
            if value is None:
                text = self.safe_dstr(mop)
                if text and "#" in text:
                    match = re.search(r'#((?:0x)?[0-9a-fA-F]+)', text)
                    if match:
                        try:
                            value = int(match.group(1), 0)
                        except ValueError:
                            pass

            if value is not None:
                return ImmediateAttr(value=value, raw=value, text=self.safe_dstr(mop))
            fvalue = self._parse_float_from_text(self.safe_dstr(mop))
            if fvalue is not None:
                return ImmediateAttr(fvalue=fvalue, text=self.safe_dstr(mop))
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t in (getattr(ida_hexrays, "mop_c", None), getattr(ida_hexrays, "mop_sc", None)):
            raw = getattr(mop, "value", None)
            value = self._to_int(raw)
            if value is None:
                value = self._to_int(getattr(getattr(mop, "c", None), "value", None))
            text = self.safe_dstr(mop)
            if value is not None:
                return ImmediateAttr(value=value, raw=value, text=text)
            fvalue = self._parse_float_from_text(text)
            if fvalue is not None:
                return ImmediateAttr(fvalue=fvalue, text=text)
            return ExpressionAttr(expr=text)

        if t == ida_hexrays.mop_str:
            text = self.safe_dstr(mop)
            if text and text.startswith('"') and text.endswith('"'):
                return StringAttr(value=text.strip('"'))
            return StringAttr(value=text)
            
        if t == ida_hexrays.mop_h:
            helper = getattr(mop, "helper", None)
            text = self.safe_dstr(mop)
            if helper:
                func_name = self._get_func_name_from_helper(helper)
                if func_name:
                    return HelperFuncAttr(name=func_name)
            if text and text.startswith("$"):
                clean_name = text.lstrip("$")
                if clean_name:
                    return HelperFuncAttr(name=clean_name)
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == getattr(ida_hexrays, "mop_b", None):
            block_id = None
            b = getattr(mop, "b", None)
            if b is not None:
                block_id = self._to_int(getattr(b, "serial", None))
                if block_id is None:
                    block_id = self._to_int(getattr(b, "id", None))
                if block_id is None:
                    block_id = self._to_int(getattr(b, "block_id", None))
            if block_id is None:
                block_id = self._to_int(getattr(mop, "block_id", None))
            if block_id is not None:
                return BlockAttr(block_id=block_id)
            text = self.safe_dstr(mop)
            if text and text.startswith("@"):
                try:
                    block_id = int(text[1:])
                    if block_id is not None:
                        return BlockAttr(block_id=block_id)
                except ValueError:
                    pass
            return ExpressionAttr(expr=self.safe_dstr(mop))

        if t == ida_hexrays.mop_d:
            insn = getattr(mop, "d", None)
            if insn:
                if insn.opcode in (ida_hexrays.m_add, ida_hexrays.m_sub):
                    l_loc = self.mop_to_attr(insn.l)
                    r_loc = self.mop_to_attr(insn.r)
                    if l_loc and r_loc:
                        if l_loc.attr_type != AttrType.IMMEDIATE and r_loc.attr_type == AttrType.IMMEDIATE:
                            offset = self._normalize_offset(r_loc, insn.opcode)
                            return AddressAttr(inner=l_loc, base=l_loc, offset=offset)
                        if r_loc.attr_type != AttrType.IMMEDIATE and l_loc.attr_type == AttrType.IMMEDIATE:
                            offset = self._normalize_offset(l_loc, insn.opcode)
                            return AddressAttr(inner=r_loc, base=r_loc, offset=offset)
                    if l_loc and l_loc.attr_type != AttrType.IMMEDIATE:
                        return l_loc
                    if r_loc and r_loc.attr_type != AttrType.IMMEDIATE:
                        return r_loc

                if hasattr(ida_hexrays, "m_ldx") and insn.opcode == ida_hexrays.m_ldx:
                    addr_key = self.mop_to_attr(insn.r)
                    if addr_key:
                        mem_size = getattr(insn, "size", None)
                        try:
                            if mem_size is not None:
                                mem_size = int(mem_size)
                        except Exception:
                            mem_size = None
                        return LoadAttr(ptr=addr_key, mem_size=mem_size)

        return ExpressionAttr(expr=self.safe_dstr(mop))

    def _to_int(self, x) -> Optional[int]:
        """内部使用的整数转换"""
        try:
            if x is None:
                return None
            return int(x)
        except Exception:
            return None

    def _parse_float_from_text(self, text: Optional[str]) -> Optional[float]:
        if not text:
            return None
        s = text.strip()
        match = re.search(r'[-+]?(?:\d+\.\d+|\d+\.)(?:[eE][-+]?\d+)?', s)
        if not match:
            match = re.search(r'[-+]?\d+(?:[eE][-+]?\d+)', s)
        if not match:
            return None
        try:
            return float(match.group(0))
        except Exception:
            return None

    def _normalize_offset(self, attr: OperandAttr, opcode) -> OperandAttr:
        if not isinstance(attr, ImmediateAttr):
            return attr
        value = attr.value
        if value is None:
            return attr
        try:
            if ida_hexrays and hasattr(ida_hexrays, "m_sub") and opcode == ida_hexrays.m_sub:
                value = -value
        except Exception:
            pass
        return ImmediateAttr(value=value, raw=attr.raw, text=attr.text)


__all__ = ["MicroCodeUtils"]

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

    def _to_int(self, x) -> Optional[int]:
        """内部使用的整数转换"""
        try:
            if x is None:
                return None
            return int(x)
        except Exception:
            return None


__all__ = ["MicroCodeUtils"]
from .constants import (
    ida_hexrays,
    idc,
    ida_funcs,
    idautils,
    ida_idaapi,
    BADADDR,
)


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
        return "call" in self.get_opcode_name(opcode).lower()

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
        if not op:
            return None
        key = op.get("key")
        if key:
            return key
        text = op.get("text")
        return text or None

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
            if callee is None:
                callee = {"key": f"callee:{callee_ea}", "text": callee_name, "ea": callee_ea}
            else:
                callee["ea"] = callee_ea
                if callee_name:
                    callee["text"] = callee_name
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

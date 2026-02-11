try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

try:
    import idc
except ImportError:
    idc = None

try:
    import ida_funcs
except ImportError:
    ida_funcs = None

try:
    import idautils
except ImportError:
    idautils = None

try:
    import ida_idaapi
except ImportError:
    ida_idaapi = None

try:
    import ida_auto
except ImportError:
    ida_auto = None

try:
    import ida_pro
except ImportError:
    ida_pro = None

try:
    import ida_ida
except ImportError:
    ida_ida = None

try:
    import ida_nalt
except ImportError:
    ida_nalt = None

try:
    import ida_gdl
except ImportError:
    ida_gdl = None

try:
    import ida_xref
except ImportError:
    ida_xref = None


def get_badaddr():
    if ida_idaapi and hasattr(ida_idaapi, "BADADDR"):
        return ida_idaapi.BADADDR
    if idc and hasattr(idc, "BADADDR"):
        return idc.BADADDR
    return 0xFFFFFFFFFFFFFFFF

BADADDR = get_badaddr()
"""
Microcode taint analysis module for IDA Pro.
"""

import json
import sys
import logging
from collections import deque

try:
    import idapro
except ImportError:
    idapro = None

try:
    import ida_auto
    import ida_pro
    import ida_ida
    import idc
    import ida_nalt
    import ida_hexrays
    import ida_funcs
    import idautils
    import ida_gdl
    import ida_idaapi
except ImportError as e:
    logging.getLogger(__name__).warning("Failed to import main IDA modules: %s", e)
    ida_auto = None
    ida_pro = None
    ida_ida = None
    idc = None
    ida_nalt = None
    ida_hexrays = None
    ida_funcs = None
    idautils = None
    ida_gdl = None
    ida_idaapi = None


def get_badaddr():
    if ida_idaapi and hasattr(ida_idaapi, "BADADDR"):
        return ida_idaapi.BADADDR
    if idc and hasattr(idc, "BADADDR"):
        return idc.BADADDR
    return 0xFFFFFFFFFFFFFFFF

BADADDR = get_badaddr()

try:
    import ida_xref
except ImportError:
    ida_xref = None

from .analyzer import (
    MicrocodeAnalyzer,
    MopUsageVisitor,
    analyze_function,
)

from .state import TaintState
from .engine import MicrocodeTaintEngine

__all__ = [
    "BADADDR",
    "idapro",
    "ida_auto",
    "ida_pro",
    "ida_ida",
    "idc",
    "ida_nalt",
    "ida_hexrays",
    "ida_funcs",
    "idautils",
    "ida_gdl",
    "ida_idaapi",
    "ida_xref",
    "MicrocodeAnalyzer",
    "MopUsageVisitor",
    "analyze_function",
    "TaintState",
    "MicrocodeTaintEngine",
]

from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Optional, Set, Dict, List, FrozenSet, Tuple, Deque
from copy import deepcopy

from .state import TaintState, TaintOrigin, TaintEntry
from .microcode_analyzer import analyze_function
from .utils import MicroCodeUtils
from .common import (
    LocalVarAttr,
    StackAttr,
    AddressAttr,
    LoadAttr,
    StoreAttr,
    RegisterAttr,
    ImmediateAttr,
    StringAttr,
    OperandAttr,
    InsnInfo,
    CallInfo,
    FuncInfo,
)
from .constants import (
    idc,
    ida_funcs,
    idautils,
    BADADDR,
    ida_hexrays,
)
from ..pathfinder import PathFinder, PathFinderConfig
from .interproc_datatypes import (
    WorkItem,
    Block,
    CFG,
    AliasChange,
    TaintPolicy,
    Finding,
    CallEdge,
    FunctionContext,
    InterProcState,
    CrossFuncRule,
)


class SimpleLogger:
    def __init__(self, verbose=False):
        import logging
        self._logger = logging.getLogger("FixedPointTaintEngine")
        self._verbose = verbose
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.DEBUG)

    def log(self, message):
        if self._verbose:
            self._logger.info(message)
        else:
            self._logger.debug(message)

    def debug(self, message):
        self._logger.debug(message)

    def info(self, message):
        self._logger.info(message)

    def warn(self, message):
        self._logger.warning(message)

    def error(self, message):
        self._logger.error(message)


def _log_info(logger, message):
    if hasattr(logger, "info"):
        logger.info(message)
    else:
        logger.log(message)


__all__ = ["SimpleLogger", "_log_info"]
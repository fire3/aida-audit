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
)
from .interproc_datatypes import AliasChange
from .logger import SimpleLogger


class AliasAnalyzer:
    def __init__(self, state, utils, logger):
        self.state = state
        self.utils = utils
        self.logger = logger

    def analyze(self, insn):
        changes = []

        if self.utils.is_move_opcode(insn.opcode):
            changes.extend(self._handle_move(insn))

        if self._is_address_taken(insn):
            changes.extend(self._handle_address_taken(insn))

        if self._is_load(insn):
            changes.extend(self._handle_load(insn))

        if self._is_store(insn):
            changes.extend(self._handle_store(insn))

        return changes

    def _handle_move(self, insn):
        changes = []
        if not insn.reads or not insn.writes:
            return changes

        src = insn.reads[0].attr
        dst = insn.writes[0].attr

        if src is None or dst is None:
            return changes

        address_src = None
        for read in insn.reads:
            if isinstance(read.attr, AddressAttr):
                address_src = read.attr
                break
        if address_src is not None:
            if self.state.add_alias(dst, address_src.inner):
                changes.append(AliasChange(dst, address_src.inner, "mov_address"))
                self.logger.log(f"[ALIAS] {dst} -> {address_src.inner}")

        if isinstance(dst, LoadAttr):
            if self.state.add_alias(dst, src):
                changes.append(AliasChange(dst, src, "mov_load"))
                self.logger.log(f"[ALIAS] {dst} -> {src}")

        return changes

    def _is_address_taken(self, insn):
        if not insn.writes:
            return False
        write = insn.writes[0]
        if write.attr and isinstance(write.attr, AddressAttr):
            return True
        return False

    def _handle_address_taken(self, insn):
        changes = []
        if len(insn.reads) != 1 or len(insn.writes) != 1:
            return changes

        src = insn.reads[0].attr
        dst = insn.writes[0].attr

        if src is None or dst is None:
            return changes

        if isinstance(dst, AddressAttr):
            if self.state.add_alias(dst.inner, src):
                changes.append(AliasChange(dst.inner, src, "address_taken"))
                self.logger.log(f"[ALIAS] &{src} -> {dst.inner}")

        return changes

    def _is_load(self, insn):
        return insn.opcode in ("mov", "op_4") and len(insn.reads) >= 1

    def _handle_load(self, insn):
        changes = []
        if not insn.reads or not insn.writes:
            return changes

        read_attr = None
        for read in insn.reads:
            if isinstance(read.attr, LoadAttr):
                read_attr = read.attr
                break
        write_attr = insn.writes[0].attr
        if read_attr is None or write_attr is None:
            return changes

        if isinstance(read_attr, LoadAttr):
            ptr = read_attr.ptr
            while isinstance(ptr, LoadAttr):
                ptr = ptr.ptr
            target = None
            if isinstance(ptr, AddressAttr):
                target = ptr.inner
            elif ptr in self.state.aliases:
                target = self.state.aliases[ptr]
            if target is not None and self.state.add_alias(write_attr, target):
                changes.append(AliasChange(write_attr, target, "load"))
                self.logger.log(f"[ALIAS] {write_attr} -> {target}")
        return changes

    def _is_store(self, insn):
        return self.utils.is_store_opcode(insn.opcode)

    def _handle_store(self, insn):
        changes = []
        if len(insn.writes) != 1:
            return changes
        write_attr = insn.writes[0].attr
        if not isinstance(write_attr, StoreAttr):
            return changes
        ptr = write_attr.ptr
        value = write_attr.value
        if ptr is None or value is None:
            return changes
        target = value.inner if isinstance(value, AddressAttr) else value
        if isinstance(target, (ImmediateAttr, StringAttr)):
            return changes
        ptr_candidates = [ptr]
        if isinstance(ptr, AddressAttr):
            ptr_candidates.append(ptr.inner)
        for candidate in ptr_candidates:
            if candidate is None:
                continue
            if self.state.add_alias(candidate, target):
                changes.append(AliasChange(candidate, target, "store"))
                self.logger.log(f"[ALIAS] {candidate} -> {target}")
            resolved = self.state.aliases.get(candidate)
            if resolved is not None and self.state.add_alias(resolved, target):
                changes.append(AliasChange(resolved, target, "store"))
                self.logger.log(f"[ALIAS] {resolved} -> {target}")
        return changes


__all__ = ["AliasAnalyzer"]
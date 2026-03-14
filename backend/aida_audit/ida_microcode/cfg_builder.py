from collections import defaultdict
from typing import List, Optional

from .common import InsnInfo, FuncInfo
from .interproc_datatypes import CFG, Block
from .logger import SimpleLogger


class CFGBuilder:
    def __init__(self, func_info, logger):
        self.func_info = func_info
        self.logger = logger
        self.cfg = CFG()

    def build(self):
        self._build_blocks()
        self._connect_blocks()
        return self.cfg

    def _build_blocks(self):
        blocks = defaultdict(list)

        for insn in self.func_info.insns:
            block_id = insn.block_id
            blocks[block_id].append(insn)

        for block_id, insns in blocks.items():
            self.cfg.blocks[block_id] = Block(
                block_id=block_id, insns=insns
            )

        if self.func_info.insns:
            first_block = self.func_info.insns[0].block_id
            self.cfg.entry_block = first_block

    def _connect_blocks(self):
        for block_id, block in self.cfg.blocks.items():
            if not block.insns:
                continue

            last_insn = block.insns[-1]

            if self._is_unconditional_jump(last_insn):
                successors = self._get_jump_targets(last_insn)
                block.successors.extend(successors)

            elif self._is_conditional_jump(last_insn):
                successors = self._get_jump_targets(last_insn)
                block.successors.extend(successors)

            else:
                next_block = self._get_next_block(block_id)
                if next_block is not None:
                    block.successors.append(next_block)

        for block_id, block in self.cfg.blocks.items():
            for succ_id in block.successors:
                if succ_id in self.cfg.blocks:
                    self.cfg.blocks[succ_id].predecessors.append(block_id)

        self.cfg.exit_blocks = [
            bid for bid, b in self.cfg.blocks.items()
            if not b.successors
        ]

    def _is_unconditional_jump(self, insn):
        return insn.opcode in ("goto", "jmp")

    def _is_conditional_jump(self, insn):
        return insn.opcode.startswith("j") and insn.opcode not in ("goto", "jmp")

    def _get_jump_targets(self, insn):
        targets = []
        for read in insn.reads:
            if read.attr and hasattr(read.attr, "block_id"):
                targets.append(read.attr.block_id)
        if not targets and insn.jump_targets:
            targets.extend(insn.jump_targets)
        return targets

    def _get_next_block(self, current_block_id):
        block_ids = sorted(self.cfg.blocks.keys())
        try:
            idx = block_ids.index(current_block_id)
            if idx + 1 < len(block_ids):
                return block_ids[idx + 1]
        except ValueError:
            pass
        return None


__all__ = ["CFGBuilder"]
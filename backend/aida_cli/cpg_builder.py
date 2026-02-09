import json
import logging
import networkx as nx
from pathlib import Path
from .model import (
    NODE_PROG, NODE_FUNC, NODE_BLOCK, NODE_INSTR, NODE_CALL, NODE_VAR, NODE_CONST, NODE_STRING, NODE_MEM, NODE_EXPR, NODE_GLOBAL,
    EDGE_HAS_FUNC, EDGE_HAS_BLOCK, EDGE_HAS_INSTR, EDGE_CFG, EDGE_CALL_OF, EDGE_ARG, EDGE_RET, EDGE_DEF, EDGE_USE, EDGE_POINTS_TO
)

logger = logging.getLogger(__name__)

class CPGBuilder:
    def __init__(self, cpg_dir: str):
        self.cpg_dir = Path(cpg_dir)
        self.graph = nx.MultiDiGraph()
        self.func_index = {}  # func_ea -> func_node_id
        self.binary_id = "unknown" # Will be loaded from meta.json
        
    def build(self):
        """Main build process following V1 spec."""
        self._load_meta()
        self._load_functions()
        return self.graph

    def _load_meta(self):
        meta_path = self.cpg_dir / "meta.json"
        if meta_path.exists():
            with open(meta_path, 'r') as f:
                data = json.load(f)
                self.binary_id = data.get("binary_id", "unknown")
                self.graph.add_node("P:0", kind=NODE_PROG, **data)
        else:
            self.graph.add_node("P:0", kind=NODE_PROG)

    def _load_functions(self):
        funcs_path = self.cpg_dir / "functions.jsonl"
        if not funcs_path.exists():
            logger.warning(f"No functions.jsonl found in {self.cpg_dir}")
            return

        with open(funcs_path, 'r') as f:
            for line in f:
                if not line.strip(): continue
                func_data = json.loads(line)
                if func_data.get("status") != "ok":
                    continue
                self._build_function(func_data)

    def _build_function(self, f_data):
        func_ea = f_data["func_ea"]
        func_id = f"F:{func_ea}"
        self.graph.add_node(func_id, kind=NODE_FUNC, name=f_data.get("name"), ea=func_ea)
        self.graph.add_edge("P:0", func_id, type=EDGE_HAS_FUNC)
        
        microcode = f_data.get("microcode", {})
        
        # Build Blocks
        for block in microcode.get("blocks", []):
            block_id = f"B:{func_ea}:{block['block_id']}"
            self.graph.add_node(block_id, kind=NODE_BLOCK, ea=block.get("start_ea"))
            self.graph.add_edge(func_id, block_id, type=EDGE_HAS_BLOCK)
            
        # Build CFG Edges
        for edge in microcode.get("cfg_edges", []):
            src_block_id = f"B:{func_ea}:{edge['src_block_id']}"
            dst_block_id = f"B:{func_ea}:{edge['dst_block_id']}"
            self.graph.add_edge(src_block_id, dst_block_id, type=EDGE_CFG, branch=edge.get("branch"))

        # Build Instructions
        # insns is a flat list in microcode dict
        for insn in microcode.get("insns", []):
            block_id = f"B:{func_ea}:{insn['block_id']}"
            insn_ea = insn.get("ea")
            insn_idx = insn.get("insn_idx", 0)
            insn_id = f"I:{func_ea}:{insn['block_id']}:{insn_idx}"
            
            self.graph.add_node(insn_id, kind=NODE_INSTR, ea=insn_ea, mnemonic=insn.get("text"))
            self.graph.add_edge(block_id, insn_id, type=EDGE_HAS_INSTR, index=insn_idx)
            
            # Handle CallSites (calls is a list)
            if "calls" in insn:
                for call_data in insn["calls"]:
                    self._build_callsite(func_ea, insn_id, call_data, insn_ea)
            
            # Handle Def/Use
            self._build_def_use(func_ea, insn_id, insn)

    def _build_callsite(self, func_ea, insn_id, call_data, insn_ea=None):
        # C:<insn_id>:<index>
        call_idx = call_data.get("index", 0)
        call_id = f"C:{insn_id}:{call_idx}"
        
        # Avoid 'kind' conflict
        attrs = call_data.copy()
        if "kind" in attrs:
            attrs["call_kind"] = attrs.pop("kind")
        
        # Inherit EA from instruction if not present
        if "ea" not in attrs and insn_ea:
            attrs["ea"] = insn_ea
            
        self.graph.add_node(call_id, kind=NODE_CALL, **attrs)
        self.graph.add_edge(call_id, insn_id, type=EDGE_CALL_OF)
        
        # Args
        for i, arg in enumerate(call_data.get("args", [])):
            arg_node = self._intern_operand(func_ea, arg)
            if arg_node:
                self.graph.add_edge(call_id, arg_node, type=EDGE_ARG, index=i)

    def _build_def_use(self, func_ea, insn_id, insn):
        # Reads -> USE
        for i, read_item in enumerate(insn.get("reads", [])):
            op = read_item.get("op")
            if not op: continue
            node = self._intern_operand(func_ea, op)
            if node:
                self.graph.add_edge(insn_id, node, type=EDGE_USE, index=i)
        
        # Writes -> DEF
        for i, write_item in enumerate(insn.get("writes", [])):
            op = write_item.get("op")
            if not op: continue
            node = self._intern_operand(func_ea, op)
            if node:
                self.graph.add_edge(insn_id, node, type=EDGE_DEF, index=i)

    def _intern_operand(self, func_ea, op):
        """
        Create or retrieve a node for an operand.
        Returns node_id.
        """
        kind = op.get("kind")
        if not kind: return None
        
        node_id = None
        
        # Helper to avoid kind conflict
        def get_attrs(op_dict):
            a = op_dict.copy()
            if "kind" in a: a["op_kind"] = a.pop("kind")
            return a
        
        if kind == "reg":
            # V:<func_ea>:reg:<regname>
            reg_name = op.get("v", {}).get("reg")
            if not reg_name: return None
            node_id = f"V:{func_ea}:reg:{reg_name}"
            if node_id not in self.graph:
                self.graph.add_node(node_id, kind=NODE_VAR, var_kind="reg", **get_attrs(op))

        elif kind == "stack":
            # V:<func_ea>:stack:<base>:<off>
            v_info = op.get("v", {})
            base = v_info.get("base")
            off = v_info.get("off")
            if base is None or off is None: return None
            node_id = f"V:{func_ea}:stack:{base}:{off}"
            if node_id not in self.graph:
                self.graph.add_node(node_id, kind=NODE_VAR, var_kind="stack", **get_attrs(op))
                
                # Create MEM node for the stack slot and add POINTS_TO edge
                mem_id = f"M:{func_ea}:stack:{base}:{off}"
                if mem_id not in self.graph:
                    self.graph.add_node(mem_id, kind=NODE_MEM, region="stack", base=base, off=off)
                self.graph.add_edge(node_id, mem_id, type=EDGE_POINTS_TO)

        elif kind == "global":
            # G:<binary_id>:<ea>
            v_info = op.get("v", {})
            ea = v_info.get("ea")
            if not ea: return None
            node_id = f"G:{self.binary_id}:{ea}"
            if node_id not in self.graph:
                self.graph.add_node(node_id, kind=NODE_GLOBAL, **get_attrs(op))

        elif kind == "const":
            # K:<bits>:<value>
            v_info = op.get("v", {})
            val = v_info.get("value")
            bits = op.get("bits", 0)
            if val is None: return None
            node_id = f"K:{bits}:{val}"
            if node_id not in self.graph:
                self.graph.add_node(node_id, kind=NODE_CONST, **get_attrs(op))
                
        elif kind == "string":
            # S:<ea>
            v_info = op.get("v", {})
            ea = v_info.get("ea")
            if not ea: return None
            node_id = f"S:{ea}"
            if node_id not in self.graph:
                self.graph.add_node(node_id, kind=NODE_STRING, **get_attrs(op))

        elif kind == "mem":
            # M:<func_ea>:<region>:<addr_hash>:<bits>
            v_info = op.get("v", {})
            region = v_info.get("region", "unknown")
            addr_obj = v_info.get("addr", {})
            addr_hash = self._get_canonical_hash(addr_obj)
            bits = op.get("bits", 0)
            
            node_id = f"M:{func_ea}:{region}:{addr_hash}:{bits}"
            if node_id not in self.graph:
                self.graph.add_node(node_id, kind=NODE_MEM, addr_hash=addr_hash, **get_attrs(op))

        elif kind in ["expr", "unknown"]:
             # E:<func_ea>:<expr_hash>
             op_copy = op.copy()
             op_copy.pop("repr", None)
             expr_hash = self._get_canonical_hash(op_copy)
             
             node_id = f"E:{func_ea}:{expr_hash}"
             if node_id not in self.graph:
                 self.graph.add_node(node_id, kind=NODE_EXPR, expr_hash=expr_hash, **get_attrs(op))
                 
                 # Recursively handle args if present
                 v_data = op.get("v", {})
                 if isinstance(v_data, dict) and "args" in v_data:
                     for i, sub_op in enumerate(v_data["args"]):
                         sub_node_id = self._intern_operand(func_ea, sub_op)
                         if sub_node_id:
                             self.graph.add_edge(node_id, sub_node_id, type=EDGE_USE, index=i)
        
        return node_id

    def _get_canonical_hash(self, data):
        """Compute stable hash for data (JSON-compatible)."""
        import hashlib
        # Canonicalize: sort keys, remove whitespace
        s = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(s.encode('utf-8')).hexdigest()

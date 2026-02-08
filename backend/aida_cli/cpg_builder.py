import json
import logging
import networkx as nx
from pathlib import Path
from .model import (
    NODE_PROG, NODE_FUNC, NODE_BLOCK, NODE_INSTR, NODE_CALL, NODE_VAR, NODE_CONST, NODE_STRING, NODE_MEM, NODE_EXPR,
    EDGE_HAS_FUNC, EDGE_HAS_BLOCK, EDGE_HAS_INSTR, EDGE_CFG, EDGE_CALL_OF, EDGE_ARG, EDGE_RET, EDGE_DEF, EDGE_USE
)

logger = logging.getLogger(__name__)

class CPGBuilder:
    def __init__(self, cpg_dir: str):
        self.cpg_dir = Path(cpg_dir)
        self.graph = nx.MultiDiGraph()
        self.func_index = {}  # func_ea -> func_node_id
        
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
        
        if kind in ["var", "stack", "reg"]:
            # Var: stable ID within function
            # V:<func_ea>:<storage>:<id> or similar
            # Use 'repr' or specific fields for uniqueness
            # V1 spec: Var/Mem/Expr ID must be stable
            v_info = op.get("v", {})
            # Construct a unique key for the variable
            
            # IMPROVEMENT: Use structured location if available (base+off)
            if "base" in v_info and "off" in v_info:
                var_key = f"{v_info['base']}:{v_info['off']}"
            else:
                # e.g., location based
                var_key = v_info.get("full_repr") or op.get("repr")
                var_key = self._normalize_key(var_key)
                
            if not var_key: return None
            node_id = f"V:{func_ea}:{var_key}"
            if node_id not in self.graph:
                self.graph.add_node(node_id, kind=NODE_VAR, **get_attrs(op))
                
        elif kind == "const":
            # Const: global reuse
            # K:<val>
            val = op.get("v", {}).get("val")
            if val is None: return None
            node_id = f"K:{val}"
            if node_id not in self.graph:
                self.graph.add_node(node_id, kind=NODE_CONST, **get_attrs(op))
                
        elif kind == "string":
            # String: global reuse
            # S:<content_hash> or S:<addr>
            s_val = op.get("v", {}).get("str")
            if s_val is None: return None
            # simple hashing for ID
            import hashlib
            h = hashlib.md5(s_val.encode('utf-8', errors='ignore')).hexdigest()
            node_id = f"S:{h}"
            if node_id not in self.graph:
                self.graph.add_node(node_id, kind=NODE_STRING, value=s_val, **get_attrs(op))

        # For V1 simplicity, we might skip detailed Mem/Expr handling unless needed for Taint
        # But let's handle Mem roughly
        elif kind in ["mem", "global"]:
             # M:<func_ea>:<full_repr>
             m_key = op.get("v", {}).get("full_repr") or op.get("repr")
             m_key = self._normalize_key(m_key)
             if m_key:
                 node_id = f"M:{func_ea}:{m_key}"
                 if node_id not in self.graph:
                     self.graph.add_node(node_id, kind=NODE_MEM, **get_attrs(op))

        elif kind in ["expr", "unknown"]:
             # E:<func_ea>:<repr>
             # Use repr as key
             repr_str = op.get("repr")
             repr_str = self._normalize_key(repr_str)
             if repr_str:
                 node_id = f"E:{func_ea}:{repr_str}"
                 if node_id not in self.graph:
                     self.graph.add_node(node_id, kind=NODE_EXPR, **get_attrs(op))
        
        return node_id

    def _normalize_key(self, repr_str):
        if not repr_str: return None
        import re
        
        # Iteratively remove prefixes until stable
        while True:
            original = repr_str
            
            # Remove "type" prefix: "int *" var
            m = re.match(r'^".*?"\s+(.*)$', repr_str)
            if m:
                repr_str = m.group(1)
                continue
                
            # Remove size prefix: _QWORD var
            m = re.match(r'^_(?:QWORD|DWORD|WORD|BYTE|OWORD|TBYTE)\s+(.*)$', repr_str)
            if m:
                repr_str = m.group(1)
                continue
            
            # If no change, break
            if repr_str == original:
                break
                
        return repr_str

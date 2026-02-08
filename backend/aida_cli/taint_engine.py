import networkx as nx
from typing import Dict, List, Set, Optional, Any
from .model import (
    NODE_STRING, NODE_CONST, NODE_VAR, NODE_MEM, NODE_EXPR,
    EDGE_DEF, EDGE_USE, EDGE_CALL_OF, EDGE_ARG
)

class TaintEngine:
    def __init__(self, graph: nx.MultiDiGraph, sources: Set[str], propagators: Dict[str, List[int]], max_depth: int = 5):
        """
        Initialize generic TaintEngine.
        
        :param graph: The CPG graph
        :param sources: Set of function names that are taint sources (e.g. {"getenv", "read"})
        :param propagators: Dictionary mapping function names to output argument indices
                            e.g. {"snprintf": [0], "memcpy": [0]}
        :param max_depth: Maximum recursion depth for trace
        """
        self.graph = graph
        self.sources = sources
        self.propagators = propagators
        self.max_depth = max_depth
        
        # Build function map for interprocedural analysis
        self.func_map = {}
        for node, data in self.graph.nodes(data=True):
            if data.get("kind") == "Function":
                name = data.get("name")
                if name:
                    # Strip underscores for consistency
                    clean_name = name
                    if clean_name.startswith("_"): clean_name = clean_name[1:]
                    self.func_map[clean_name] = node
                    self.func_map[name] = node # Keep original too

    def get_taint_sources(self, node_id) -> List[Dict]:
        """
        Trace back from node_id to find taint sources.
        Returns list of source dicts: {"kind": "CallSite", "id": ..., "name": ..., "ea": ...}
        """
        return self._trace(node_id, set(), 0)

    def _trace(self, node_id, visited, depth):
        # print(f"DEBUG: _trace {node_id} depth={depth}")
        if depth > self.max_depth: return []
        if node_id in visited: return []
        visited.add(node_id)
        
        node_data = self.graph.nodes[node_id]
        kind = node_data.get("kind")
        
        # 1. Base Cases: Safe
        if kind in [NODE_STRING, NODE_CONST]:
            return []
            
        results = []
        
        # 2. Variable/Memory: Trace Definitions
        if kind in [NODE_VAR, NODE_MEM, NODE_EXPR]:
            # A. Explicit DEFs (Instr -> Var)
            # Var has incoming EDGE_DEF from Instr
            has_def = False
            for instr_id, _, edge_data in self.graph.in_edges(node_id, data=True):
                if edge_data.get("type") == EDGE_DEF:
                    has_def = True
                    results.extend(self._check_instr_source(instr_id, visited, depth+1))
            
            # B. Implicit DEFs (Output Args)
            # Look for USEs where this variable is an output argument
            for instr_id, _, edge_data in self.graph.in_edges(node_id, data=True):
                if edge_data.get("type") == EDGE_USE:
                    # Check if this instr is a CallSite and we are an output arg
                    call_sites = [u for u, _, d in self.graph.in_edges(instr_id, data=True) if d.get("type") == EDGE_CALL_OF]
                    for cs in call_sites:
                        # print(f"DEBUG: Checking propagator {cs} for {node_id}")
                        if self._is_propagator_output(cs, node_id):
                            # print(f"DEBUG: Propagator match! {cs}")
                            has_def = True
                            results.extend(self._trace_call_inputs(cs, visited, depth+1))

            pass

        return results

    def _check_instr_source(self, instr_id, visited, depth):
        # Is this instr a call to a source?
        # Check for associated CallSites
        call_sites = [u for u, _, d in self.graph.in_edges(instr_id, data=True) if d.get("type") == EDGE_CALL_OF]
        results = []
        for cs in call_sites:
            name = self._get_callee_name(cs)
            if self._is_source_name(name):
                results.append(self._make_source_info(cs, name))
            else:
                # Return from non-source function.
                # Try interprocedural trace
                sources = self._trace_interprocedural(cs, visited, depth)
                if sources: results.extend(sources)
        return results

    def _trace_interprocedural(self, call_id, visited, depth):
        # Find callee function node
        name = self._get_callee_name(call_id)
        if not name: return []
        
        # Check if we have this function in our graph
        func_node = self.func_map.get(name)
        if not func_node: return []
        
        # Find return variable (heuristic: x0 / fp:0)
        return_var = self._find_return_var(func_node)
        if not return_var: return []
        
        # Trace inside the callee
        # We need to ensure we don't loop infinitely if recursion is direct
        # But 'visited' handles nodes. 'return_var' is a different node than caller's var.
        return self._trace(return_var, visited, depth + 1)

    def _find_return_var(self, func_node):
        # Heuristic: Find variable in this function that represents x0/rax
        # We assume variables are linked to function scope by some means, 
        # or we scan for vars with specific properties near function start/end.
        # In this CPG, vars are often named like 'var80.8' or registers.
        # But we saw 'V:func_addr:fp:0' for x0.
        
        func_ea = self.graph.nodes[func_node].get("ea") # e.g. "0x100000a88"
        if not func_ea: return None
        
        # Construct ID prefix? 
        # Node IDs are strings. 
        # We can iterate all nodes... (inefficient)
        # Or check if we can predict the ID.
        # ID format seems to be V:<ea>:<base>:<off>
        # e.g. V:0x100000a88:fp:0
        
        target_id = f"V:{func_ea}:fp:0"
        if target_id in self.graph.nodes:
            return target_id
            
        return None

    def _trace_call_inputs(self, call_id, visited, depth):
        name = self._get_callee_name(call_id)
        
        # If the function itself is a source (e.g. read), it taints the output
        if self._is_source_name(name):
             return [self._make_source_info(call_id, name)]

        # Check inputs
        args = []
        for _, neighbor, edge_data in self.graph.out_edges(call_id, data=True):
            if edge_data.get("type") == EDGE_ARG:
                args.append((edge_data.get("index"), neighbor))
        
        tainted_inputs = []
        
        for idx, arg_node in args:
            # Skip output args
            if name in self.propagators and idx in self.propagators[name]:
                continue
            
            # Recursively trace
            sources = self._trace(arg_node, visited, depth)
            if sources:
                tainted_inputs.extend(sources)
                
        return tainted_inputs

    def _is_propagator_output(self, call_id, var_node_id):
        name = self._get_callee_name(call_id)
        if name not in self.propagators: return False
        
        indices = self.propagators[name]
        # Check args of this call
        for _, neighbor, edge_data in self.graph.out_edges(call_id, data=True):
            if edge_data.get("type") == EDGE_ARG:
                if edge_data.get("index") in indices:
                    if neighbor == var_node_id:
                        return True
                    
                    # Check partial match for expressions/memory (e.g. buf + offset)
                    neighbor_data = self.graph.nodes[neighbor]
                    if neighbor_data.get("kind") in [NODE_EXPR, NODE_MEM]:
                        var_data = self.graph.nodes[var_node_id]
                        var_repr = var_data.get("repr") or var_data.get("name")
                        # Also try to clean up repr (remove type/size suffix like .8)
                        # But simple substring might work for now
                        expr_repr = neighbor_data.get("repr")
                        
                        if var_repr and expr_repr:
                             # 1. Direct containment
                            if var_repr in expr_repr:
                                return True
                            
                            # 2. Try to extract variable name (last token) and check
                            # e.g. "_QWORD __s.8" -> "__s.8"
                            var_tokens = var_repr.split()
                            if len(var_tokens) > 1:
                                var_name = var_tokens[-1]
                                if var_name and len(var_name) > 1 and var_name in expr_repr:
                                    return True
        return False

    def _get_callee_name(self, call_id):
        data = self.graph.nodes[call_id]
        name = data.get("callee_name")
        if not name:
            target = data.get("target", {})
            if target: name = target.get("name")
        
        if name:
            if name.startswith("__imp_"): name = name[6:]
            elif name.startswith("_imp_"): name = name[5:]
            if name.startswith("_"): name = name[1:]
            
        return name

    def _is_source_name(self, name):
        if not name: return False
        return name in self.sources

    def _make_source_info(self, call_id, name):
        node = self.graph.nodes[call_id]
        return {
            "kind": "CallSite",
            "id": call_id,
            "name": name,
            "ea": node.get("ea", "unknown")
        }

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

    def get_taint_sources(self, node_id) -> List[Dict]:
        """
        Trace back from node_id to find taint sources.
        Returns list of source dicts: {"kind": "CallSite", "id": ..., "name": ..., "ea": ...}
        """
        return self._trace(node_id, set(), 0)

    def _trace(self, node_id, visited, depth):
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
                        if self._is_propagator_output(cs, node_id):
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
                # Could trace arguments (if it returns a value derived from args).
                pass
        return results

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
                if edge_data.get("index") in indices and neighbor == var_node_id:
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

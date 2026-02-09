import networkx as nx
from typing import Dict, List, Set, Optional, Any
from .model import (
    NODE_STRING, NODE_CONST, NODE_VAR, NODE_MEM, NODE_EXPR, NODE_CALL,
    EDGE_DEF, EDGE_USE, EDGE_CALL_OF, EDGE_ARG, EDGE_POINTS_TO
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
        self.ea_map = {}
        for node, data in self.graph.nodes(data=True):
            if data.get("kind") == "Function":
                name = data.get("name")
                if name:
                    # Strip underscores for consistency
                    clean_name = name
                    if clean_name.startswith("_"): clean_name = clean_name[1:]
                    self.func_map[clean_name] = node
                    self.func_map[name] = node # Keep original too
                    
                    # Map EA to Name
                    ea = data.get("ea")
                    if ea:
                        self.ea_map[str(ea)] = name
        
        # Build caller map: callee_name -> [call_site_id]
        self.caller_map = {}
        for node, data in self.graph.nodes(data=True):
             if data.get("kind") == NODE_CALL:
                 callee_name = data.get("callee_name")
                 if callee_name:
                     if callee_name not in self.caller_map:
                         self.caller_map[callee_name] = []
                     self.caller_map[callee_name].append(node)
                     
                     if callee_name.startswith("_"):
                         sname = callee_name[1:]
                         if sname not in self.caller_map:
                             self.caller_map[sname] = []
                         self.caller_map[sname].append(node)

    def debug_trace(self, node_id: str) -> List[Dict]:
        """
        Debug interface: trace a node with verbose logging.
        """
        print(f"[DEBUG] Starting trace for node: {node_id}")
        return self._trace(node_id, set(), 0, verbose=True)

    def dump_subgraph(self, node_ids: List[str], output_path: str):
        """
        Debug interface: export subgraph containing specific nodes and their neighbors.
        """
        sub_nodes = set(node_ids)
        for nid in node_ids:
            if nid in self.graph:
                sub_nodes.update(self.graph.predecessors(nid))
                sub_nodes.update(self.graph.successors(nid))
        
        subgraph = self.graph.subgraph(sub_nodes)
        data = nx.node_link_data(subgraph)
        
        import json
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[DEBUG] Subgraph dumped to {output_path}")

    def get_taint_sources(self, node_id) -> List[Dict]:
        """
        Trace back from node_id to find taint sources.
        Returns list of source dicts: {"kind": "CallSite", "id": ..., "name": ..., "ea": ...}
        """
        return self._trace(node_id, set(), 0)

    def _check_implicit_defs(self, node_id, visited, depth, verbose=False):
        """
        Check if node_id is an output argument of any function call (Implicit Definition).
        """
        results = []
        # Look for USEs where this variable is an output argument
        # Also check if this node is DIRECTLY an output argument (incoming ARG edge)
        for user_node, _, edge_data in self.graph.in_edges(node_id, data=True):
            edge_type = edge_data.get("type")
            
            # Case 1: Direct Argument
            if edge_type == EDGE_ARG:
                cs = user_node # user_node is the CallSite source
                if self._is_propagator_output(cs, node_id):
                    results.extend(self._trace_call_inputs(cs, visited, depth+1, verbose))
                else:
                    # Check user-defined function output (pass-by-reference)
                    sources = self._trace_user_func_output(cs, node_id, visited, depth, verbose)
                    if sources:
                        results.extend(sources)

            # Case 2: Used in an Expression which is an Argument
            elif edge_type == EDGE_USE:
                # Check if user_node is an argument to a CallSite
                for cs, _, d in self.graph.in_edges(user_node, data=True):
                    if d.get("type") == EDGE_ARG:
                        # user_node is an argument to cs
                        # Check if user_node is an output argument
                        if self._is_propagator_output(cs, user_node):
                            results.extend(self._trace_call_inputs(cs, visited, depth+1, verbose))
                        else:
                            # Check user-defined function output (pass-by-reference)
                            sources = self._trace_user_func_output(cs, user_node, visited, depth, verbose)
                            if sources:
                                results.extend(sources)
                
                # Check if this instr is a CallSite and we are an output arg
                call_sites = [u for u, _, d in self.graph.in_edges(user_node, data=True) if d.get("type") == EDGE_CALL_OF]
                for cs in call_sites:
                    if self._is_propagator_output(cs, node_id):
                        results.extend(self._trace_call_inputs(cs, visited, depth+1, verbose))
                    
                    # Check user-defined function output for ALL pointer arguments
                    for _, arg_node, edge_data in self.graph.out_edges(cs, data=True):
                        if edge_data.get("type") == EDGE_ARG:
                            arg_data = self.graph.nodes[arg_node]
                            repr_str = arg_data.get("repr", "")
                            if "&" in repr_str or "*" in repr_str or "addr_of" in arg_data.get("op_kind", ""):
                                 sources = self._trace_user_func_output(cs, arg_node, visited, depth, verbose)
                                 if sources:
                                     results.extend(sources)
        return results

    def _trace(self, node_id, visited, depth, verbose=False):
        if verbose: print(f"[DEBUG] _trace depth={depth} node={node_id}")
        if depth > self.max_depth: 
            if verbose: print(f"[DEBUG] Max depth reached at {node_id}")
            return []
        if node_id in visited: 
            if verbose: print(f"[DEBUG] Visited loop at {node_id}")
            return []
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
            for instr_id, _, edge_data in self.graph.in_edges(node_id, data=True):
                if edge_data.get("type") == EDGE_DEF:
                    if verbose: print(f"[DEBUG]   Found DEF from instr {instr_id}")
                    results.extend(self._check_instr_source(instr_id, visited, depth+1, verbose))
                    
                    # Check for alias (AddressOf)
                    results.extend(self._trace_alias(instr_id, visited, depth+1, verbose))
            
            # B. Implicit DEFs (Output Args)
            results.extend(self._check_implicit_defs(node_id, visited, depth, verbose))

            # NEW: Handle POINTS_TO
            if kind == NODE_VAR:
                 # Trace memory this var points to
                 for _, neighbor, edge_data in self.graph.out_edges(node_id, data=True):
                     if edge_data.get("type") == EDGE_POINTS_TO:
                         if verbose: print(f"[DEBUG]   Following POINTS_TO -> {neighbor}")
                         results.extend(self._trace(neighbor, visited, depth, verbose))
            
            if kind == NODE_MEM:
                 # Trace variables that point to this memory
                 for src_var, _, edge_data in self.graph.in_edges(node_id, data=True):
                     if edge_data.get("type") == EDGE_POINTS_TO:
                         if verbose: print(f"[DEBUG]   Reverse POINTS_TO <- {src_var}")
                         # Check if src_var is an output argument
                         results.extend(self._check_implicit_defs(src_var, visited, depth, verbose))

            # C. Expression Operands (Expr -> Var/Expr)
            # If this is an Expr, trace its operands (outgoing EDGE_USE)
            if kind == NODE_EXPR:
                for _, neighbor, edge_data in self.graph.out_edges(node_id, data=True):
                    if edge_data.get("type") == EDGE_USE:
                        results.extend(self._trace(neighbor, visited, depth+1, verbose))

            # D. Interprocedural: Trace Callers (Parameters)
            # If this variable is a parameter, trace back to call sites
            if kind == NODE_VAR:
                results.extend(self._trace_callers(node_id, visited, depth, verbose))

        return results

    def _trace_callers(self, node_id, visited, depth, verbose=False):
        # 1. Parse EA from node_id
        # node_id format: V:<ea>:... 
        parts = node_id.split(":")
        if len(parts) < 2: return []
        ea_str = parts[1]
        
        # 2. Get Function Name
        func_name = self.ea_map.get(ea_str)
        # print(f"DEBUG: _trace_callers node={node_id} ea={ea_str} func={func_name}")
        if not func_name: return []
        
        # 3. Determine Parameter Index
        node_data = self.graph.nodes[node_id]
        repr_str = node_data.get("repr", "")
        
        param_index = -1
        # Heuristic for ARM64 registers
        # x0-x7 are arguments
        import re
        # Match x0, x1... w0, w1... followed by non-digit (to avoid x00)
        # Handle cases like x0_0.8, x0.8, x0
        # Debug regex
        # print(f"DEBUG: repr_raw={repr(repr_str)}")
        
        # Relaxed regex: Look for xN or wN preceded by boundary or space, followed by non-digit
        # Using [^a-zA-Z0-9] instead of \b for safety if needed, but \b should work.
        # Let's try explicitly handling the underscore issue if any
        
        m = re.search(r'(?:^|[\s\W])([xw])([0-7])(?!\d)', repr_str)
        if m:
            param_index = int(m.group(2))
        
        if param_index == -1: return []
        
        # 4. Find Callers
        caller_ids = self.caller_map.get(func_name, [])
        if not caller_ids: 
             # Try stripping underscore
             if func_name.startswith("_"):
                 caller_ids = self.caller_map.get(func_name[1:], [])
        
        if not caller_ids: return []
        
        results = []
        for cs in caller_ids:
             # Find argument at param_index
             found_arg = False
             for _, arg_node, edge_data in self.graph.out_edges(cs, data=True):
                 if edge_data.get("type") == EDGE_ARG and edge_data.get("index") == param_index:
                     found_arg = True
                     # Trace this argument in the caller's context
                     results.extend(self._trace(arg_node, visited, depth + 1, verbose))
                     
        return results

    def _check_instr_source(self, instr_id, visited, depth, verbose=False):
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
                sources = self._trace_interprocedural(cs, visited, depth, verbose)
                if sources: results.extend(sources)
        return results

    def _trace_interprocedural(self, call_id, visited, depth, verbose=False):
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
        return self._trace(return_var, visited, depth + 1, verbose)

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

    def _trace_call_inputs(self, call_id, visited, depth, verbose=False):
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
            sources = self._trace(arg_node, visited, depth, verbose)
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

    def _trace_alias(self, instr_id, visited, depth, verbose=False):
        """
        Trace variables aliased by AddressOf operations.
        If instr is 'mov ptr, &target', trace other variables defined by '&target'.
        """
        if verbose: print(f"[DEBUG] _trace_alias instr={instr_id}")
        results = []
        # Find input Exprs
        # Instr -> USE -> Expr
        # We need to find Expr nodes that are USED by this Instr.
        # The graph structure for Instr->Expr is OutEdge(Instr, Expr, type=USE)
        
        for _, u, d in self.graph.out_edges(instr_id, data=True):
            if d.get("type") == EDGE_USE:
                node_data = self.graph.nodes[u]
                if node_data.get("kind") == NODE_EXPR:
                    repr_str = node_data.get("repr", "")
                    if verbose: print(f"[DEBUG]   Checking Expr {u} repr={repr_str}")
                    # Heuristic: AddressOf often has '&' in repr or op_kind='addr_of'
                    if "&" in repr_str or node_data.get("op_kind") == "addr_of":
                        if verbose: print(f"[DEBUG]     AddressOf detected! u={u}")
                        # This Expr is '&target'.
                        # We need to find other Instrs that USE this SAME Expr node (or equivalent nodes).
                        # Assuming Expr nodes are shared or linked?
                        # If not shared, we must rely on searching.
                        
                        # Check in-edges of this Expr (predecessors)
                        # Predecessors are Instrs that use this Expr.
                        for instr_other, _, d2 in self.graph.in_edges(u, data=True):
                            if instr_other == instr_id: continue
                            if d2.get("type") == EDGE_USE:
                                # Found another instruction using the same AddressOf Expr.
                                # Trace the variable defined by this instruction.
                                if verbose: print(f"[DEBUG]     Found alias instr {instr_other}")
                                for v_other, _, d3 in self.graph.out_edges(instr_other, data=True):
                                    if d3.get("type") == EDGE_DEF:
                                         if verbose: print(f"[DEBUG]       Alias variable {v_other}")
                                         results.extend(self._trace(v_other, visited, depth+1, verbose))
        return results

    def _trace_user_func_output(self, call_id, arg_node_id, visited, depth, verbose=False):
        # 1. Get Callee
        name = self._get_callee_name(call_id)
        if not name: return []
        func_node = self.func_map.get(name)
        if not func_node: return []
        
        # 2. Get Arg Index
        arg_index = -1
        edge_data = self.graph.get_edge_data(call_id, arg_node_id)
        if edge_data:
            for key in edge_data:
                 data = edge_data[key]
                 if data.get("type") == EDGE_ARG:
                     arg_index = data.get("index")
                     break
        
        if arg_index == -1: return []

        # 3. Find Parameter in Callee
        param_node = self._get_func_param(func_node, arg_index)
        if not param_node: return []
        
        # 4. Trace Param in Callee
        return self._trace(param_node, visited, depth + 1, verbose)

    def _get_func_param(self, func_node, index):
        func_ea = self.graph.nodes[func_node].get("ea")
        if not func_ea: return None
        
        # Heuristic for Aida CPG (ARM64)
        # Arg 0 corresponds to V:<func_ea>:fp:0
        if index == 0:
            param_id = f"V:{func_ea}:fp:0"
            if param_id in self.graph.nodes:
                return param_id
        
        return None

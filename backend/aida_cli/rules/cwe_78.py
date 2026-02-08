import networkx as nx
from typing import Iterator, Optional, Set, Dict, List
from ..model import Finding, NODE_CALL, EDGE_ARG
from ..taint_engine import TaintEngine
from .base import BaseRule

class CWE78Rule(BaseRule):
    # Sink functions
    SINKS = {"system", "popen", "exec", "execl", "execlp", "execle", "execv", "execvp"}
    
    # Taint sources
    SOURCES = {"getenv", "read", "recv", "fgets", "_read", "_getenv", "recvfrom"}
    
    # Propagators: {func_name: [output_arg_indices]}
    PROPAGATORS = {
        "snprintf": [0], "sprintf": [0], "strcpy": [0], "memcpy": [0], "strcat": [0],
        "__snprintf_chk": [0], "strncpy": [0], "read": [1], "_read": [1]
    }
    
    def match(self, graph: nx.MultiDiGraph) -> Iterator[str]:
        """Yields CallSite node IDs that call sink functions."""
        for node, data in graph.nodes(data=True):
            if data.get("kind") == NODE_CALL:
                # Check callee name
                name = data.get("callee_name")
                if not name:
                    target = data.get("target", {})
                    if target: name = target.get("name")
                
                # Strip leading underscore if present (IDA convention)
                if name and name.startswith("_"):
                    name = name[1:]
                    
                if name and name in self.SINKS:
                    yield node

    def analyze(self, graph: nx.MultiDiGraph, call_id: str) -> Optional[Finding]:
        # 1. Get the CallSite
        call_data = graph.nodes[call_id]
        # ID format: C:I:func_ea:block_id:insn_idx:call_idx
        parts = call_id.split(":")
        func_ea = parts[2] if len(parts) > 2 else "unknown"
        
        # 2. Check arguments
        # We need to find the ARG nodes connected to this call
        args = []
        for _, neighbor, edge_data in graph.out_edges(call_id, data=True):
            if edge_data.get("type") == EDGE_ARG:
                args.append((edge_data.get("index"), neighbor))
        
        # Initialize TaintEngine with specific configuration
        taint_engine = TaintEngine(graph, self.SOURCES, self.PROPAGATORS)
        taint_sources = []
        evidence_nodes = [call_id]
        
        is_vulnerable = False
        
        for idx, arg_node_id in args:
            # Trace back sources for each argument
            sources = taint_engine.get_taint_sources(arg_node_id)
            if sources:
                is_vulnerable = True
                taint_sources.extend(sources)
                # Add source IDs to evidence
                for s in sources:
                    if "id" in s: evidence_nodes.append(s["id"])

        if is_vulnerable:
             # Clean up callee name
             callee = call_data.get("callee_name")
             if not callee: callee = call_data.get("target", {}).get("name")
             
             # Remove duplicates in sources
             unique_sources = []
             seen_ids = set()
             for s in taint_sources:
                 if s["id"] not in seen_ids:
                     unique_sources.append(s)
                     seen_ids.add(s["id"])

             return Finding(
                rule_id="cwe-78.command_injection",
                cwe="CWE-78",
                title="Potential Command Injection",
                severity="high",
                binary_id="unknown",
                func_ea=func_ea,
                sink={"kind": "CallSite", "id": call_id, "callee": callee, "ea": call_data.get("ea", "unknown")},
                sources=unique_sources,
                evidence={"node_ids": evidence_nodes}
            )
        return None

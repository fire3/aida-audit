
import sys
import os
import networkx as nx

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.aida_cli.cpg_builder import CPGBuilder
from backend.aida_cli.taint_engine import TaintEngine
from backend.aida_cli.rules.cwe_78 import CWE78Rule
from backend.aida_cli.model import (
    NODE_VAR, NODE_EXPR, NODE_MEM, NODE_CALL, NODE_INSTR,
    EDGE_CALL_OF, EDGE_ARG, EDGE_USE, EDGE_DEF
)

def debug_trace():
    # Set this to the CPG you want to debug
    cpg_path = "/home/fire3/SRC/aida-mcp/scan_results_cwe78/CWE78_OS_Command_Injection__char_connect_socket_execl_12-bad/CWE78_OS_Command_Injection__char_connect_socket_execl_12-bad.94df3d9c.cpg_json"
    
    if len(sys.argv) > 1:
        cpg_path = sys.argv[1]

    print(f"Loading CPG from {cpg_path}...")
    if not os.path.exists(cpg_path):
        print("CPG path does not exist.")
        return

    builder = CPGBuilder(cpg_path)
    graph = builder.build()
    print(f"Graph loaded: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    # Find execl call
    execl_nodes = []
    for node, data in graph.nodes(data=True):
        if data.get("kind") == NODE_CALL:
            name = data.get("callee_name", "")
            if name and "execl" in name:
                execl_nodes.append(node)
                print(f"Found execl candidate: {node} {name}")
    
    if not execl_nodes:
        print("No execl calls found.")
        return

    # Analyze each execl call
    for execl_node in execl_nodes:
        print(f"\nAnalyzing {execl_node}...")
        
        # Check arguments
        args = {}
        for _, neighbor, edge_data in graph.out_edges(execl_node, data=True):
            if edge_data.get("type") == EDGE_ARG:
                idx = edge_data.get("index")
                args[idx] = neighbor
                print(f"  Arg {idx}: {neighbor} {graph.nodes[neighbor]}")
        
        # Trace interesting arguments (e.g. Arg 3 for execl)
        # Note: Arg indices depend on the specific function signature
        target_arg_idx = 3 # Commonly the command in some variants, or arg list
        if target_arg_idx in args:
            arg_node = args[target_arg_idx]
            print(f"  Tracing Arg {target_arg_idx} ({arg_node})...")
            
            engine = TaintEngine(graph, CWE78Rule.SOURCES, CWE78Rule.PROPAGATORS)
            sources = engine.get_taint_sources(arg_node)
            
            if sources:
                print(f"    Taint Sources found: {len(sources)}")
                for s in sources:
                    print(f"      Source: {s}")
            else:
                print("    No taint sources found for this argument.")

if __name__ == "__main__":
    debug_trace()

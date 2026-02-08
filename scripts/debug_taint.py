
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
    cpg_path = "/Users/fire3/SRC/aida-mcp/scan_results_cwe78/CWE78_OS_Command_Injection__char_connect_socket_execl_21-bad/CWE78_OS_Command_Injection__char_connect_socket_execl_21-bad.cpg_json"
    
    print(f"Loading CPG from {cpg_path}...")
    builder = CPGBuilder(cpg_path)
    graph = builder.build()
    print(f"Graph loaded: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    # Find execl call
    execl_node = None
    for node, data in graph.nodes(data=True):
        if data.get("kind") == NODE_CALL:
            name = data.get("callee_name", "")
            if "execl" in name:
                print(f"Found execl call: {node} {name}")
                execl_node = node
                break
    
    if not execl_node:
        print("execl call not found")
        return

    # Find argument 3 (index 3)
    arg_node = None
    for _, neighbor, edge_data in graph.out_edges(execl_node, data=True):
        if edge_data.get("type") == EDGE_ARG and edge_data.get("index") == 3:
            arg_node = neighbor
            print(f"Found arg 3 node: {arg_node} {graph.nodes[arg_node]}")
            
            # Print DEFs of arg_node
            print("  DEFs of arg_node:")
            for instr_id, _, edge_data in graph.in_edges(arg_node, data=True):
                if edge_data.get("type") == EDGE_DEF:
                    print(f"    <- {instr_id} (Type: {edge_data.get('type')})")
                    # Check if this instr is recv
                    if graph.nodes[instr_id].get("kind") == NODE_INSTR:
                         # Find call site
                         for cs, _, d in graph.in_edges(instr_id, data=True):
                             if d.get("type") == EDGE_CALL_OF:
                                 print(f"       Called by: {cs} {graph.nodes[cs].get('callee_name')}")

            break
            
    if not arg_node:
        print("Arg 3 not found")
        return

    # Find recv call
    print("\nLooking for recv call...")
    recv_node = None
    for node, data in graph.nodes(data=True):
        if data.get("kind") == NODE_CALL:
            name = data.get("callee_name", "")
            if "recv" in name:
                print(f"Found recv call: {node} {name}")
                recv_node = node
                
                # Check outgoing edges to find the instruction (CallSite -> Instr)
                for _, v, d in graph.out_edges(node, data=True):
                    if d.get("type") == EDGE_CALL_OF:
                        instr_node = v
                        print(f"  Called by Instr: {instr_node}")
                        print(f"  Instr data: {graph.nodes[instr_node]}")
                        
                        # Check outgoing edges from Instr (USE)
                        print("  Instr USES:")
                        for _, v_use, d2 in graph.out_edges(instr_node, data=True):
                            if d2.get("type") == EDGE_USE:
                                v_data = graph.nodes[v_use]
                                print(f"    -> {v_use} ({v_data.get('repr')}) v={v_data.get('v')}")
                                if str(arg_node) == str(v_use):
                                    print("       (Exact Match with Arg 3!)")
                                else:
                                    if v_use == arg_node:
                                        print("       (Exact Match by ID!)")
                                    
                        # Check Args of recv
                        print("  recv Args:")
                        for _, v, d2 in graph.out_edges(node, data=True):
                            if d2.get("type") == EDGE_ARG:
                                print(f"    Arg {d2.get('index')}: {v} ({graph.nodes[v].get('repr')})")
                                if d2.get("index") == 1:
                                    # Check if arg 1 matches arg_node using TaintEngine logic
                                    engine = TaintEngine(graph, CWE78Rule.SOURCES, CWE78Rule.PROPAGATORS)
                                    is_prop = engine._is_propagator_output(node, arg_node)
                                    print(f"       Is propagator output for arg_node? {is_prop}")

    print("\nRunning TaintEngine trace...")
    engine = TaintEngine(graph, CWE78Rule.SOURCES, CWE78Rule.PROPAGATORS)
    sources = engine.get_taint_sources(arg_node)
    print(f"Taint sources found: {len(sources)}")
    for s in sources:
        print(f"  Source: {s}")

if __name__ == "__main__":
    debug_trace()

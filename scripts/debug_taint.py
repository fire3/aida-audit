
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
    # cpg_path = "/Users/fire3/SRC/aida-mcp/scan_results_cwe78/CWE78_OS_Command_Injection__char_connect_socket_execl_12-bad/CWE78_OS_Command_Injection__char_connect_socket_execl_12-bad.cpg_json"
    # cpg_path = "/Users/fire3/SRC/aida-mcp/scan_results_cwe78/CWE78_OS_Command_Injection__char_connect_socket_execl_32-bad/CWE78_OS_Command_Injection__char_connect_socket_execl_32-bad.cpg_json"
    cpg_path = "/home/fire3/SRC/aida-mcp/scan_results_cwe78/CWE78_OS_Command_Injection__char_connect_socket_execl_43-bad/CWE78_OS_Command_Injection__char_connect_socket_execl_43-bad.cpg_json"
    
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
                print(f"Found call candidate: {node} {name}")
                if name in ["execl", "_execl", "execlp", "_execlp"]:
                    execl_node = node
                    print(f"  Selected as sink: {node}")
    
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
                    print(f"       Instr: {graph.nodes[instr_id]}")
                    print("       Instr Inputs:")
                    for _, u, d2 in graph.out_edges(instr_id, data=True):
                         if d2.get("type") == EDGE_USE:
                             print(f"         -> {u} {graph.nodes[u]}")
                             # If u is Expr, check its inputs
                             if graph.nodes[u].get("kind") == "Expr":
                                 print("           Expr Inputs:")
                                 for _, u2, d3 in graph.out_edges(u, data=True):
                                      print(f"             -> {u2} {graph.nodes[u2]}")
                    # Check if this instr is recv
                    if graph.nodes[instr_id].get("kind") == NODE_INSTR:
                         # Find call site
                         for cs, _, d in graph.in_edges(instr_id, data=True):
                             if d.get("type") == EDGE_CALL_OF:
                                 callee = graph.nodes[cs].get('callee_name')
                                 print(f"       Called by: {cs} {callee}")
                                 
                                 # If called by badSource, check its arguments (USEs of instr_id)
                                 if "badSource" in str(callee):
                                     print("       Checking badSource arguments...")
                                     for _, u, d2 in graph.out_edges(instr_id, data=True):
                                         if d2.get("type") == EDGE_USE:
                                             print(f"         Arg used: {u} {graph.nodes[u]}")
                                             
                                     # Also check ARG edges of the CallSite
                                     print("       Checking CallSite arguments...")
                                     for _, a, d3 in graph.out_edges(cs, data=True):
                                         if d3.get("type") == EDGE_ARG:
                                             print(f"         Arg {d3.get('index')}: {a} {graph.nodes[a]}")
            
            # Print USES/Out-Edges of arg_node
            print("  Out-Edges of arg_node:")
            for _, neighbor, edge_data in graph.out_edges(arg_node, data=True):
                 print(f"    -> {neighbor} ({edge_data})")

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
                                    print(f"       Out-edges of Arg 1:")
                                    for _, neighbor, edge_data in graph.out_edges(v, data=True):
                                         print(f"         -> {neighbor} ({edge_data})")

    print("\nRunning TaintEngine trace...")
    engine = TaintEngine(graph, CWE78Rule.SOURCES, CWE78Rule.PROPAGATORS)
    sources = engine.get_taint_sources(arg_node)
    print(f"Taint sources found: {len(sources)}")
    for s in sources:
        print(f"  Source: {s}")

    # Print caller instructions
    print("\nCaller Instructions (0x100000db0):")
    # Find block containing 0x100000db0
    caller_block = None
    for node, data in graph.nodes(data=True):
        if data.get("kind") == "Block":
            # Check if this block contains the call
            # Actually, the call ID C:I:0x100000db0:1:4:0 implies Function EA 0x100000db0?
            # No, C:I:FuncEA:BlockIdx:InstrIdx:CallIdx
            # So FuncEA is 0x100000db0.
            # Block index is 1.
            if data.get("ea") == "0x100000db0" and str(node).endswith(":1"):
                caller_block = node
                break
    
    if caller_block:
        print(f"Found Block: {caller_block}")
        # Find instructions in this block
        # Edges: Block -> Instr (CONTAINS?)
        # Or just search nodes with prefix I:0x100000db0:1:
        for node, data in graph.nodes(data=True):
            if str(node).startswith("I:0x100000db0:1:"):
                print(f"  {node}: {data.get('mnemonic')} Inputs: {[(u, d) for u, _, d in graph.in_edges(node, data=True) if d.get('type')=='USE']}")


    # Find execl call
    print("\nFinding execl call...")
    execl_node = None
    for node, data in graph.nodes(data=True):
        if data.get("kind") == "CallSite":
            callee = data.get("callee_name", "")
            if not callee and "target" in data:
                 callee = data["target"].get("name", "")
            
            if "execl" in callee:
                print(f"Found execl call: {node} {callee}")
                execl_node = node
                
                # Print args
                print("  Args:")
                for _, arg, d in graph.out_edges(node, data=True):
                    if d.get("type") == "ARG":
                        print(f"    Arg {d.get('index')}: {arg} {graph.nodes[arg]}")
                        
                        # Trace this arg
                    print(f"    Tracing Arg {d.get('index')}...")
                    
                    # Analyze the node structure if it's a Var
                    if arg.startswith("V:"):
                        print(f"    Analyzing Var node {arg}:")
                        print(f"      In-edges:")
                        for u, v, k in graph.in_edges(arg, data=True):
                             print(f"        <- {u} ({k.get('type')}) {graph.nodes[u].get('kind')}")
                        print(f"      Out-edges:")
                        for u, v, k in graph.out_edges(arg, data=True):
                             print(f"        -> {v} ({k.get('type')}) {graph.nodes[v].get('kind')}")

                    engine = TaintEngine(graph, {"recv", "read", "getenv"}, {"recv": [1]})
                    sources = engine.get_taint_sources(arg)
                    print(f"    Sources: {len(sources)}")
                    for s in sources:
                        print(f"      {s}")
            



if __name__ == "__main__":
    debug_trace()

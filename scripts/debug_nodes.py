
import sys
import os
import networkx as nx

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.aida_cli.cpg_builder import CPGBuilder

def debug_nodes():
    # cpg_path = "/Users/fire3/SRC/aida-mcp/scan_results_cwe78/CWE78_OS_Command_Injection__char_connect_socket_execl_12-bad/CWE78_OS_Command_Injection__char_connect_socket_execl_12-bad.cpg_json"
    cpg_path = "/Users/fire3/SRC/aida-mcp/scan_results_cwe78/CWE78_OS_Command_Injection__char_connect_socket_execl_41-bad/CWE78_OS_Command_Injection__char_connect_socket_execl_41-bad.cpg_json"
    
    print(f"Loading CPG from {cpg_path}...")
    builder = CPGBuilder(cpg_path)
    graph = builder.build()
    
    # Find execl call
    execl_node = None
    for node, data in graph.nodes(data=True):
        if data.get("kind") == "CallSite" and "execl" in data.get("callee_name", ""):
            execl_node = node
            print(f"\nFound execl call: {node}")
            print(f"  Data: {data}")
            
            print("  Arguments:")
            for u, v, d in graph.out_edges(node, data=True):
                if d.get("type") == "ARG":
                    print(f"    Arg {d.get('index')}: {v}")
                    print(f"      Data: {graph.nodes[v]}")
                    
                    # Print In-Edges of the argument
                    print("      In-Edges:")
                    for u2, v2, d2 in graph.in_edges(v, data=True):
                        print(f"        <- {u2} ({d2})")
                        
            break
            
    if not execl_node:
        print("execl call not found")

if __name__ == "__main__":
    debug_nodes()

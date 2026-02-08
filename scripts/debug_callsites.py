import networkx as nx
import json
import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))
from aida_cli.cpg_builder import load_cpg

if __name__ == "__main__":
    cpg_path = "/Users/fire3/SRC/aida-mcp/scan_results_cwe78/CWE78_OS_Command_Injection__char_connect_socket_execl_41-bad/CWE78_OS_Command_Injection__char_connect_socket_execl_41-bad.cpg_json"
    
    print(f"Loading CPG from {cpg_path}...")
    graph = load_cpg(cpg_path)
    print(f"Graph loaded: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    print("\n--- CallSites ---")
    for node, data in graph.nodes(data=True):
        if data.get("kind") == "CallSite":
            print(f"CallSite: {node} -> {data.get('callee_name')}")

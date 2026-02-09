import argparse
import sys
import os
import networkx as nx
import json
import re
from pathlib import Path

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.aida_cli.cpg_builder import CPGBuilder
from backend.aida_cli.model import (
    NODE_FUNC, NODE_BLOCK, NODE_INSTR, 
    EDGE_HAS_BLOCK, EDGE_HAS_INSTR, EDGE_CFG, EDGE_CALL_OF, EDGE_ARG, EDGE_DEF, EDGE_USE
)

def find_functions(graph, name_pattern):
    """Find function nodes matching the name pattern."""
    matches = []
    pattern = re.compile(name_pattern)
    for node, data in graph.nodes(data=True):
        if data.get("kind") == NODE_FUNC:
            func_name = data.get("name", "")
            if pattern.search(func_name):
                matches.append((node, data))
    return matches

def get_function_subgraph(graph, func_node_id):
    """
    Collect all nodes and edges belonging to the function.
    Includes: Function Node, Blocks, Instructions.
    Also includes immediate neighbors (callees, variables) to show context.
    """
    nodes_to_include = {func_node_id}
    
    # Traverse HAS_BLOCK -> HAS_INSTR
    # 1. Get Blocks
    blocks = []
    for _, neighbor, edge_data in graph.out_edges(func_node_id, data=True):
        if edge_data.get("type") == EDGE_HAS_BLOCK:
            blocks.append(neighbor)
            nodes_to_include.add(neighbor)
    
    # 2. Get Instructions for each block
    instructions = []
    for block in blocks:
        for _, neighbor, edge_data in graph.out_edges(block, data=True):
            if edge_data.get("type") == EDGE_HAS_INSTR:
                instructions.append(neighbor)
                nodes_to_include.add(neighbor)
                
    # 3. Include arguments/variables connected to instructions (optional, for context)
    #    Let's include immediate neighbors of instructions (e.g., calls, args, defs)
    #    But be careful not to include the whole graph.
    
    #    For visualization, we might want to see what instructions Call or Use.
    final_nodes = set(nodes_to_include)
    
    # Add immediate neighbors of instructions (e.g. Call targets, Variables used)
    for instr in instructions:
        for neighbor in graph.successors(instr):
            final_nodes.add(neighbor)
        for neighbor in graph.predecessors(instr):
            # Predecessors of instruction are usually Blocks (HAS_INSTR), but could be others?
            # Actually EDGE_DEF comes FROM instruction TO variable.
            # EDGE_USE comes FROM variable TO instruction (wait, usually Var -> Instr is Use? Or Instr -> Var is Use?)
            # In taint_engine.py: 
            #   EDGE_DEF: Instr -> Var
            #   EDGE_USE: Expr -> Instr (or similar)
            # Let's just add neighbors to be safe, but exclude huge nodes if any.
            if neighbor not in nodes_to_include:
                 # Check if it's a Block (already included)
                 if graph.nodes[neighbor].get("kind") == NODE_BLOCK: continue
                 final_nodes.add(neighbor)

    return graph.subgraph(final_nodes)

def export_dot(subgraph, output_path):
    """Export subgraph to DOT format."""
    try:
        from networkx.drawing.nx_pydot import write_dot
        write_dot(subgraph, output_path)
        print(f"Graph exported to {output_path}")
    except ImportError:
        # Fallback manual export if pydot is missing
        print("pydot not found, using manual DOT export.")
        with open(output_path, "w") as f:
            f.write("digraph G {\n")
            # Write nodes
            for node, data in subgraph.nodes(data=True):
                label = data.get("label", str(node))
                kind = data.get("kind", "")
                name = data.get("name", "")
                mnemonic = data.get("mnemonic", "")
                
                display_label = f"{node}\\n{kind}"
                if name: display_label += f"\\n{name}"
                if mnemonic: display_label += f"\\n{mnemonic}"
                
                # Simple styling
                shape = "box"
                color = "black"
                if kind == NODE_FUNC: shape = "ellipse"; color = "blue"
                elif kind == NODE_BLOCK: shape = "box"; color = "gray"
                elif kind == NODE_INSTR: shape = "box"; color = "black"
                
                f.write(f'  "{node}" [label="{display_label}", shape={shape}, color={color}];\n')
            
            # Write edges
            for u, v, data in subgraph.edges(data=True):
                etype = data.get("type", "")
                f.write(f'  "{u}" -> "{v}" [label="{etype}"];\n')
            
            f.write("}\n")
        print(f"Graph exported to {output_path}")

def export_json(subgraph, output_path):
    """Export subgraph to JSON format."""
    data = nx.node_link_data(subgraph)
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Graph exported to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Visualize CPG subgraph for a specific function.")
    parser.add_argument("--cpg", required=True, help="Path to CPG directory (.cpg_json)")
    parser.add_argument("--func", required=True, help="Function name (regex supported)")
    parser.add_argument("--output", default="func_graph.dot", help="Output file path")
    parser.add_argument("--format", choices=["dot", "json"], default="dot", help="Output format")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.cpg):
        print(f"Error: CPG path {args.cpg} does not exist.")
        sys.exit(1)
        
    print(f"Loading CPG from {args.cpg}...")
    builder = CPGBuilder(args.cpg)
    graph = builder.build()
    print(f"Graph loaded: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    print(f"Searching for function matching '{args.func}'...")
    matches = find_functions(graph, args.func)
    
    if not matches:
        print("No matching functions found.")
        sys.exit(0)
        
    if len(matches) > 1:
        print(f"Found {len(matches)} matches. Using the first one:")
        for n, d in matches:
            print(f"  - {d.get('name')} ({n})")
    
    target_node, target_data = matches[0]
    print(f"Extracting subgraph for {target_data.get('name')} ({target_node})...")
    
    subgraph = get_function_subgraph(graph, target_node)
    print(f"Subgraph contains {len(subgraph.nodes)} nodes and {len(subgraph.edges)} edges.")
    
    if args.format == "dot":
        export_dot(subgraph, args.output)
    else:
        export_json(subgraph, args.output)

if __name__ == "__main__":
    main()

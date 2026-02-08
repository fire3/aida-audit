import json
import argparse
from typing import List, Optional
from .cpg_builder import CPGBuilder
from .rules import get_all_rules, get_rule

def run_scan(cpg_dir: str, rule_names: Optional[List[str]] = None):
    print(f"Building CPG from {cpg_dir}...")
    builder = CPGBuilder(cpg_dir)
    graph = builder.build()
    print(f"Graph built: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges.")
    
    available_rules = get_all_rules()
    
    if rule_names:
        selected_rules = []
        for name in rule_names:
            if name in available_rules:
                selected_rules.append(available_rules[name]())
            else:
                print(f"Warning: Rule '{name}' not found. Skipping.")
    else:
        selected_rules = [r() for r in available_rules.values()]

    if not selected_rules:
        print("No rules selected or found.")
        return

    findings = []
    
    print(f"Running {len(selected_rules)} rules...")
    for rule in selected_rules:
        for candidate in rule.match(graph):
            finding = rule.analyze(graph, candidate)
            if finding:
                findings.append(finding)
    
    print(f"Scan complete. Found {len(findings)} issues.")
    for f in findings:
        print(json.dumps(f.to_dict(), indent=2))

def main():
    parser = argparse.ArgumentParser(description="Scan CPG for vulnerabilities")
    parser.add_argument("cpg_dir", help="Path to CPG JSON directory")
    parser.add_argument("--rules", help="Comma-separated list of rules to run (e.g. cwe-78)", default=None)
    args = parser.parse_args()
    
    rule_names = None
    if args.rules:
        rule_names = [r.strip() for r in args.rules.split(",") if r.strip()]
        
    run_scan(args.cpg_dir, rule_names)

if __name__ == "__main__":
    main()

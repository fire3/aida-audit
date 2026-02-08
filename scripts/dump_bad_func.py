import json
import sys

file_path = "/Users/fire3/SRC/aida-mcp/scan_results_cwe78/CWE78_OS_Command_Injection__char_connect_socket_execl_01-bad/CWE78_OS_Command_Injection__char_connect_socket_execl_01-bad.cpg_json/functions.jsonl"

with open(file_path, 'r') as f:
    for line in f:
        data = json.loads(line)
        if data['name'].endswith("bad"):
            print(f"Function: {data['name']}")
            if not data.get('microcode'):
                print("No microcode")
                continue
                
            insns = data['microcode'].get('insns', [])
            for insn in insns:
                print(f"{insn.get('ea')}: {insn.get('text')}")
                # Print calls if any
                if insn.get('calls'):
                    for call in insn['calls']:
                        print(f"  CALL: {call.get('callee_name')} args={len(call.get('args', []))}")

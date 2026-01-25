import sys
import os
import json
import argparse
import re
from . import export_cmd
from . import server_cmd

def _print_main_help():
    print("Usage: aida-mcp <command> [args]")
    print("Commands:")
    print("  export  - Export IDA database")
    print("  serve   - Start MCP server")
    print("  install - Generate MCP client config")

def _normalize_client(value):
    key = value.strip().lower().replace(" ", "-")
    mapping = {
        "opencode": "opencode",
        "roo": "roo-code",
        "roo-code": "roo-code",
        "roocode": "roo-code",
        "trae": "trae",
        "claude": "claude-code",
        "claude-code": "claude-code",
        "claudecode": "claude-code",
        "cline": "cline",
    }
    return mapping.get(key)

def _build_stdio_config(project, python_cmd, server_name):
    command = python_cmd
    if os.name == "nt" and " " in command:
        command = "python"
    return {
        "mcpServers": {
            server_name: {
                "command": command,
                "args": ["-m", "aida_mcp.mcp_stdio_server", "--project", project],
            }
        }
    }

def _build_opencode_stdio_config(project, python_cmd, server_name):
    command = python_cmd
    if os.name == "nt" and " " in command:
        command = "python"
    return {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            server_name: {
                "type": "local",
                "command": [command, "-m", "aida_mcp.mcp_stdio_server", "--project", project],
                "enabled": True,
            }
        }
    }

def _build_http_config(url, server_name):
    return {
        "mcpServers": {
            server_name: {
                "url": url,
            }
        }
    }

def _build_opencode_http_config(url, server_name):
    return {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            server_name: {
                "type": "remote",
                "url": url,
                "enabled": True,
            }
        }
    }

def _read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Simple fallback to remove trailing commas which are common in JSONC
        content = re.sub(r',(\s*[}\]])', r'\1', content)
        return json.loads(content)

def _write_json(path, payload):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")

def _pick_server_name(existing):
    base = "aida-mcp"
    if base not in existing:
        return base
    idx = 2
    while f"{base}-{idx}" in existing:
        idx += 1
    return f"{base}-{idx}"

def _merge_config(existing, payload):
    if not isinstance(existing, dict):
        existing = {}
    servers = existing.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    for key, value in payload.get("mcpServers", {}).items():
        if key in servers:
            key = _pick_server_name(servers)
        servers[key] = value
    existing["mcpServers"] = servers
    return existing

def _merge_opencode_config(existing, payload):
    if not isinstance(existing, dict):
        existing = {}
    
    if "$schema" not in existing:
        existing["$schema"] = "https://opencode.ai/config.json"
        
    servers = existing.get("mcp")
    if not isinstance(servers, dict):
        servers = {}
    for key, value in payload.get("mcp", {}).items():
        if key in servers:
            key = _pick_server_name(servers)
        servers[key] = value
    existing["mcp"] = servers
    return existing

def _config_roots():
    roots = []
    for key in ("APPDATA", "LOCALAPPDATA"):
        value = os.environ.get(key)
        if value:
            roots.append(value)
    home = os.path.expanduser("~")
    if home:
        roots.append(os.path.join(home, ".config"))
        roots.append(home)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        roots.insert(0, xdg)
    seen = []
    for item in roots:
        if item and item not in seen:
            seen.append(item)
    return seen

def _client_name_candidates(client):
    mapping = {
        "opencode": ["opencode", "open-code", "open_code"],
        "roo-code": ["roo-code", "roo", "roocode"],
        "trae": ["trae"],
        "claude-code": ["claude-code", "claude", "claudecode"],
        "cline": ["cline"],
    }
    return mapping.get(client, [client])

def _candidate_paths(client):
    names = _client_name_candidates(client)
    roots = _config_roots()
    paths = []
    if client == "trae":
        appdata = os.environ.get("APPDATA")
        if appdata:
            paths.append(os.path.join(appdata, "trae", "user", "mcp.json"))
        home = os.path.expanduser("~")
        if home:
            paths.append(os.path.join(home, "trae", "user", "mcp.json"))
    
    if client == "opencode":
        home = os.path.expanduser("~")
        if home:
            paths.append(os.path.join(home, ".config", "opencode", "opencode.json"))

    for root in roots:
        for name in names:
            paths.extend([
                os.path.join(root, name, "mcp.json"),
                os.path.join(root, name, "mcp_servers.json"),
                os.path.join(root, name, "config.json"),
                os.path.join(root, f".{name}", "mcp.json"),
                os.path.join(root, name, "opencode.json"),
            ])
    return paths

def _find_existing_config(client):
    for path in _candidate_paths(client):
        if os.path.isfile(path):
            return path
    return None

def _default_config_path(client):
    roots = _config_roots()
    base = roots[0] if roots else "."
    name = _client_name_candidates(client)[0]
    if client == "trae":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return os.path.join(appdata, "trae", "user", "mcp.json")
        home = os.path.expanduser("~")
        if home:
            return os.path.join(home, "trae", "user", "mcp.json")
    
    if client == "opencode":
        home = os.path.expanduser("~")
        if home:
             return os.path.join(home, ".config", "opencode", "opencode.json")

    return os.path.join(base, name, "mcp.json")

def install_main():
    parser = argparse.ArgumentParser(description="Generate MCP client config files")
    parser.add_argument("--client", action="append", default=[], help="Supported clients: opencode, roo-code, trae, claude-code, cline")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--project", default=".")
    parser.add_argument("--python", dest="python_cmd", default=sys.executable)
    parser.add_argument("--url", default="http://127.0.0.1:8765/mcp")
    parser.add_argument("--output", default="auto")
    args = parser.parse_args()

    raw_clients = []
    for item in args.client:
        raw_clients.extend([c for c in item.split(",") if c.strip()])
    if raw_clients:
        clients = []
        for c in raw_clients:
            norm = _normalize_client(c)
            if not norm:
                raise SystemExit(f"Unsupported client: {c}")
            if norm not in clients:
                clients.append(norm)
    else:
        clients = ["opencode", "roo-code", "trae", "claude-code", "cline"]

    def get_payload(client):
        is_opencode = (client == "opencode")
        if args.transport == "stdio":
            if is_opencode:
                return _build_opencode_stdio_config(os.path.abspath(args.project), args.python_cmd, "aida-mcp")
            else:
                return _build_stdio_config(os.path.abspath(args.project), args.python_cmd, "aida-mcp")
        else:
            if is_opencode:
                return _build_opencode_http_config(args.url, "aida-mcp")
            else:
                return _build_http_config(args.url, "aida-mcp")

    def merge(client, existing, payload):
        if client == "opencode":
            return _merge_opencode_config(existing, payload)
        else:
            return _merge_config(existing, payload)

    output = args.output
    if output == "-":
        target_client = clients[0] if clients else "claude-code"
        payload = get_payload(target_client)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    if output != "auto":
        output_is_file = output.lower().endswith(".json")
        if output_is_file and len(clients) > 1:
            raise SystemExit("Output is a file but multiple clients were selected")

        if output_is_file:
            target_client = clients[0] if clients else "claude-code"
            payload = get_payload(target_client)
            _write_json(output, payload)
            print(output)
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return

        os.makedirs(output, exist_ok=True)
        for client in clients:
            filename = f"mcp_{client}.json"
            path = os.path.join(output, filename)
            payload = get_payload(client)
            _write_json(path, payload)
            print(f"{client}: {path}")
        return

    for client in clients:
        existing_path = _find_existing_config(client)
        payload = get_payload(client)
        
        if existing_path:
            existing = _read_json(existing_path)
            merged = merge(client, existing, payload)
            _write_json(existing_path, merged)
            print(f"{client}: {existing_path}")
        else:
            target = _default_config_path(client)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            _write_json(target, payload)
            print(f"{client}: {target}")

def main():
    if len(sys.argv) < 2:
        _print_main_help()
        sys.exit(1)

    command = sys.argv[1]
    
    # Check if user is asking for help on the main command
    if command in ("-h", "--help"):
        _print_main_help()
        sys.exit(0)

    # Remove command from argv so sub-scripts don't see it
    # We keep sys.argv[0] as the program name
    del sys.argv[1]

    if command == "export":
        export_cmd.main()
    elif command == "serve":
        server_cmd.main()
    elif command == "config":
        config_main()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: export, serve, config")
        sys.exit(1)

if __name__ == "__main__":
    main()

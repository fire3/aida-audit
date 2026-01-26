import sys
import os
import json
import argparse
import re
import shutil
from . import export_cmd
from . import server_cmd

def _print_main_help():
    print("Usage: aida-cli <command> [args]")
    print("Commands:")
    print("  export  - Export MCP database")
    print("  serve   - Start MCP server")
    print("  install - Generate MCP client config")
    print("  workspace - Initialize a local workspace")

def _build_opencode_stdio_config(project, python_cmd, server_name):
    command = python_cmd
    if os.name == "nt" and " " in command:
        command = "python"
    return {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            server_name: {
                "type": "local",
                "command": [command, "-m", "aida_cli.mcp_stdio_server", "--project", project],
                "enabled": True,
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
    base = "aida-cli"
    if base not in existing:
        return base
    idx = 2
    while f"{base}-{idx}" in existing:
        idx += 1
    return f"{base}-{idx}"

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

def _candidate_paths():
    roots = _config_roots()
    paths = []
    home = os.path.expanduser("~")
    if home:
        paths.append(os.path.join(home, ".config", "opencode", "opencode.json"))

    for root in roots:
        paths.extend([
            os.path.join(root, "opencode", "opencode.json"),
            os.path.join(root, "opencode.json"),
        ])
    return paths

def _find_existing_config():
    for path in _candidate_paths():
        if os.path.isfile(path):
            return path
    return None

def _default_config_path():
    roots = _config_roots()
    base = roots[0] if roots else "."
    home = os.path.expanduser("~")
    if home:
         return os.path.join(home, ".config", "opencode", "opencode.json")

    return os.path.join(base, "opencode", "opencode.json")

def config_main():
    parser = argparse.ArgumentParser(description="Generate MCP client config files")
    parser.add_argument("--transport", choices=["stdio", "http"], default="http")
    parser.add_argument("--project", default=".")
    parser.add_argument("--python", dest="python_cmd", default=sys.executable)
    parser.add_argument("--url", default="http://127.0.0.1:8765/mcp")
    parser.add_argument("--output", default="auto")
    args = parser.parse_args()

    def get_payload():
        if args.transport == "stdio":
            return _build_opencode_stdio_config(os.path.abspath(args.project), args.python_cmd, "aida-cli")
        return _build_opencode_http_config(args.url, "aida-cli")

    output = args.output
    if output == "-":
        payload = get_payload()
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    if output != "auto":
        if output.lower().endswith(".json"):
            payload = get_payload()
            _write_json(output, payload)
            print(output)
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return

        os.makedirs(output, exist_ok=True)
        path = os.path.join(output, "opencode.json")
        payload = get_payload()
        _write_json(path, payload)
        print(f"opencode: {path}")
        return

    existing_path = _find_existing_config()
    payload = get_payload()
    if existing_path:
        existing = _read_json(existing_path)
        merged = _merge_opencode_config(existing, payload)
        _write_json(existing_path, merged)
        print(f"opencode: {existing_path}")
    else:
        target = _default_config_path()
        os.makedirs(os.path.dirname(target), exist_ok=True)
        _write_json(target, payload)
        print(f"opencode: {target}")

def _skills_root_candidates():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return [
        os.path.join(current_dir, "skills"),
        os.path.abspath(os.path.join(current_dir, "..", "..", "skills")),
    ]

def _resolve_skills_root():
    for candidate in _skills_root_candidates():
        if os.path.isdir(candidate):
            return candidate
    return None

def _copy_skills(skills_root, target_root):
    if not skills_root or not os.path.isdir(skills_root):
        return []
    copied = []
    for name in os.listdir(skills_root):
        source_dir = os.path.join(skills_root, name)
        if not os.path.isdir(source_dir):
            continue
        if not os.path.isfile(os.path.join(source_dir, "SKILL.md")):
            continue
        target_dir = os.path.join(target_root, name)
        shutil.copytree(source_dir, target_dir, dirs_exist_ok=True)
        copied.append(name)
    return copied

def workspace_main():
    parser = argparse.ArgumentParser(description="Initialize a local MCP workspace")
    parser.add_argument("--init", required=True, help="Workspace directory to initialize")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--python", dest="python_cmd", default=sys.executable)
    parser.add_argument("--url", default="http://127.0.0.1:8765/mcp")
    args = parser.parse_args()

    workspace_root = os.path.abspath(args.init)
    project_root = os.path.join(workspace_root, "project")
    opencode_skills_root = os.path.join(workspace_root, ".opencode", "skills")
    os.makedirs(project_root, exist_ok=True)
    os.makedirs(opencode_skills_root, exist_ok=True)

    def get_payload():
        if args.transport == "stdio":
            return _build_opencode_stdio_config(project_root, args.python_cmd, "aida-cli")
        return _build_opencode_http_config(args.url, "aida-cli")

    payload = get_payload()
    path = os.path.join(workspace_root, "opencode.json")
    _write_json(path, payload)
    print(f"opencode: {path}")

    skills_source = _resolve_skills_root()
    copied = []
    if skills_source:
        copied.extend(_copy_skills(skills_source, opencode_skills_root))
        print(f"skills: {opencode_skills_root}")
    else:
        print("skills: not found")

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
    elif command == "workspace":
        workspace_main()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: export, serve, config, workspace")
        sys.exit(1)

if __name__ == "__main__":
    main()

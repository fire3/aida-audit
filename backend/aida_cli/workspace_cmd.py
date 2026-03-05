import sys
import os
import json
import argparse
import shutil


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


def _write_json(path, payload):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")


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


def _build_mcp_http_config(url):
    return {
        "mcpServers": {
            "aida": {
                "type": "http",
                "url": url
            }
        }
    }


def _build_claude_settings():
    return {
        "permissions": {
            "allow": [
                "mcp__aida__*"
            ]
        },
        "enableAllProjectMcpServers": True,
        "enabledMcpjsonServers": [
            "aida"
        ]
    }


def init_workspace(workspace_root, url="http://127.0.0.1:8765/mcp"):
    workspace_root = os.path.abspath(workspace_root)
    opencode_skills_root = os.path.join(workspace_root, ".opencode", "skills")
    os.makedirs(opencode_skills_root, exist_ok=True)

    path = os.path.join(workspace_root, "opencode.json")
    _write_json(path, _build_opencode_http_config(url, "aida-cli"))

    mcp_json_path = os.path.join(workspace_root, ".mcp.json")
    _write_json(mcp_json_path, _build_mcp_http_config(url))

    claude_dir = os.path.join(workspace_root, ".claude")
    os.makedirs(claude_dir, exist_ok=True)
    settings_path = os.path.join(claude_dir, "settings.local.json")
    _write_json(settings_path, _build_claude_settings())

    skills_source = _resolve_skills_root()
    copied = []
    if skills_source:
        copied.extend(_copy_skills(skills_source, opencode_skills_root))

    return {
        "opencode": path,
        "mcp": mcp_json_path,
        "claude": settings_path,
        "skills_dir": opencode_skills_root if skills_source else None,
        "copied_skills": copied,
    }


def main():
    parser = argparse.ArgumentParser(description="Initialize a local MCP workspace")
    parser.add_argument("--init", required=True, default=".", help="Workspace directory to initialize")
    parser.add_argument("--python", dest="python_cmd", default=sys.executable)
    parser.add_argument("--url", default="http://127.0.0.1:8765/mcp")
    args = parser.parse_args()

    result = init_workspace(args.init, url=args.url)
    print(f"opencode: {result['opencode']}")
    print(f"mcp: {result['mcp']}")
    print(f"claude: {result['claude']}")
    if result["skills_dir"]:
        print(f"skills: {result['skills_dir']}")
    else:
        print("skills: not found")


if __name__ == "__main__":
    main()

import argparse
import os
import sys
import time
import json
import requests
import subprocess
import signal
from typing import Optional
from .audit_database import AuditDatabase
from .constants import AUDIT_DB_FILENAME

OPENCODE_PORT = 4096
OPENCODE_URL = f"http://localhost:{OPENCODE_PORT}"

def ensure_opencode_config(project_path: str):
    """Ensure aida-cli is registered in opencode config."""
    from . import cli
    # We reuse the logic from cli.py, but we need to import it or copy it.
    # Since cli.py has _build_opencode_stdio_config and logic to find config path,
    # we can try to use it.
    
    # Construct the config payload
    python_cmd = sys.executable
    payload = cli._build_opencode_stdio_config(os.path.abspath(project_path), python_cmd, "aida-cli")
    
    # Find existing config or default path
    existing_path = cli._find_existing_config()
    target_path = existing_path or cli._default_config_path()
    
    if os.path.exists(target_path):
        try:
            with open(target_path, 'r') as f:
                existing = json.load(f)
        except:
            existing = {}
        merged = cli._merge_opencode_config(existing, payload)
        with open(target_path, 'w') as f:
            json.dump(merged, f, indent=2)
    else:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, 'w') as f:
            json.dump(payload, f, indent=2)
            
    print(f"Updated OpenCode config at: {target_path}")

def start_opencode_server() -> Optional[subprocess.Popen]:
    """Start opencode server if not running."""
    try:
        requests.get(f"{OPENCODE_URL}/global/health", timeout=1)
        print("OpenCode server is already running.")
        return None
    except requests.exceptions.ConnectionError:
        print("Starting OpenCode server...")
        # Assuming 'opencode' is in PATH
        process = subprocess.Popen(
            ["opencode", "serve", "--port", str(OPENCODE_PORT)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid 
        )
        # Wait for it to come up
        for _ in range(10):
            try:
                requests.get(f"{OPENCODE_URL}/global/health", timeout=1)
                print("OpenCode server started.")
                return process
            except requests.exceptions.ConnectionError:
                time.sleep(1)
        raise RuntimeError("Failed to start OpenCode server")

def load_agent_prompt() -> str:
    """Load the system prompt from AGENTS.md."""
    template_path = os.path.join(os.path.dirname(__file__), "templates", "AGENTS.md")
    with open(template_path, 'r') as f:
        return f.read()

def check_export_exists(project_path: str) -> bool:
    """Check if the project directory contains exported DB files."""
    if not os.path.exists(project_path):
        return False
    
    # Check for binary.db or any .db file that looks like an export
    has_db = False
    for fname in os.listdir(project_path):
        if fname.endswith(".db") and fname != AUDIT_DB_FILENAME:
            has_db = True
            break
            
    return has_db

def run_audit(target: str, project_path: str):
    """Main audit loop."""
    print(f"Starting audit for: {target}")

    # Check for export
    if not check_export_exists(project_path):
        print(f"Error: No exported database found in '{project_path}'.")
        print(f"Please run 'aida-cli export {target}' first.")
        return
    
    # 1. Initialize Audit DB
    db_path = os.path.join(project_path, AUDIT_DB_FILENAME)
    audit_db = AuditDatabase(db_path)
    audit_db.connect()
    
    # 2. Ensure Config
    ensure_opencode_config(project_path)
    
    # 3. Start Server
    server_proc = start_opencode_server()
    
    try:
        # 4. Create Session
        resp = requests.post(f"{OPENCODE_URL}/session", json={"title": f"Audit: {os.path.basename(target)}"})
        resp.raise_for_status()
        session_id = resp.json()["id"]
        print(f"Created session: {session_id}")
        
        # 5. Send Initial Prompt
        system_prompt = load_agent_prompt()
        initial_message = f"""
TARGET: {target}
PROJECT_PATH: {os.path.abspath(project_path)}

{system_prompt}

Please start by checking the audit plan.
"""
        print("Sending initial prompt...")
        # Note: The API might vary. Based on web ref, POST /session/:id/message
        # Body: { parts: [...] } or just message string?
        # Web ref says: Body: { messageID?, model?, agent?, noReply?, system?, tools?, parts }
        # Let's try sending 'parts' with text.
        
        payload = {
            "parts": [{"type": "text", "text": initial_message}]
        }
        
        # Log initial message
        audit_db.add_message(session_id, "user", initial_message)

        resp = requests.post(f"{OPENCODE_URL}/session/{session_id}/message", json=payload)
        resp.raise_for_status()
        
        # Log response
        # The response format from opencode might need inspection.
        # Assuming it returns the message object which contains parts.
        resp_data = resp.json()
        if "parts" in resp_data:
            response_text = "".join([p.get("text", "") for p in resp_data["parts"] if p.get("type") == "text"])
            audit_db.add_message(session_id, "assistant", response_text)
        
        print("Agent started. Monitoring progress...")
        
        # 6. Monitor Loop
        last_log_id = 0
        while True:
            # Check Audit DB logs
            logs = audit_db.get_logs(limit=5)
            new_logs = [l for l in logs if l['id'] > last_log_id]
            for log in reversed(new_logs):
                print(f"[Agent] {log['message']}")
                last_log_id = log['id']
            
            # Check Plan status
            plans = audit_db.get_plans()
            pending = [p for p in plans if p['status'] == 'pending']
            in_progress = [p for p in plans if p['status'] == 'in_progress']
            failed = [p for p in plans if p['status'] == 'failed']
            
            if not pending and not in_progress and plans:
                print("All plans completed!")
                break
                
            if failed:
                print(f"Warning: {len(failed)} tasks failed.")
                
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("Stopping audit...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if server_proc:
            os.killpg(os.getpgid(server_proc.pid), signal.SIGTERM)
        audit_db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target binary or directory to audit")
    parser.add_argument("--project", default=".", help="Project directory")
    args = parser.parse_args()
    
    run_audit(args.target, args.project)

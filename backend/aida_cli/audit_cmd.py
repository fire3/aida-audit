import argparse
import os
import sys
import time
import json
import traceback
from typing import Optional, List, Dict, Any

from .config import Config
from .llm_client import LLMClient
from .mcp_client import HttpMcpClient, StdioMcpClient, McpClient
from .audit_database import AuditDatabase
from .constants import AUDIT_DB_FILENAME

def load_agent_prompt() -> str:
    """Load the system prompt from AGENTS.md."""
    template_path = os.path.join(os.path.dirname(__file__), "templates", "AGENTS.md")
    try:
        with open(template_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print("Warning: AGENTS.md not found, using default prompt.")
        return "You are a helpful security auditor."

def get_tools_for_llm(mcp_client: McpClient) -> List[Dict[str, Any]]:
    """Fetch tools from MCP and convert to OpenAI tool format."""
    mcp_tools = mcp_client.list_tools()
    llm_tools = []
    for tool in mcp_tools:
        llm_tools.append({
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["inputSchema"]
            }
        })
    return llm_tools

def run_audit(project_path: str):
    config = Config()
    run_audit_loop(project_path, config)

def run_audit_loop(project_path: str, config: Config):
    # 1. Initialize Audit DB
    db_path = os.path.join(project_path, AUDIT_DB_FILENAME)
    audit_db = AuditDatabase(db_path)
    audit_db.connect()

    # 2. Check LLM Config first
    api_key = config.get_llm_api_key()
    if not api_key:
        print("Error: LLM API Key not found.")
        print("Please run 'aida_cli config' to set up your LLM configuration.")
        audit_db.close()
        return

    # 3. Initialize MCP Client
    print("Initializing MCP Client...")
    mcp_transport = config.mcp.get("transport", "http")
    if mcp_transport == "http":
        url = config.mcp.get("url", "http://127.0.0.1:8765/mcp")
        mcp_client = HttpMcpClient(url)
    else:
        cmd = config.mcp.get("command", ["aida_cli", "serve"])
        cwd = config.mcp.get("working_directory", ".")
        mcp_client = StdioMcpClient(cmd, cwd=os.path.abspath(cwd))
        mcp_client.start()

    try:
        mcp_client.initialize()
        tools = get_tools_for_llm(mcp_client)
        print(f"Loaded {len(tools)} tools from MCP.")
    except Exception as e:
        print(f"Failed to initialize MCP: {e}")
        print("Please ensure the MCP server is running (try 'aida_cli serve').")
        audit_db.close()
        return
    
    # 4. Initialize LLM Client
    llm_client = LLMClient(
        base_url=config.get_llm_base_url(),
        api_key=api_key,
        model=config.get_llm_model()
    )

    # 4. Prepare Conversation
    system_prompt = load_agent_prompt()
    initial_context = f"PROJECT_PATH: {os.path.abspath(project_path)}"
    
    messages = [
        {"role": "system", "content": f"{initial_context}\n\n{system_prompt}"},
        {"role": "user", "content": "Please start the audit by checking the audit plan."}
    ]
    
    session_id = f"audit-{int(time.time())}"
    print(f"Starting audit session: {session_id}")

    # 5. Main Loop
    turn_count = 0
    max_turns = 100 # Safety limit

    try:
        while turn_count < max_turns:
            turn_count += 1
            print(f"\n--- Turn {turn_count} ---")
            
            # Call LLM
            try:
                response = llm_client.chat_completion(messages, tools=tools)
            except Exception as e:
                print(f"LLM Call Failed: {e}")
                time.sleep(5)
                continue

            message = response["choices"][0]["message"]
            messages.append(message)
            
            content = message.get("content")
            tool_calls = message.get("tool_calls")

            # Log content
            if content:
                print(f"[Assistant]: {content}")
                audit_db.add_message(session_id, "assistant", content)

            if not tool_calls:
                # If no tools called, maybe we are done or waiting for user?
                # For automated audit, we usually expect continuous action until 'done'.
                # But let's just wait a bit to avoid rapid loops if it hallucinates.
                # Or prompts user input?
                # For now, let's just break if it says "I am done" or similar, but simpler to just pause.
                if content and "audit complete" in content.lower():
                    print("Audit appears complete.")
                    break
                # If just talking, maybe continue?
                # If it stops calling tools, we might need to prompt it to continue?
                # Let's add a "continue" user message if it stops?
                # But risky. Let's just pause.
                pass

            # Handle Tool Calls
            if tool_calls:
                for tool_call in tool_calls:
                    func_name = tool_call["function"]["name"]
                    args_str = tool_call["function"]["arguments"]
                    call_id = tool_call["id"]
                    
                    print(f"[Tool Call] {func_name}({args_str})")
                    
                    try:
                        args = json.loads(args_str)
                        result = mcp_client.call_tool(func_name, args)
                        
                        # Format result
                        if isinstance(result, (dict, list)):
                            result_str = json.dumps(result, ensure_ascii=False)
                        else:
                            result_str = str(result)
                            
                        # Truncate if too long
                        if len(result_str) > 5000:
                            result_str = result_str[:5000] + "... (truncated)"
                            
                    except Exception as e:
                        print(f"[Tool Error] {e}")
                        result_str = f"Error: {str(e)}"

                    # Append result
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": result_str
                    })
                    print(f"[Tool Result] Length: {len(result_str)}")

    except KeyboardInterrupt:
        print("\nAudit stopped by user.")
    except Exception as e:
        print(f"Fatal Error: {e}")
        traceback.print_exc()
    finally:
        if isinstance(mcp_client, StdioMcpClient):
            mcp_client.stop()
        audit_db.close()

def main():
    parser = argparse.ArgumentParser(description="AIDA Audit Command")
    parser.add_argument("project", nargs="?", default=".", help="Project directory")
    parser.add_argument("--config", help="Path to config file")
    parser.add_argument("--api-key", help="LLM API Key")
    parser.add_argument("--url", help="LLM Base URL")
    parser.add_argument("--model", help="LLM Model")
    args = parser.parse_args()

    project_path = os.path.abspath(args.project)
    audit_db_path = os.path.join(project_path, AUDIT_DB_FILENAME)
    if not os.path.exists(audit_db_path):
        print(f"Error: No audit database found at {audit_db_path}")
        print("Please run 'export' with this directory as the output first.")
        sys.exit(1)

    # Load Config
    config = Config(args.config)
    
    # Apply CLI overrides
    if args.api_key:
        config.data["llm"]["api_key"] = args.api_key
    if args.url:
        config.data["llm"]["base_url"] = args.url
    if args.model:
        config.data["llm"]["model"] = args.model

    run_audit_loop(args.project, config)

if __name__ == "__main__":
    main()

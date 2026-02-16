import os
import time
import json
import traceback
import threading
from typing import Optional, List, Dict, Any

from .config import Config
from .llm_client import LLMClient
from .mcp_client import HttpMcpClient, StdioMcpClient, McpClient
from .audit_database import AuditDatabase

def load_agent_prompt(agent_name: str) -> str:
    """Load the system prompt from templates."""
    filename = f"{agent_name}.md"
    template_path = os.path.join(os.path.dirname(__file__), "templates", filename)
    try:
        with open(template_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Warning: {filename} not found, using default prompt.")
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

class AuditService:
    def __init__(self, project_path: str, audit_db: AuditDatabase):
        self.project_path = project_path
        self.audit_db = audit_db
        self.status = "idle"  # idle, running, completed, failed
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._error: Optional[str] = None
        self.current_session_id: Optional[str] = None
        self.current_agent: Optional[str] = None

    def start(self):
        if self.status == "running":
            return
        
        self._stop_event.clear()
        self.status = "running"
        self._error = None
        self._thread = threading.Thread(target=self._run_loop)
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        if self.status == "running":
            self._stop_event.set()
            # We don't wait for join here to avoid blocking the API response
            # The loop will detect stop_event and exit

    def get_status(self):
        return {
            "status": self.status,
            "error": self._error,
            "current_session_id": self.current_session_id,
            "current_agent": self.current_agent
        }

    def _run_loop(self):
        mcp_client = None
        try:
            config = Config()
            
            # 1. Check LLM Config
            api_key = config.get_llm_api_key()
            if not api_key:
                raise ValueError("LLM API Key not found. Please configure it via CLI or settings.")

            # 2. Initialize MCP Client
            mcp_transport = config.mcp.get("transport", "http")
            if mcp_transport == "http":
                port = os.environ.get("AIDA_MCP_PORT", "8765")
                url = config.mcp.get("url", f"http://127.0.0.1:{port}/mcp")
                mcp_client = HttpMcpClient(url)
            else:
                cmd = config.mcp.get("command", ["aida_cli", "serve"])
                cwd = config.mcp.get("working_directory", ".")
                mcp_client = StdioMcpClient(cmd, cwd=os.path.abspath(cwd))
                mcp_client.start()

            try:
                mcp_client.initialize()
                tools = get_tools_for_llm(mcp_client)
                self.audit_db.log_progress(f"Audit Service: Connected to MCP, loaded {len(tools)} tools.")
            except Exception as e:
                raise RuntimeError(f"Failed to initialize MCP: {e}")

            # 3. Initialize LLM Client
            llm_client = LLMClient(
                base_url=config.get_llm_base_url(),
                api_key=api_key,
                model=config.get_llm_model()
            )

            # 4. Alternating Loop
            while not self._stop_event.is_set():
                # Step 1: Run Plan Agent
                self.audit_db.log_progress("Starting Planning Phase...")
                self._run_session("PLAN_AGENT", llm_client, tools, mcp_client)
                
                if self._stop_event.is_set():
                    break

                # Step 2: Run Audit Agent
                self.audit_db.log_progress("Starting Execution Phase...")
                self._run_session("AUDIT_AGENT", llm_client, tools, mcp_client)

                # Optional: Sleep briefly between sessions
                time.sleep(2)

        except Exception as e:
            self.status = "failed"
            self._error = str(e)
            traceback.print_exc()
            if self.audit_db:
                try:
                    self.audit_db.log_progress(f"Audit Service Failed: {e}")
                except:
                    pass
        finally:
            if mcp_client and isinstance(mcp_client, StdioMcpClient):
                mcp_client.stop()
            
            if self.status == "running":
                 if self._stop_event.is_set():
                     self.status = "idle"
                 else:
                     self.status = "completed"

    def _run_session(self, agent_name: str, llm_client: LLMClient, tools: List[Dict], mcp_client: McpClient):
        # Load Prompt
        system_prompt = load_agent_prompt(agent_name)
        initial_context = f"PROJECT_PATH: {os.path.abspath(self.project_path)}"
        
        messages = [
            {"role": "system", "content": f"{initial_context}\n\n{system_prompt}"},
            {"role": "user", "content": "Please start your session."}
        ]
        
        session_id = f"{agent_name.lower()}-{int(time.time())}"
        self.current_session_id = session_id
        self.current_agent = agent_name
        self.audit_db.log_progress(f"Starting session: {session_id} ({agent_name})")

        turn_count = 0
        max_turns = 50 # Limit per session to avoid infinite loops

        while turn_count < max_turns:
            if self._stop_event.is_set():
                self.audit_db.log_progress("Audit stopped by user.")
                break

            turn_count += 1
            
            # Call LLM
            try:
                response = llm_client.chat_completion(messages, tools=tools)
            except Exception as e:
                self.audit_db.log_progress(f"LLM Call Failed: {e}")
                time.sleep(5)
                continue

            message = response["choices"][0]["message"]
            messages.append(message)
            
            content = message.get("content")
            tool_calls = message.get("tool_calls")

            # Log content
            if content:
                self.audit_db.add_message(session_id, "assistant", content)

            # Check for completion signal
            if not tool_calls:
                # If LLM says "audit complete" or just finishes without tool calls, end session
                # But we should be careful. Sometimes it just talks.
                # However, for these specific agents, we instructed them to end session.
                # Let's assume if it returns text without tool calls, it might be done or asking for info.
                # But usually, if it's "Plan Agent", it adds plans then says "Done".
                # If it's "Audit Agent", it does work then says "Done".
                # So if no tool calls, we can probably check for keywords or just continue if it looks like a question?
                # Actually, our prompt says "Your session should end...". 
                # Let's just break if no tool calls are present, assuming it's a "summary" message.
                if content:
                    # Log it as progress too so it appears in logs
                    self.audit_db.log_progress(f"[{agent_name}] {content[:200]}...")
                
                # We break the session loop here to yield control back to the outer loop (switch agent)
                break

            # Handle Tool Calls
            if tool_calls:
                for tool_call in tool_calls:
                    if self._stop_event.is_set():
                        break

                    func_name = tool_call["function"]["name"]
                    args_str = tool_call["function"]["arguments"]
                    call_id = tool_call["id"]
                    
                    # Log tool call
                    try:
                        tool_call_json = json.dumps({
                            "name": func_name,
                            "arguments": json.loads(args_str)
                        })
                        self.audit_db.add_message(session_id, "tool_call", tool_call_json)
                    except:
                        self.audit_db.add_message(session_id, "tool_call", f"{func_name}({args_str})")
                    
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
                        
                        # Log tool result
                        self.audit_db.add_message(session_id, "tool_result", result_str)
                            
                    except Exception as e:
                        result_str = f"Error: {str(e)}"

                    # Append result
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": result_str
                    })

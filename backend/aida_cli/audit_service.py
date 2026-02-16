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
from .audit_cmd import load_agent_prompt, get_tools_for_llm

class AuditService:
    def __init__(self, project_path: str, audit_db: AuditDatabase):
        self.project_path = project_path
        self.audit_db = audit_db
        self.status = "idle"  # idle, running, completed, failed
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._error: Optional[str] = None

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
            "error": self._error
        }

    def _run_loop(self):
        try:
            self._execute_audit()
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
            if self.status == "running":
                 # If we exited naturally without exception and status is still running
                 # (e.g. stopped or finished), update it.
                 # If stopped, it might be better to say "stopped" or "idle"?
                 # User wants to know if it's running.
                 if self._stop_event.is_set():
                     self.status = "idle"
                 else:
                     # Completed naturally
                     self.status = "completed"

    def _execute_audit(self):
        config = Config()
        
        # 1. We already have audit_db connected
        
        # 2. Check LLM Config
        api_key = config.get_llm_api_key()
        if not api_key:
            raise ValueError("LLM API Key not found. Please configure it via CLI or settings.")

        # 3. Initialize MCP Client
        # We assume the server is running on the default port or configured port.
        # Since we are running INSIDE the server process, we can try to find the port.
        # But for now let's use the config or default.
        mcp_transport = config.mcp.get("transport", "http")
        if mcp_transport == "http":
            port = os.environ.get("AIDA_MCP_PORT", "8765")
            url = config.mcp.get("url", f"http://127.0.0.1:{port}/mcp")
            mcp_client = HttpMcpClient(url)
        else:
            # Stdio doesn't make sense here as we are the server, 
            # but if configured to use ANOTHER server via stdio... rare.
            # Let's fallback to http default if inside server?
            # Actually, let's just stick to config.
            cmd = config.mcp.get("command", ["aida_cli", "serve"])
            cwd = config.mcp.get("working_directory", ".")
            mcp_client = StdioMcpClient(cmd, cwd=os.path.abspath(cwd))
            mcp_client.start()

        try:
            mcp_client.initialize()
            tools = get_tools_for_llm(mcp_client)
            self.audit_db.log_progress(f"Audit Service: Connected to MCP, loaded {len(tools)} tools.")
        except Exception as e:
            if isinstance(mcp_client, StdioMcpClient):
                mcp_client.stop()
            raise RuntimeError(f"Failed to initialize MCP: {e}")

        # 4. Initialize LLM Client
        llm_client = LLMClient(
            base_url=config.get_llm_base_url(),
            api_key=api_key,
            model=config.get_llm_model()
        )

        # 5. Prepare Conversation
        system_prompt = load_agent_prompt()
        initial_context = f"PROJECT_PATH: {os.path.abspath(self.project_path)}"
        
        messages = [
            {"role": "system", "content": f"{initial_context}\n\n{system_prompt}"},
            {"role": "user", "content": "Please start the audit by checking the audit plan."}
        ]
        
        session_id = f"audit-service-{int(time.time())}"
        self.audit_db.log_progress(f"Starting audit session: {session_id}")

        # 6. Main Loop
        turn_count = 0
        max_turns = 100 

        try:
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

                if not tool_calls:
                    if content and "audit complete" in content.lower():
                        self.audit_db.log_progress("Audit completed by Agent.")
                        break
                    pass

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
        finally:
            if isinstance(mcp_client, StdioMcpClient):
                mcp_client.stop()
            # Do NOT close audit_db as it is shared

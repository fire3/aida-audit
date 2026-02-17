import os
import time
import json
import traceback
import threading
from typing import Optional, List, Dict, Any, Callable

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
        return "你是一位专业的安全审计专家。"

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
    tool_names = [t["function"]["name"] for t in llm_tools]
    print(f"[DEBUG] Available tools: {tool_names}")
    return llm_tools

class BaseAgent:
    project_store = None
    
    def __init__(self, 
                 llm_client: LLMClient, 
                 mcp_client: McpClient, 
                 audit_db: AuditDatabase, 
                 project_path: str,
                 tools: List[Dict],
                 project_store=None,
                 on_session_start: Optional[Callable[[str, str], None]] = None,
                 on_message: Optional[Callable[[str, str, str], None]] = None,
                 on_session_end: Optional[Callable[[str], None]] = None):
        self.llm_client = llm_client
        self.mcp_client = mcp_client
        self.audit_db = audit_db
        self.project_path = project_path
        self.all_tools = tools
        self.project_store = project_store
        self.on_session_start = on_session_start
        self.on_message = on_message
        self.on_session_end = on_session_end
        self.session_id: Optional[str] = None
        
    @property
    def name(self) -> str:
        raise NotImplementedError
        
    def get_system_prompt(self) -> str:
        return load_agent_prompt(self.name)
        
    def get_initial_message(self) -> str:
        return ""
    
    def get_initial_context(self) -> str:
        return ""
        
    def get_tools(self) -> List[Dict]:
        return self.all_tools

    def _add_message(self, session_id: str, role: str, content: str):
        """Add message to memory and trigger callback for real-time display."""
        self._session_messages.append({"role": role, "content": content})
        if self.on_message:
            self.on_message(session_id, role, content)
        
    def _flush_messages_to_db(self):
        """Write accumulated messages to database (only on normal end)."""
        if not self.session_id:
            return
        for msg in self._session_messages:
            self.audit_db.add_message(self.session_id, msg["role"], msg["content"])
        
    def run(self, stop_event: threading.Event):
        self._session_messages = []  # Reset message buffer
        
        system_prompt = self.get_system_prompt()
        initial_context = self.get_initial_context()
        
        content = self.get_initial_message()
        tools = self.get_tools()
        
        messages = [
            {"role": "system", "content": f"{initial_context}\n\n{system_prompt}"},
            {"role": "user", "content": content}
        ]
        
        self.session_id = f"{self.name.lower()}-{int(time.time())}"
        if self.on_session_start:
            self.on_session_start(self.session_id, self.name)
            
        self.audit_db.log_progress(f"开始会话: {self.session_id} ({self.name})")

        # Record initial prompts (in memory only)
        self._add_message(self.session_id, "system", f"{initial_context}\n\n{system_prompt}")
        self._add_message(self.session_id, "user", content)
        
        turn_count = 0
        max_turns = 200

        while turn_count < max_turns:
            if stop_event.is_set():
                self.audit_db.log_progress(f"[{self.name}] 会话结束: 用户停止 (第 {turn_count} 轮)")
                self._session_messages = []  # Discard messages on stop
                break

            turn_count += 1
            
            # Call LLM with streaming
            accumulated_content = ""
            accumulated_reasoning = ""
            tool_calls_buffer = []
            
            try:
                for chunk in self.llm_client.chat_completion_stream(messages, tools=tools):
                    # Check stop event during streaming
                    if stop_event.is_set():
                        self.audit_db.log_progress(f"[{self.name}] 会话中断: 用户停止 (第 {turn_count} 轮)")
                        self._session_messages = []  # Discard messages on stop
                        break
                    
                    # Handle non-choice chunks (log, heartbeat, etc.)
                    if "choices" not in chunk or not chunk["choices"]:
                        continue
                        
                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                    
                    # Accumulate content
                    if delta.get("content"):
                        accumulated_content += delta["content"]
                    if delta.get("reasoning"):
                        accumulated_reasoning += delta["reasoning"]
                    if delta.get("reasoning_content"):
                        accumulated_reasoning += delta["reasoning_content"]
                    
                    # Handle tool calls in streaming
                    if delta.get("tool_calls"):
                        for tc in delta["tool_calls"]:
                            if "index" in tc:
                                idx = tc["index"]
                                while len(tool_calls_buffer) <= idx:
                                    tool_calls_buffer.append({"function": {"arguments": ""}})
                                if tc.get("function"):
                                    if "name" in tc["function"]:
                                        tool_calls_buffer[idx]["function"]["name"] = tc["function"]["name"]
                                    if "arguments" in tc["function"]:
                                        tool_calls_buffer[idx]["function"]["arguments"] += tc["function"]["arguments"]
                            elif "id" in tc:
                                idx = len(tool_calls_buffer) - 1
                                if idx >= 0:
                                    tool_calls_buffer[idx]["id"] = tc["id"]
                                    
                # Check if we broke due to stop event
                if stop_event.is_set():
                    self._session_messages = []  # Discard messages
                    break
                    
            except Exception as e:
                self.audit_db.log_progress(f"LLM 调用失败: {e}")
                self._session_messages = []  # Discard messages on error
                time.sleep(5)
                continue

            # Build message for history
            message = {"role": "assistant"}
            final_content = accumulated_content
            if accumulated_reasoning:
                if "<think>" not in final_content:
                    final_content = f"<think>{accumulated_reasoning}</think>\n\n{final_content}".strip()
            if final_content:
                message["content"] = final_content
            
            # Build proper tool_calls structure
            valid_tool_calls = []
            for tc in tool_calls_buffer:
                if tc.get("function", {}).get("name") and tc.get("function", {}).get("arguments"):
                    try:
                        # Ensure arguments is valid JSON
                        args = json.loads(tc["function"]["arguments"])
                        valid_tool_calls.append({
                            "id": tc.get("id", f"call_{int(time.time() * 1000)}"),
                            "type": "function",
                            "function": {
                                "name": tc["function"]["name"],
                                "arguments": json.dumps(args)
                            }
                        })
                    except json.JSONDecodeError:
                        # Skip invalid tool calls
                        pass
            
            if valid_tool_calls:
                message["tool_calls"] = valid_tool_calls
                
            messages.append(message)
            
            content = message.get("content")
            tool_calls = message.get("tool_calls")

            # Log content
            if content:
                self._add_message(self.session_id, "assistant", content)

            # Check for completion signal
            if not tool_calls:
                if content:
                    self.audit_db.log_progress(f"[{self.name}] 会话结束: 正常完成 (第 {turn_count} 轮)")
                else:
                    self.audit_db.log_progress(f"[{self.name}] 会话结束: 无响应 (第 {turn_count} 轮)")
                break

            # Handle Tool Calls
            if tool_calls:
                for tool_call in tool_calls:
                    if stop_event.is_set():
                        self.audit_db.log_progress(f"[{self.name}] 会话结束: 工具执行中停止 (第 {turn_count} 轮)")
                        break

                    func_name = tool_call["function"]["name"]
                    args_str = tool_call["function"]["arguments"]
                    call_id = tool_call.get("id", "")
                    
                    # Log tool call
                    try:
                        tool_call_json = json.dumps({
                            "name": func_name,
                            "arguments": json.loads(args_str) if args_str else {}
                        })
                        self._add_message(self.session_id, "tool_call", tool_call_json)
                    except:
                        self._add_message(self.session_id, "tool_call", f"{func_name}({args_str})")
                    
                    try:
                        args = json.loads(args_str) if args_str else {}
                        result = self.mcp_client.call_tool(func_name, args)
                        
                        if isinstance(result, (dict, list)):
                            result_str = json.dumps(result, ensure_ascii=False)
                        else:
                            result_str = str(result)
                            
                        if len(result_str) > 5000:
                            result_str = result_str[:5000] + "... (truncated)"
                        
                        self._add_message(self.session_id, "tool_result", result_str)
                            
                    except Exception as e:
                        result_str = f"Error: {str(e)}"
                        self._add_message(self.session_id, "tool_result", result_str)

                    messages.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": result_str
                    })
        
        # Log session end reason and flush messages to DB only on normal end
        # Normal end means: completed without being stopped (either normal completion or max turns reached)
        session_ended_normally = turn_count > 0 and not stop_event.is_set()
        
        if turn_count >= max_turns:
            self.audit_db.log_progress(f"[{self.name}] 会话结束: 达到最大轮数 ({max_turns})")
        
        if session_ended_normally:
            # Normal end: write messages to database
            self._flush_messages_to_db()
        
        # Notify session end (always notify)
        if self.on_session_end and self.session_id:
            self.on_session_end(self.session_id)

PLAN_AGENT_EXCLUDE = {
    'audit_create_note', 'audit_get_notes', 'audit_update_note', 'audit_delete_note',
    'audit_mark_finding', 'audit_get_findings', 'audit_get_analysis_progress',
    'audit_link_finding_to_plan', 'audit_unlink_finding_from_plan',
    'audit_get_plan_findings', 'audit_get_finding_plans',
    'audit_log_progress'
}


class PlanAgent(BaseAgent):
    def __init__(self, 
                 llm_client: LLMClient, 
                 mcp_client: McpClient, 
                 audit_db: AuditDatabase, 
                 project_path: str,
                 tools: List[Dict],
                 project_store=None,
                 on_session_start: Optional[Callable[[str, str], None]] = None,
                 on_message: Optional[Callable[[str, str, str], None]] = None,
                 on_session_end: Optional[Callable[[str], None]] = None):
        super().__init__(llm_client, mcp_client, audit_db, project_path, tools, project_store, on_session_start, on_message, on_session_end)
    
    @property
    def name(self) -> str:
        return "PLAN_AGENT"
    
    def get_system_prompt(self) -> str:
        try:
            plans = self.audit_db.get_plans(plan_type='audit_plan')
            if not plans:
                return load_agent_prompt("PLAN_AGENT_INITIAL")
            else:
                return load_agent_prompt("PLAN_AGENT_REVIEW")
        except Exception as e:
            print(f"Error checking plans: {e}")
            return load_agent_prompt("PLAN_AGENT_INITIAL")

    def get_initial_context(self) -> str:
        return f"""
请为这些二进制文件创建安全审计计划。"""
        
    def get_tools(self) -> List[Dict]:
        tools = [
            t for t in self.all_tools
            if t['function']['name'] not in PLAN_AGENT_EXCLUDE
        ]
        self.audit_db.log_progress(f"计划代理: 使用 {len(tools)} 个工具 (排除: {len(self.all_tools) - len(tools)})")
        return tools

class AuditAgent(BaseAgent):
    def __init__(self, 
                 llm_client: LLMClient, 
                 mcp_client: McpClient, 
                 audit_db: AuditDatabase, 
                 project_path: str,
                 tools: List[Dict],
                 specific_task: Optional[Dict] = None,
                 project_store=None,
                 on_session_start: Optional[Callable[[str, str], None]] = None,
                 on_message: Optional[Callable[[str, str, str], None]] = None,
                 on_session_end: Optional[Callable[[str], None]] = None):
        super().__init__(llm_client, mcp_client, audit_db, project_path, tools, project_store, on_session_start, on_message, on_session_end)
        self.specific_task = specific_task
        
    @property
    def name(self) -> str:
        return "AUDIT_AGENT"
        
    def get_tools(self) -> List[Dict]:
        plan_tools = {'audit_create_macro_plan', 'audit_plan_update', 'audit_plan_list'}
        keep_tool = 'audit_create_agent_task'
        tools = [
            t for t in self.all_tools 
            if t['function']['name'] in {keep_tool} or t['function']['name'] not in plan_tools
        ]
        self.audit_db.log_progress(f"审计代理: 使用 {len(tools)} 个工具 (排除: {len(self.all_tools) - len(tools)})")
        return tools

    def get_initial_message(self) -> str:
        if self.specific_task:
            return f"你的工作是:\n标题: {self.specific_task['title']}\n描述: {self.specific_task['description']}\nID: {self.specific_task['id']}\n\n现在请开始你的工作。"
        return "开始你的工作。"

class AuditService:
    def __init__(self, project_path: str, audit_db: AuditDatabase, on_message: Optional[Callable[[str, str, str], None]] = None, on_session_end: Optional[Callable[[str], None]] = None):
        self.project_path = project_path
        self.audit_db = audit_db
        self.on_message = on_message
        self.on_session_end = on_session_end
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

    def _update_session_info(self, session_id: str, agent_name: str):
        self.current_session_id = session_id
        self.current_agent = agent_name

    def _run_loop(self):
        mcp_client = None
        try:
            config = Config()
            
            # 1. Check LLM Config
            api_key = config.get_llm_api_key()
            if not api_key:
                raise ValueError("未找到 LLM API Key，请通过 CLI 或设置进行配置。")

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
                tool_names = [t["function"]["name"] for t in tools]
                self.audit_db.log_progress(f"审计服务: 已连接到 MCP，加载了 {len(tools)} 个工具: {tool_names}")
            except Exception as e:
                raise RuntimeError(f"MCP 初始化失败: {e}")

            # 3. Initialize LLM Client
            llm_client = LLMClient(
                base_url=config.get_llm_base_url(),
                api_key=api_key,
                model=config.get_llm_model()
            )

            # 4. Alternating Loop
            while not self._stop_event.is_set():
                # Step 1: Run Plan Agent
                self.audit_db.log_progress("开始规划阶段...")
                plan_agent = PlanAgent(
                    llm_client, 
                    mcp_client, 
                    self.audit_db, 
                    self.project_path, 
                    tools,
                    on_session_start=self._update_session_info,
                    on_message=self.on_message,
                    on_session_end=self.on_session_end
                )
                plan_agent.run(self._stop_event)
                
                if self._stop_event.is_set():
                    break

                # Step 2: Run Audit Agent
                self.audit_db.log_progress("开始执行阶段...")
                
                # Fetch pending agent plans
                pending_tasks = self.audit_db.get_plans(status="pending", plan_type="agent_plan")
                if not pending_tasks:
                     self.audit_db.log_progress("没有待执行的 Agent 任务，跳过执行阶段。")
                else:
                    task = pending_tasks[0]
                    self.audit_db.log_progress(f"正在分配任务给审计代理: {task['title']} (ID: {task['id']})")
                    
                    # Mark task as in_progress
                    self.audit_db.update_plan_status(task['id'], "in_progress")

                    audit_agent = AuditAgent(
                        llm_client,
                        mcp_client,
                        self.audit_db,
                        self.project_path,
                        tools,
                        specific_task=task,
                        on_session_start=self._update_session_info,
                        on_message=self.on_message,
                        on_session_end=self.on_session_end
                    )
                    audit_agent.run(self._stop_event)
                    
                    # Mark task as completed (assuming success if it returns)
                    self.audit_db.update_plan_status(task['id'], "completed")

                # Optional: Sleep briefly between sessions
                time.sleep(2)

        except Exception as e:
            self.status = "failed"
            self._error = str(e)
            traceback.print_exc()
            if self.audit_db:
                try:
                    self.audit_db.log_progress(f"审计服务失败: {e}")
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

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

from collections import deque

class LoopDetector:
    def __init__(self, max_history: int = 5, min_length: int = 10, threshold: float = 0.9):
        self.history = deque(maxlen=max_history)
        self.min_length = min_length
        self.threshold = threshold

    def is_looping(self, content: str) -> bool:
        if len(content) < self.min_length:
            return False
            
        # Normalize content (remove whitespace)
        normalized_content = "".join(content.split())
        
        for past_content in self.history:
            # Check for exact match or high similarity
            if normalized_content == past_content:
                return True
            
            # Simple similarity check (can be improved)
            # If one is a substring of another and length is close
            if len(past_content) > 0:
                ratio = 0.0
                if len(normalized_content) > len(past_content):
                    if past_content in normalized_content:
                         ratio = len(past_content) / len(normalized_content)
                else:
                    if normalized_content in past_content:
                         ratio = len(normalized_content) / len(past_content)
                
                if ratio > self.threshold:
                    return True

        self.history.append(normalized_content)
        return False

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
                 on_session_end: Optional[Callable[[str], None]] = None,
                 on_chunk: Optional[Callable[[str, str, str], None]] = None):
        self.llm_client = llm_client
        self.mcp_client = mcp_client
        self.audit_db = audit_db
        self.project_path = project_path
        self.all_tools = tools
        self.project_store = project_store
        self.on_session_start = on_session_start
        self.on_message = on_message
        self.on_session_end = on_session_end
        self.on_chunk = on_chunk
        self.session_id: Optional[str] = None
        self.loop_detector = LoopDetector()
        
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
        
    def run(self, stop_event: threading.Event) -> bool:
        """Run the agent session. Returns True if completed successfully, False if interrupted/failed."""
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
        session_ended_normally = False

        while turn_count < max_turns:
            if stop_event.is_set():
                self.audit_db.log_progress(f"[{self.name}] 会话结束: 用户停止 (第 {turn_count} 轮)")
                break

            turn_count += 1
            
            # Call LLM with streaming
            accumulated_content = ""
            accumulated_reasoning = ""
            tool_calls_buffer = {}  # Map index to dict
            
            try:
                for chunk in self.llm_client.chat_completion_stream(messages, tools=tools):
                    # Check stop event during streaming
                    if stop_event.is_set():
                        self.audit_db.log_progress(f"[{self.name}] 会话中断: 用户停止 (第 {turn_count} 轮)")
                        break
                    
                    chunk_type = chunk.type
                    
                    if chunk_type == 'content_block_start':
                        idx = chunk.index
                        block = chunk.content_block
                        if block.type == 'tool_use':
                            tool_calls_buffer[idx] = {
                                "id": block.id,
                                "name": block.name,
                                "arguments": ""
                            }
                    elif chunk_type == 'content_block_delta':
                        idx = chunk.index
                        delta = chunk.delta
                        if delta.type == 'text_delta':
                            text = delta.text
                            accumulated_content += text
                            if self.on_chunk:
                                self.on_chunk(self.session_id, "content", text)
                        elif delta.type == 'thinking_delta':
                            thinking = delta.thinking
                            accumulated_reasoning += thinking
                            if self.on_chunk:
                                self.on_chunk(self.session_id, "reasoning", thinking)
                        elif delta.type == 'input_json_delta':
                            if idx in tool_calls_buffer:
                                tool_calls_buffer[idx]["arguments"] += delta.partial_json

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
            full_content = ""
            if accumulated_reasoning:
                full_content += f"<think>{accumulated_reasoning}</think>\n"
            full_content += accumulated_content
            
            # Loop Detection Check
            # We check accumulated_content (the actual response) and accumulated_reasoning (the thinking)
            # If either causes a loop, we abort.
            # Usually loops happen in content or thinking.
            
            is_loop = False
            if accumulated_content and self.loop_detector.is_looping(accumulated_content):
                is_loop = True
                self.audit_db.log_progress(f"[{self.name}] 检测到内容循环输出，强制终止会话。")
            elif accumulated_reasoning and self.loop_detector.is_looping(accumulated_reasoning):
                is_loop = True
                self.audit_db.log_progress(f"[{self.name}] 检测到思考过程循环输出，强制终止会话。")
            
            if is_loop:
                 # Record what we have so far
                if full_content:
                    message["content"] = full_content
                    messages.append(message)
                    self._add_message(self.session_id, "assistant", full_content)
                
                # Force stop, do NOT mark task as completed (handled in outer loop by checking stop_event or explicit return)
                # We can simulate a stop_event or break with a flag
                # Let's set a flag to indicate abnormal termination
                self.audit_db.log_progress(f"[{self.name}] 会话因循环输出被终止 (第 {turn_count} 轮)")
                session_ended_normally = False
                break

            if full_content:
                message["content"] = full_content
            
            # Build proper tool_calls structure
            valid_tool_calls = []
            for idx in sorted(tool_calls_buffer.keys()):
                tc = tool_calls_buffer[idx]
                if tc.get("name") and tc.get("arguments"):
                    try:
                        # Ensure arguments is valid JSON
                        args = json.loads(tc["arguments"])
                        # Re-dump to normalize
                        normalized_args = json.dumps(args)
                    except json.JSONDecodeError:
                        # Keep original string if invalid, let downstream handle it
                        normalized_args = tc["arguments"]
                        
                    valid_tool_calls.append({
                        "id": tc.get("id", f"call_{int(time.time() * 1000)}"),
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": normalized_args
                        }
                    })
            
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
                    session_ended_normally = True
                else:
                    self.audit_db.log_progress(f"[{self.name}] 会话结束: 无响应 (第 {turn_count} 轮)")
                    session_ended_normally = False
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
                        self.audit_db.log_progress(f"[{self.name}] 工具执行失败: {func_name} - {str(e)}")
                        self._add_message(self.session_id, "tool_result", result_str)

                    messages.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": result_str
                    })
        
        # Log session end reason and flush messages to DB
        # Normal end means: completed without being stopped (either normal completion or max turns reached)
        # We also need to check if we broke out due to loop detection (turn_count < max_turns and not stop_event)
        # Wait, if we broke loop due to detection, we should return False
        
        # Check if we exited due to loop detection
        # The loop breaks when is_loop is True. 
        # But we don't have is_loop variable here in scope.
        # We can infer it if we didn't complete normally (no tool calls, no content, but loop ended)
        # Actually, let's track exit reason.
        
        is_loop_failure = False
        # If we broke out of loop early without stop_event and without completion signal
        # It's hard to tell without a flag.
        # Let's assume run() returns success status.
        
        if turn_count >= max_turns:
            self.audit_db.log_progress(f"[{self.name}] 会话结束: 达到最大轮数 ({max_turns})")
        
        # Always flush messages to DB (so session appears in history even when stopped)
        if turn_count > 0:
            self._flush_messages_to_db()
        
        # Notify session end (always notify)
        if self.on_session_end and self.session_id:
            self.on_session_end(self.session_id)
            
        return session_ended_normally and not stop_event.is_set()

PLAN_AGENT_EXCLUDE = {
    'audit_create_note', 'audit_update_note', 'audit_delete_note',
    'audit_mark_finding',
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
                 on_session_end: Optional[Callable[[str], None]] = None,
                 on_chunk: Optional[Callable[[str, str, str], None]] = None):
        super().__init__(llm_client, mcp_client, audit_db, project_path, tools, project_store, on_session_start, on_message, on_session_end, on_chunk)
    
    @property
    def name(self) -> str:
        try:
            plans = self.audit_db.get_plans(plan_type='audit_plan')
            if not plans:
                return "Initial Plan Agent"
            else:
                return "Review Plan Agent"
        except Exception as e:
            print(f"Error checking plans: {e}")
            return "Initial Plan Agent"
    
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
                 on_session_end: Optional[Callable[[str], None]] = None,
                 on_chunk: Optional[Callable[[str, str, str], None]] = None):
        super().__init__(llm_client, mcp_client, audit_db, project_path, tools, project_store, on_session_start, on_message, on_session_end, on_chunk)
        self.specific_task = specific_task
        
    @property
    def name(self) -> str:
        return "AUDIT_AGENT"
        
    def get_tools(self) -> List[Dict]:
        exclude_tools = {'audit_create_macro_plan', 'audit_plan_update', 'audit_plan_list'}
        tools = [
            t for t in self.all_tools 
            if t['function']['name'] not in exclude_tools
        ]
        self.audit_db.log_progress(f"审计代理: 使用 {len(tools)} 个工具 (排除: {len(self.all_tools) - len(tools)})")
        return tools

    def get_initial_message(self) -> str:
        if self.specific_task:
            return f"""
你的工作是:
任务标题: {self.specific_task['title']}
任务描述: {self.specific_task['description']}
任务ID: {self.specific_task['id']}

现在请开始你的工作。"""
        return "开始你的工作。"

class VerificationAgent(AuditAgent):
    @property
    def name(self) -> str:
        return "VERIFICATION_AGENT"

    def get_tools(self) -> List[Dict]:
        exclude_tools = {'audit_create_macro_plan', 'audit_plan_update', 'audit_plan_list', 'audit_create_agent_task'}
        tools = [
            t for t in self.all_tools 
            if t['function']['name'] not in exclude_tools
        ]
        self.audit_db.log_progress(f"验证代理: 使用 {len(tools)} 个工具")
        return tools

class AuditService:
    def __init__(self, project_path: str, audit_db: AuditDatabase, on_message: Optional[Callable[[str, str, str], None]] = None, on_session_end: Optional[Callable[[str], None]] = None, on_chunk: Optional[Callable[[str, str, str], None]] = None):
        self.project_path = project_path
        self.audit_db = audit_db
        self.on_message = on_message
        self.on_session_end = on_session_end
        self.on_chunk = on_chunk
        self.status = "idle"  # idle, running, completed, failed
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._error: Optional[str] = None
        self.current_session_id: Optional[str] = None
        self.current_agent: Optional[str] = None

    def start(self):
        if self.status == "running":
            return
        
        # Reset any stuck in_progress plans to pending
        count = self.audit_db.reset_in_progress_plans()
        if count > 0:
            self.audit_db.log_progress(f"系统启动: 重置了 {count} 个未完成的任务为 pending 状态。")
        
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
                    on_session_end=self.on_session_end,
                    on_chunk=self.on_chunk
                )
                plan_agent.run(self._stop_event)
                
                if self._stop_event.is_set():
                    break

                # Step 2: Run Audit Agent or Verification Agent
                self.audit_db.log_progress("开始执行阶段...")
                
                # Fetch pending plans (both types)
                pending_verifications = self.audit_db.get_plans(status="pending", plan_type="verification_plan")
                pending_audits = self.audit_db.get_plans(status="pending", plan_type="agent_plan")
                
                task = None
                AgentClass = None
                
                if pending_verifications:
                    task = pending_verifications[0]
                    AgentClass = VerificationAgent
                    self.audit_db.log_progress(f"优先执行验证任务: {task['title']}")
                elif pending_audits:
                    task = pending_audits[0]
                    AgentClass = AuditAgent
                
                if not task:
                     self.audit_db.log_progress("没有待执行的 Agent 任务，跳过执行阶段。")
                else:
                    self.audit_db.log_progress(f"正在分配任务给 {AgentClass.__name__}: {task['title']} (ID: {task['id']})")
                    
                    # Mark task as in_progress
                    self.audit_db.update_plan_status(task['id'], "in_progress")

                    agent_instance = AgentClass(
                        llm_client,
                        mcp_client,
                        self.audit_db,
                        self.project_path,
                        tools,
                        specific_task=task,
                        on_session_start=self._update_session_info,
                        on_message=self.on_message,
                        on_session_end=self.on_session_end,
                        on_chunk=self.on_chunk
                    )
                    success = agent_instance.run(self._stop_event)
                    
                    # Only mark task as completed if success (normal completion and not stopped)
                    if success:
                        self.audit_db.update_plan_status(task['id'], "completed")
                    elif self._stop_event.is_set():
                        self.audit_db.log_progress(f"任务 '{task['title']}' 被用户停止，重置为 pending")
                        self.audit_db.update_plan_status(task['id'], "pending")
                    else:
                        # Loop detection or other failure
                        self.audit_db.log_progress(f"任务 '{task['title']}' 执行异常 (可能因循环输出)，重置为 failed")
                        self.audit_db.update_plan_status(task['id'], "failed")

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

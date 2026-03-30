import anthropic
import json
import time
import re
from typing import List, Dict, Any, Optional, Callable, Iterator, Union

class LLMClient:
    def __init__(self, base_url: str, api_key: str, model: str, max_retries: int = 3):
        self.client = anthropic.Anthropic(
            api_key=api_key,
            # remove v1 end string
            base_url=base_url.rstrip("v1")
        )
        self.model = model
        self.max_retries = max_retries

    def _convert_messages(self, messages: List[Dict[str, Any]]) -> tuple[str, List[Dict[str, Any]]]:
        """Convert OpenAI-style messages to Anthropic format."""
        system_prompt = ""
        anthropic_msgs = []
        
        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            
            if role == "system":
                system_prompt += content + "\n\n"
            elif role == "tool":
                # Convert OpenAI tool response to Anthropic tool_result
                anthropic_msgs.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": msg.get("tool_call_id"),
                        "content": content
                    }]
                })
            elif role == "assistant":
                new_content = []
                
                # Extract thinking from content if present (DeepSeek style <think>...</think>)
                thinking_match = re.search(r'<think>(.*?)</think>', content, re.DOTALL) if content else None
                if thinking_match:
                    thinking_text = thinking_match.group(1)
                    new_content.append({"type": "thinking", "thinking": thinking_text})
                    # Remove thinking from content for the text block
                    text_content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
                    if text_content:
                        new_content.append({"type": "text", "text": text_content})
                elif content:
                    new_content.append({"type": "text", "text": content})
                
                tool_calls = msg.get("tool_calls")
                if tool_calls:
                    for tc in tool_calls:
                        func = tc["function"]
                        try:
                            args = json.loads(func["arguments"]) if isinstance(func["arguments"], str) else func["arguments"]
                        except:
                            args = {}
                        new_content.append({
                            "type": "tool_use",
                            "id": tc["id"],
                            "name": func["name"],
                            "input": args
                        })
                
                anthropic_msgs.append({
                    "role": "assistant",
                    "content": new_content
                })
            else: # user
                anthropic_msgs.append({
                    "role": "user",
                    "content": content
                })
                
        return system_prompt.strip(), anthropic_msgs

    def _convert_tools(self, tools: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
        """Convert OpenAI-style tools to Anthropic format."""
        if not tools:
            return None
            
        anthropic_tools = []
        for tool in tools:
            if tool.get("type") == "function":
                func = tool["function"]
                anthropic_tools.append({
                    "name": func["name"],
                    "description": func.get("description", ""),
                    "input_schema": func.get("parameters", {})
                })
        return anthropic_tools

    def chat_completion(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> Any:
        system_prompt, anthropic_msgs = self._convert_messages(messages)
        anthropic_tools = self._convert_tools(tools)
        
        kwargs = {
            "model": self.model,
            "messages": anthropic_msgs,
            "max_tokens": 8192,
            "temperature": 1.0,
        }
        
        if system_prompt:
            kwargs["system"] = system_prompt
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        last_exception = None
        for attempt in range(self.max_retries):
            try:
                response = self.client.messages.create(**kwargs)
                return response
            except Exception as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt
                    print(f"LLM Call Failed (attempt {attempt + 1}/{self.max_retries}): {e}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    print(f"LLM Call Failed after {self.max_retries} attempts: {e}")
        
        if last_exception:
            raise last_exception
        raise Exception("LLM call failed without exception info")

    def chat_completion_stream(
        self, 
        messages: List[Dict[str, Any]], 
        tools: Optional[List[Dict[str, Any]]] = None,
        on_chunk: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Iterator[Any]:
        """Stream chat completion responses."""
        system_prompt, anthropic_msgs = self._convert_messages(messages)
        anthropic_tools = self._convert_tools(tools)
        
        kwargs = {
            "model": self.model,
            "messages": anthropic_msgs,
            "max_tokens": 8192,
            "temperature": 1.0,
            "stream": True
        }
        
        if system_prompt:
            kwargs["system"] = system_prompt
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        last_exception = None
        for attempt in range(self.max_retries):
            try:
                with self.client.messages.create(**kwargs) as stream:
                    for chunk in stream:
                        if on_chunk:
                            # Convert Anthropic chunk to a dict for callback if needed, 
                            # or just pass the raw chunk if consumer handles it.
                            # For compatibility, let's pass a dict representation
                            on_chunk(chunk)
                        yield chunk
                return
            except Exception as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt
                    print(f"LLM Stream Failed (attempt {attempt + 1}/{self.max_retries}): {e}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    print(f"LLM Stream Failed after {self.max_retries} attempts: {e}")
        
        if last_exception:
            raise last_exception
        raise Exception("LLM call failed without exception info")

    def extract_content(self, response: Any) -> Optional[str]:
        # Handle Anthropic Message object
        if hasattr(response, 'content'):
            text_blocks = [block.text for block in response.content if block.type == 'text']
            return "".join(text_blocks) if text_blocks else None
        return None

    def extract_tool_calls(self, response: Any) -> List[Dict[str, Any]]:
        # Handle Anthropic Message object
        if hasattr(response, 'content'):
            tool_uses = [block for block in response.content if block.type == 'tool_use']
            return [{
                "id": tu.id,
                "function": {
                    "name": tu.name,
                    "arguments": json.dumps(tu.input)
                },
                "type": "function"
            } for tu in tool_uses]
        return []

    def list_models(self) -> List[str]:
        import httpx
        try:
            # Use httpx to call OpenAI-compatible models endpoint
            base_url = str(self.client.base_url).rstrip("/") + "/v1"
            response = httpx.get(
                f"{base_url}/models",
                headers={"Authorization": f"Bearer {self.client.api_key}"},
                timeout=10.0
            )
            if response.status_code == 200:
                data = response.json()
                return [model["id"] for model in data.get("data", [])]
            else:
                print(f"Failed to list models: {response.status_code} - {response.text[:200] if response.text else 'empty'}")
                return []
        except Exception as e:
            print(f"Failed to list models from API: {e}")
            return []

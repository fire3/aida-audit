import json
import subprocess
import requests
import os
import sys
from typing import Dict, Any, List, Optional, Union

class McpClient:
    def __init__(self):
        self._request_id = 0

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def initialize(self) -> Dict[str, Any]:
        return self.call_method("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "aida-audit-client", "version": "0.1.0"}
        })

    def list_tools(self) -> List[Dict[str, Any]]:
        resp = self.call_method("tools/list", {})
        return resp.get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        return self.call_method("tools/call", {
            "name": name,
            "arguments": arguments
        })

    def call_method(self, method: str, params: Dict[str, Any]) -> Any:
        raise NotImplementedError

class HttpMcpClient(McpClient):
    def __init__(self, url: str):
        super().__init__()
        self.url = url

    def call_method(self, method: str, params: Dict[str, Any]) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._next_id()
        }
        try:
            resp = requests.post(self.url, json=payload, timeout=300) # Long timeout for tools
            resp.raise_for_status()
            data = resp.json()
            
            if "error" in data:
                raise RuntimeError(f"MCP Error: {data['error']}")
            
            return data.get("result")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"MCP Connection Error: {e}")

class StdioMcpClient(McpClient):
    def __init__(self, command: List[str], cwd: str = "."):
        super().__init__()
        self.command = command
        self.cwd = cwd
        self.process = None

    def start(self):
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=sys.stderr, # Forward stderr to console for debugging
                cwd=self.cwd,
                text=True,
                bufsize=1 # Line buffered
            )
        except Exception as e:
            raise RuntimeError(f"Failed to start MCP server: {e}")

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

    def call_method(self, method: str, params: Dict[str, Any]) -> Any:
        if not self.process:
            self.start()

        req_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": req_id
        }
        
        try:
            json_str = json.dumps(payload)
            self.process.stdin.write(json_str + "\n")
            self.process.stdin.flush()
            
            # Read response
            while True:
                line = self.process.stdout.readline()
                if not line:
                    raise RuntimeError("MCP Server closed connection unexpectedly")
                
                try:
                    data = json.loads(line)
                    # Skip logs or other output if not matching ID (though server shouldn't send random JSON)
                    if data.get("id") == req_id:
                        if "error" in data:
                            raise RuntimeError(f"MCP Error: {data['error']}")
                        return data.get("result")
                except json.JSONDecodeError:
                    print(f"MCP Stdio Warning: Ignored non-JSON output: {line.strip()}")
                    continue
                    
        except BrokenPipeError:
            raise RuntimeError("MCP Server pipe broken")

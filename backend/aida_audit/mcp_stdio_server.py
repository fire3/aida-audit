import sys
import json
import logging
import argparse
import os
import traceback
from typing import Any
import threading
from concurrent.futures import ThreadPoolExecutor

# Ensure we can import local modules if run as script
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    __package__ = "aida_audit"

from .project_store import ProjectStore
from .mcp_service import McpService, McpError

# Configure logging to stderr (so stdout is clean for JSON-RPC)
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("aida-audit-server")

_print_lock = threading.Lock()

def _print_response(response):
    with _print_lock:
        print(json.dumps(response))
        sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", default=".", help="Path to IDA project directory")
    parser.add_argument("--workers", type=int, default=None, help="Max worker threads for tool calls")
    args = parser.parse_args()

    project_path = args.project
    if project_path == "." and "AIDA_MCP_PROJECT" in os.environ:
         project_path = os.environ["AIDA_MCP_PROJECT"]

    try:
        store = ProjectStore(project_path)
        service = McpService(store)
        logger.info(f"AIDA MCP Server running for project: {project_path}")
    except Exception as e:
        logger.error(f"Failed to initialize service: {e}")
        sys.exit(1)

    # Read lines from stdin
    # MCP Stdio transport uses newline-delimited JSON
    try:
        max_workers = 4
        try:
            mw_env = os.environ.get("AIDA_MCP_WORKERS")
            if mw_env:
                max_workers = max(1, int(mw_env))
        except Exception:
            pass
        if args.workers is not None:
            max_workers = max(1, int(args.workers))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    request = json.loads(line)
                    executor.submit(handle_request, request, service)
                except json.JSONDecodeError:
                    response = _jsonrpc_error(None, -32700, "Parse error")
                    _print_response(response)
                except Exception as e:
                    logger.error(f"Error handling request: {e}")
    except KeyboardInterrupt:
        logger.info("Server stopping...")

def _jsonrpc_error(id_value, code, message, data=None):
    err = {"code": int(code), "message": str(message)}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id_value, "error": err}

def _tool_result(payload, is_error=False):
    text = json.dumps(payload, ensure_ascii=False)
    return {"content": [{"type": "text", "text": text}], "isError": bool(is_error)}

def _ok(data):
    return {"ok": True, "data": data}

def _err(code, message, details=None):
    e = {"code": str(code), "message": str(message)}
    if details is not None:
        e["details"] = details
    return {"ok": False, "error": e}

def handle_request(request: dict, service: McpService):
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        response = _jsonrpc_error(None, -32600, "Invalid Request")
        _print_response(response)
        return

    msg_type = request.get("method")
    msg_id = request.get("id")
    
    # If it's a notification (no id), we don't send a response
    if msg_id is None and msg_type != "notifications/initialized":
        # Handle notifications if needed
        return

    try:
        if msg_type == "initialize":
            params = request.get("params") or {}
            pv = params.get("protocolVersion") or "2025-06-18"
            server_info = {"name": "aida-audit", "version": "0.1.0"}
            result = {"protocolVersion": pv, "capabilities": {"tools": {}}, "serverInfo": server_info}
            response = {"jsonrpc": "2.0", "id": msg_id, "result": result}
        elif msg_type == "tools/list":
            tools = [
                {"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]}
                for t in service.get_tools()
            ]
            response = {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tools}}
        elif msg_type == "tools/call":
            params = request.get("params", {})
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not name:
                response = _jsonrpc_error(msg_id, -32602, "Invalid params: name required")
            else:
                tools = service.get_tools()
                handler = next((t["handler"] for t in tools if t["name"] == name), None)
                if not handler:
                    response = {"jsonrpc": "2.0", "id": msg_id, "result": _tool_result(_err("NOT_FOUND", f"tool_not_found: {name}"), is_error=True)}
                else:
                    try:
                        res = handler(arguments)
                        response = {"jsonrpc": "2.0", "id": msg_id, "result": _tool_result(_ok(res))}
                    except McpError as e:
                        response = {"jsonrpc": "2.0", "id": msg_id, "result": _tool_result(_err(e.code, e.message, e.details), is_error=True)}
                    except Exception as e:
                        response = {"jsonrpc": "2.0", "id": msg_id, "result": _tool_result(
                            _err("INTERNAL_ERROR", "tool_exception", {"error": str(e), "traceback": traceback.format_exc()}),
                            is_error=True,
                        )}
        elif msg_type == "notifications/initialized":
            return
        elif msg_type == "ping":
            response = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
        else:
            if msg_id is not None:
                 response = _jsonrpc_error(msg_id, -32601, f"Method not found: {msg_type}")
    except Exception as e:
        logger.exception(f"Error processing {msg_type}")
        if msg_id is not None:
            response = _jsonrpc_error(msg_id, -32000, str(e))
    
    if msg_id is not None:
        _print_response(response)

if __name__ == "__main__":
    main()

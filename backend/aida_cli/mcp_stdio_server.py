import sys
import json
import logging
import argparse
import os
from typing import Any

# Ensure we can import local modules if run as script
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    __package__ = "aida_cli"

from .project_store import ProjectStore
from .mcp_service import McpService

# Configure logging to stderr (so stdout is clean for JSON-RPC)
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("aida-cli-server")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", default=".", help="Path to IDA project directory")
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
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                handle_request(request, service)
            except json.JSONDecodeError:
                logger.error("Invalid JSON received")
            except Exception as e:
                logger.error(f"Error handling request: {e}")
    except KeyboardInterrupt:
        logger.info("Server stopping...")

def handle_request(request: dict, service: McpService):
    msg_type = request.get("method")
    msg_id = request.get("id")
    
    # If it's a notification (no id), we don't send a response
    if msg_id is None and msg_type != "notifications/initialized":
        # Handle notifications if needed
        return

    response = {"jsonrpc": "2.0", "id": msg_id}

    try:
        if msg_type == "initialize":
            response["result"] = {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "aida-cli-server",
                    "version": "0.1.0"
                }
            }
        elif msg_type == "tools/list":
            tools = service.get_tools_metadata()
            response["result"] = {
                "tools": tools
            }
        elif msg_type == "tools/call":
            params = request.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            
            # Find tool
            tools = service.get_tools()
            tool = next((t for t in tools if t["name"] == name), None)
            
            if tool:
                result = tool["handler"](**args)
                # Ensure result is text for MCP content
                content_text = json.dumps(result, indent=2) if not isinstance(result, str) else result
                response["result"] = {
                    "content": [{
                        "type": "text",
                        "text": content_text
                    }]
                }
            else:
                response["error"] = {"code": -32601, "message": f"Tool not found: {name}"}
        elif msg_type == "notifications/initialized":
            # Handled, no response
            return
        elif msg_type == "ping":
            response["result"] = {}
        else:
            if msg_id is not None:
                 response["error"] = {"code": -32601, "message": f"Method not found: {msg_type}"}
    except Exception as e:
        logger.exception(f"Error processing {msg_type}")
        if msg_id is not None:
            response["error"] = {"code": -32000, "message": str(e)}
    
    if msg_id is not None:
        print(json.dumps(response))
        sys.stdout.flush()

if __name__ == "__main__":
    main()

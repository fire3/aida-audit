import argparse
import json
import logging
import os
import sys
import uvicorn
import asyncio
from contextlib import asynccontextmanager
from typing import Optional, List, Union, Dict, Any
from collections import defaultdict
from fastapi import FastAPI, Request, Response, APIRouter, HTTPException, Query, Path, Body
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("aida_server")

from .project_store import ProjectStore
from .mcp_service import McpService, McpError
from .audit_database import AuditDatabase
from .audit_service import AuditService
from .constants import AUDIT_DB_FILENAME
from . import audit_mcp_tools

# Global service instance
service = None
project_store = None
audit_db = None
audit_service = None

message_queue: Dict[str, asyncio.Queue] = defaultdict(asyncio.Queue)
completed_sessions: set = set()

def on_message_callback(session_id: str, role: str, content: str):
    """Callback to push messages to SSE clients."""
    queue = message_queue.get(session_id)
    if queue:
        try:
            queue.put_nowait({"role": role, "content": content})
        except Exception:
            pass

def on_chunk_callback(session_id: str, chunk_type: str, content: str):
    """Callback to push raw chunks to SSE clients for real-time display."""
    queue = message_queue.get(session_id)
    if queue:
        try:
            queue.put_nowait({"type": "chunk", "chunk_type": chunk_type, "content": content})
        except Exception:
            pass

def on_session_end_callback(session_id: str):
    """Callback when session ends."""
    completed_sessions.add(session_id)
    queue = message_queue.get(session_id)
    if queue:
        try:
            queue.put_nowait({"role": "system", "content": "__SESSION_END__"})
        except Exception:
            pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global service, project_store, audit_db, audit_service
    project_path = os.environ.get("AIDA_MCP_PROJECT", ".")
    audit_db = None
    try:
        project_store = ProjectStore(project_path)
        service = McpService(project_store)
        print(f"Loaded project from: {project_path}")

        audit_db_path = os.path.join(project_path, AUDIT_DB_FILENAME)
        if os.path.exists(os.path.dirname(audit_db_path)):
            audit_db = AuditDatabase(audit_db_path)
            audit_db.connect()
            audit_mcp_tools.set_audit_db(audit_db)
            print(f"Loaded audit database: {audit_db_path}")
            
            audit_service = AuditService(project_path, audit_db, on_message_callback, on_session_end_callback, on_chunk_callback)
            print(f"Audit Service initialized")

    except Exception as e:
        print(f"Failed to load project: {e}", file=sys.stderr)

    yield

    # Shutdown
    if audit_service:
        audit_service.stop()
    if project_store:
        project_store.close()
    if audit_db:
        audit_db.close()

app = FastAPI(lifespan=lifespan)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models ---
class NoteCreate(BaseModel):
    binary_name: str
    content: str
    note_type: str
    function_name: Optional[str] = None
    address: Optional[Union[str, int]] = None
    tags: Optional[str] = None
    confidence: str = "medium"

class NoteUpdate(BaseModel):
    content: Optional[str] = None
    tags: Optional[str] = None

class FindingCreate(BaseModel):
    binary_name: str
    severity: str
    category: str
    description: str
    function_name: Optional[str] = None
    address: Optional[Union[str, int]] = None
    evidence: Optional[str] = None
    cvss: Optional[float] = None
    exploitability: Optional[str] = None

# --- REST API Implementation ---

api_router = APIRouter(prefix="/api/v1")

def get_service():
    if not service:
        raise HTTPException(status_code=503, detail="Server not initialized")
    return service

def handle_mcp_error(e: McpError):
    if e.code == "NOT_FOUND":
        raise HTTPException(status_code=404, detail=e.message)
    elif e.code == "INVALID_ARGUMENT":
        raise HTTPException(status_code=400, detail=e.message)
    elif e.code == "UNSUPPORTED":
        raise HTTPException(status_code=501, detail=e.message)
    else:
        raise HTTPException(status_code=500, detail=e.message)

# Project Endpoints

@api_router.get("/mcp/tools")
def get_mcp_tools():
    """Get list of available MCP tools and their schemas."""
    svc = get_service()
    try:
        return svc.get_tools_metadata()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/project")
def get_project_overview():
    svc = get_service()
    try:
        return svc.get_project_overview()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/project/binaries")
def list_binaries(
    offset: int = 0,
    limit: int = 50,
    detail: bool = False
):
    svc = get_service()
    return svc.get_project_binaries(offset=offset, limit=limit, detail=detail)

@api_router.get("/project/search/exports")
def search_project_exports(
    function_name: str,
    match: str = "exact",
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.search_exported_function_in_project(function_name, match, offset, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/project/search/functions")
def search_project_functions(
    function_name: str,
    match: str = "contains",
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.search_functions_in_project(function_name, match, offset, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/project/search/strings")
def search_project_strings(
    query: str,
    match: str = "contains",
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.search_string_symbol_in_project(query, match, offset, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Binary Endpoints

@api_router.get("/binary/{binary_name}")
def get_binary_metadata(binary_name: str):
    svc = get_service()
    try:
        return svc.get_binary_metadata(binary_name)
    except Exception as e: # McpError is wrapped or raised directly? McpService raises standard exceptions or McpError?
        # McpService methods usually wrap and re-raise or just run. 
        # But looking at McpService code, _get_binary raises LookupError/KeyError.
        # Ideally we should catch those too.
        if isinstance(e, (LookupError, KeyError)):
             raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/sections")
def list_binary_sections(binary_name: str):
    svc = get_service()
    try:
        return svc.list_binary_sections(binary_name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/segments")
def list_binary_segments(binary_name: str):
    svc = get_service()
    try:
        return svc.list_binary_segments(binary_name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/functions")
def list_binary_functions(
    binary_name: str,
    query: Optional[str] = None,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.list_binary_functions(binary_name, query=query, offset=offset, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/binary/{binary_name}/symbols")
def list_binary_symbols(
    binary_name: str,
    query: Optional[str] = None,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.list_binary_symbols(binary_name, query=query, offset=offset, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/strings")
def list_strings(
    binary_name: str,
    query: Optional[str] = None,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.list_binary_strings(binary_name, query=query, offset=offset, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/imports")
def list_imports(
    binary_name: str,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.list_binary_imports(binary_name, offset=offset, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/exports")
def list_exports(
    binary_name: str,
    query: Optional[str] = None,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.list_binary_exports(binary_name, query=query, offset=offset, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Notes Endpoints

@api_router.get("/notes")
def get_notes(
    binary_name: Optional[str] = None,
    query: Optional[str] = None,
    note_type: Optional[str] = None,
    tags: Optional[str] = None,
    limit: int = 50
):
    try:
        return audit_mcp_tools.audit_get_notes(
            binary_name=binary_name,
            query=query,
            note_type=note_type,
            tags=tags,
            limit=limit
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/notes")
def create_note(note: NoteCreate):
    try:
        return audit_mcp_tools.audit_create_note(
            binary_name=note.binary_name,
            content=note.content,
            note_type=note.note_type,
            function_name=note.function_name,
            address=note.address,
            tags=note.tags,
            confidence=note.confidence
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.put("/notes/{note_id}")
def update_note(note_id: int, note: NoteUpdate):
    try:
        return audit_mcp_tools.audit_update_note(
            note_id=note_id,
            content=note.content,
            tags=note.tags
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.delete("/notes/{note_id}")
def delete_note(note_id: int):
    try:
        return audit_mcp_tools.audit_delete_note(note_id=note_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Findings Endpoints

@api_router.get("/findings")
def get_findings(
    binary_name: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None
):
    try:
        return audit_mcp_tools.audit_get_findings(
            binary_name=binary_name,
            severity=severity,
            category=category
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/findings")
def mark_finding(finding: FindingCreate):
    try:
        return audit_mcp_tools.audit_mark_finding(
            binary_name=finding.binary_name,
            severity=finding.severity,
            category=finding.category,
            description=finding.description,
            function_name=finding.function_name,
            address=finding.address,
            evidence=finding.evidence,
            cvss=finding.cvss,
            exploitability=finding.exploitability
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/analysis-progress")
def get_analysis_progress(binary_name: str):
    try:
        return audit_mcp_tools.audit_get_analysis_progress(binary_name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Analysis Endpoints

@api_router.get("/binary/{binary_name}/disassembly")
def get_binary_disassembly(
    binary_name: str,
    start_address: str = Query(..., description="Start address (hex or int)"),
    end_address: str = Query(..., description="End address (hex or int)")
):
    svc = get_service()
    try:
        return svc.get_binary_disassembly_text(binary_name, start_address, end_address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/function/{address}/disassembly")
def get_binary_function_disassembly(
    binary_name: str,
    address: str
):
    svc = get_service()
    try:
        return svc.get_binary_function_disassembly_text(binary_name, address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/address/{address}/disassembly")
def get_binary_disassembly_context(
    binary_name: str,
    address: str,
    context_lines: int = 10
):
    svc = get_service()
    try:
        return svc.get_binary_disassembly_context(binary_name, address, context_lines)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/function/{address}/pseudocode")
def get_binary_function_pseudocode(
    binary_name: str,
    address: str
):
    svc = get_service()
    try:
        # returns list of dicts, but we usually ask for one function here
        res = svc.get_binary_function_pseudocode_by_address(binary_name, address)
        if not res:
            raise HTTPException(status_code=404, detail="Pseudocode not found")
        return res[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/bytes")
def get_binary_bytes(
    binary_name: str,
    address: str,
    length: int,
    format_type: Optional[str] = None
):
    svc = get_service()
    try:
        return svc.get_binary_bytes(binary_name, address, length, format_type)
    except McpError as e:
        handle_mcp_error(e)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/address/{address}")
def resolve_address(
    binary_name: str,
    address: str
):
    svc = get_service()
    try:
        return svc.resolve_address(binary_name, address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/function/{address}/callers")
def get_callers(
    binary_name: str,
    address: str,
    depth: Optional[int] = None,
    limit: Optional[int] = None
):
    svc = get_service()
    try:
        return svc.get_binary_function_callers(binary_name, address, depth, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/function/{address}/callees")
def get_callees(
    binary_name: str,
    address: str,
    depth: Optional[int] = None,
    limit: Optional[int] = None
):
    svc = get_service()
    try:
        return svc.get_binary_function_callees(binary_name, address, depth, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/xrefs/to/{address}")
def get_xrefs_to(
    binary_name: str,
    address: str,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.get_binary_cross_references_to_address(binary_name, address, offset, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/xrefs/from/{address}")
def get_xrefs_from(
    binary_name: str,
    address: str,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.get_binary_cross_references_from_address(binary_name, address, offset, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/xrefs/{address}")
def get_xrefs(
    binary_name: str,
    address: str,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.get_binary_cross_references(binary_name, address, offset, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Audit Endpoints

@api_router.get("/audit/plans")
def get_audit_plans(status: Optional[str] = None, plan_type: Optional[str] = None):
    try:
        # Check if DB is initialized
        if not audit_db:
             return []
        return audit_mcp_tools.audit_plan_list(status, plan_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/audit/logs")
def get_audit_logs(limit: int = 50):
    if not audit_db:
         return []
    try:
        return audit_db.get_logs(limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/audit/messages")
def get_audit_messages(session_id: Optional[str] = None, limit: int = 100):
    if not audit_db:
         return []
    try:
        return audit_db.get_messages(session_id, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/audit/stream/{session_id}")
async def stream_audit_messages(session_id: str):
    """SSE endpoint for real-time message streaming."""
    if session_id not in message_queue:
        message_queue[session_id]
    
    queue = message_queue[session_id]
    
    async def event_generator():
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=30)
                
                if message.get("content") == "__SESSION_END__":
                    yield f"data: {json.dumps({'type': 'session_end'})}\n\n"
                    break
                    
                yield f"data: {json.dumps(message)}\n\n"
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
            except Exception:
                break
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@api_router.get("/audit/sessions")
def get_audit_sessions():
    if not audit_db:
         return []
    try:
        return audit_db.get_sessions()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/audit/notes")
def get_audit_notes(binary_name: Optional[str] = None, limit: int = 50):
    if not audit_db:
         return []
    try:
        return audit_mcp_tools.audit_get_notes(binary_name=binary_name, limit=limit)
    except Exception as e:
         raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/audit/findings")
def get_audit_findings(binary_name: Optional[str] = None, severity: Optional[str] = None):
    if not audit_db:
         return []
    try:
        return audit_mcp_tools.audit_get_findings(binary_name=binary_name, severity=severity)
    except Exception as e:
         raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/audit/status")
def get_audit_status():
    if not audit_service:
        return {"status": "not_initialized", "error": "Audit service not available"}
    return audit_service.get_status()

@api_router.post("/audit/start")
def start_audit():
    if not audit_service:
        raise HTTPException(status_code=503, detail="Audit service not initialized")
    try:
        audit_service.start()
        return {"status": "started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/audit/stop")
def stop_audit():
    if not audit_service:
        raise HTTPException(status_code=503, detail="Audit service not initialized")
    audit_service.stop()
    return {"status": "stopping"}


# Include the API router
app.include_router(api_router)

# --- End of REST API Implementation ---

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

@app.post("/{path:path}")
async def handle_mcp(path: str, request: Request):
    # Simple path check if needed, but we catch all POSTs for now
    # You can enforce path check if strictly required, e.g.:
    # if path != "mcp": return JSONResponse(status_code=404)
    
    try:
        body = await request.body()
        msg = json.loads(body.decode("utf-8")) if body else None
    except Exception:
        return JSONResponse(status_code=400, content=_jsonrpc_error(None, -32700, "Parse error"))

    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return JSONResponse(status_code=400, content=_jsonrpc_error(None, -32600, "Invalid Request"))

    mid = msg.get("id")
    method = msg.get("method")
    
    if "method" not in msg:
        # JSON-RPC notification? or invalid. Return accepted.
        return Response(status_code=202)

    if not service:
        return JSONResponse(status_code=503, content=_jsonrpc_error(mid, -32000, "Server not initialized"))

    try:
        resp = dispatch(msg)
        if resp is None:
            return Response(status_code=202)
        return JSONResponse(content=resp)
    except Exception as e:
        return JSONResponse(status_code=500, content=_jsonrpc_error(mid, -32603, f"Internal error: {e}"))

def dispatch(msg):
    mid = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}

    logger.info(f"MCP Request: method={method} params={json.dumps(params, ensure_ascii=False)}")

    if method == "initialize":
        pv = params.get("protocolVersion") or "2025-06-18"
        server_info = {"name": "aida-cli", "version": "0.1.0"}
        result = {"protocolVersion": pv, "capabilities": {"tools": {}}, "serverInfo": server_info}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}

    if method == "tools/list":
        tools = [
            {"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]}
            for t in service.get_tools()
        ]
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}}

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not name:
            return _jsonrpc_error(mid, -32602, "Invalid params: name required")
        
        tools = service.get_tools()
        handler = next((t["handler"] for t in tools if t["name"] == name), None)
        if not handler:
            return {"jsonrpc": "2.0", "id": mid, "result": _tool_result(_err("NOT_FOUND", f"tool_not_found: {name}"), is_error=True)}
        
        try:
            res = handler(arguments)
            return {"jsonrpc": "2.0", "id": mid, "result": _tool_result(_ok(res))}
        except McpError as e:
            return {"jsonrpc": "2.0", "id": mid, "result": _tool_result(_err(e.code, e.message, e.details), is_error=True)}
        except Exception as e:
            import traceback
            return {"jsonrpc": "2.0", "id": mid, "result": _tool_result(
                _err("INTERNAL_ERROR", "tool_exception", {"error": str(e), "traceback": traceback.format_exc()}),
                is_error=True,
            )}

    return _jsonrpc_error(mid, -32601, f"Method not found: {method}")

# --- Static File Serving (Frontend) ---
current_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(current_dir, "static")

if os.path.exists(static_dir):
    # Mount assets directory if it exists (for efficiency)
    assets_dir = os.path.join(static_dir, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")
    
    # Catch-all for SPA and root
    @app.get("/{path:path}")
    async def serve_frontend(path: str):
        # 1. Try to serve exact file match
        full_path = os.path.join(static_dir, path)
        if os.path.isfile(full_path):
            return FileResponse(full_path)
            
        # 2. If path looks like a file (has extension), return 404
        # This prevents serving index.html for missing JS/CSS files
        if "." in os.path.basename(path):
            raise HTTPException(status_code=404, detail="File not found")
            
        # 3. Otherwise serve index.html (SPA routing)
        index_path = os.path.join(static_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
            
        raise HTTPException(status_code=404, detail="Not Found")
else:
    logger.warning(f"Static directory not found at {static_dir}. Frontend will not be served.")

def main():
    parser = argparse.ArgumentParser(description="AIDA MCP server (FastAPI + Uvicorn)")
    parser.add_argument("project", nargs="?", default=".", help="Directory containing .db files")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (debug mode)")
    args = parser.parse_args()

    os.environ["AIDA_MCP_PROJECT"] = args.project
    os.environ["AIDA_MCP_PORT"] = str(args.port)
    
    # Check if project path exists
    if not os.path.exists(args.project):
        print(f"Warning: Project path '{args.project}' does not exist.", file=sys.stderr)

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload
    )

if __name__ == "__main__":
    main()

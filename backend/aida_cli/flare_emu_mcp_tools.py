import os
import io
import logging
import traceback
from typing import Dict, Any, List, Optional
from .project_store import ProjectStore

def get_flare_emu_dsl_guide_impl() -> str:
    """Retrieve the official guide for writing Flare-Emu Text DSL scripts.
    """
    try:
        # Locate the guide file relative to this module
        current_dir = os.path.dirname(os.path.abspath(__file__))
        guide_path = os.path.join(current_dir, "templates", "FLARE_EMU_DSL_GUIDE.md")

        if not os.path.exists(guide_path):
            return "Error: DSL Guide file not found."

        with open(guide_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading DSL guide: {str(e)}"

def run_flare_emu_dsl_impl(project_store: ProjectStore, binary_name: str, script: str) -> Dict[str, Any]:
    """Execute a Flare-Emu Text DSL script on a specific binary.
    """
    try:
        # Delayed imports
        from .flare_emu_dsl import TextDSLParser, DSLRunner
        from .flare_emu_aida import AidaEmuHelper
    except ImportError as e:
        raise RuntimeError(f"Failed to import emulation modules: {e}")

    try:
        binary = project_store.get_binary(binary_name)
        if not binary:
            raise LookupError(f"binary_not_found: {binary_name}")

        # Access the underlying DB path from the binary object
        # ProjectStore wraps BinaryDbQuery, which has db_path
        db_path = getattr(binary, "db_path", None)
        if not db_path:
            raise RuntimeError("Binary database path not found.")

        # Initialize emulator helper
        # verbose=0 to minimize stdout noise, we capture logs via handler
        eh = AidaEmuHelper(db_path, verbose=0)
        
        # Parse script
        parser = TextDSLParser()
        try:
            scenario = parser.parse(script)
        except Exception as e:
            return {
                "success": False,
                "error": f"DSL Parsing Error: {str(e)}",
                "logs": []
            }

        # Setup log capturing
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        
        # Get the logger used by DSLRunner
        dsl_logger = logging.getLogger("aida_cli.flare_emu_dsl")
        dsl_logger.addHandler(handler)
        dsl_logger.setLevel(logging.INFO)
        
        dsl_logger.info(f"DSL Script Input:\n{script}")

        captured_reports = []
        def report_cb(filename, content):
            captured_reports.append({"file": filename, "content": content})
        
        runner = DSLRunner(eh, report_callback=report_cb)
        success = True
        error_msg = None
        
        try:
            runner.run(scenario)
        except Exception as e:
            success = False
            error_msg = str(e)
        finally:
            dsl_logger.removeHandler(handler)
            
        logs = log_capture.getvalue().splitlines()
        
        result = {
            "success": success,
            "logs": logs,
            "reports": captured_reports,
            "variables": runner.variables,
            "coverage_count": len(runner.coverage_data),
            "trace_events_count": len(runner.trace_log),
            "crash_context": runner.crash_context
        }
        
        if error_msg:
            result["error"] = error_msg
            
        # If trace is enabled, include it (might be large, maybe truncate?)
        if runner.features.get("trace") or runner.features.get("trace_calls"):
            result["trace"] = runner.trace_log[:1000] # Limit to 1000 events to avoid blowing up JSON
            if len(runner.trace_log) > 1000:
                result["trace_truncated"] = True
                
        if runner.features.get("trace_calls"):
            result["call_trace"] = runner.call_trace

        return result

    except LookupError as e:
        raise e
    except Exception as e:
        raise RuntimeError(f"Emulation failed: {str(e)}\n{traceback.format_exc()}")

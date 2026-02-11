import argparse
import json
import os
import shutil
import sys
import tempfile
from collections import deque

from . import ida_utils
from .taint_rules import RuleSet, default_cwe78_rules
from .pathfinder import PathFinder
from .taint_intra import IntraTaintScanner

# Try to import IDA modules
import idapro
import ida_auto
import ida_pro
import ida_ida
import idc
import ida_nalt
import ida_hexrays
import ida_funcs
import idautils
import ida_gdl
import ida_idaapi
import idc
import ida_gdl
import ida_ida

def _load_rules(path):
    """Load rules from a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return RuleSet(
        rule_id=payload.get("rule_id", "custom"),
        cwe=payload.get("cwe", "custom"),
        title=payload.get("title", "custom taint rule"),
        severity=payload.get("severity", "medium"),
        sources=payload.get("sources", []),
        sinks=payload.get("sinks", []),
        propagators=payload.get("propagators", []),
    )


def _open_database(target, logger):
    """Open the IDB/I64 database."""
    if not target:
        return True
    if idapro:
        try:
            logger.log(f"Opening database: {target}")
            idapro.open_database(target, run_auto_analysis=True)
            return True
        except Exception as e:
            logger.log(f"Failed to open database: {e}", level="ERROR")
            return False
    logger.log("IDA Python environment not available", level="ERROR")
    return False


def _wait_analysis(logger):
    """Wait for IDA auto-analysis to complete."""
    if ida_auto is None:
        return
    logger.log("Waiting for auto-analysis...")
    monitor = ida_utils.AutoAnalysisMonitor(logger.log)
    monitor.hook()
    ida_auto.auto_wait()
    monitor.unhook()


def _ensure_function_analysis(logger):
    """Ensure functions are analyzed, forcing analysis if necessary."""
    if ida_auto is None or ida_funcs is None:
        return
    try:
        func_count = ida_funcs.get_func_qty()
    except Exception:
        func_count = 0
    if func_count:
        return
    logger.log("No functions found after auto_wait. Forcing analysis...", level="WARN")
    try:
        import ida_segment
    except Exception:
        return
    ida_auto.set_auto_state(True)
    seg = ida_segment.get_first_seg()
    while seg:
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)
        seg = ida_segment.get_next_seg(seg.start_ea)
    ida_auto.auto_wait()
    try:
        func_count = ida_funcs.get_func_qty()
        logger.log(f"Function count after forced analysis: {func_count}")
    except Exception:
        pass


def _iter_targets(target):
    """Iterate over all valid IDB/I64 targets."""
    if not target:
        return [None]
    if not os.path.isdir(target):
        return [target]
    
    targets = []
    for root, _, files in os.walk(target):
        for fname in files:
            if fname.lower().endswith((".i64", ".idb")):
                targets.append(os.path.join(root, fname))
    
    # If no IDB found, try all files? (Original behavior seemed to do that, but let's be safer)
    # Original logic:
    # if targets: return sorted(targets)
    # else: append all files
    # Let's keep original logic for backward compatibility if needed, but slightly cleaner
    if targets:
        return sorted(targets)

    for root, _, files in os.walk(target):
        for fname in files:
            targets.append(os.path.join(root, fname))
    return sorted(targets)


def _is_idb(path):
    """Check if the path is an IDA database file."""
    if not path:
        return False
    low = path.lower()
    return low.endswith(".i64") or low.endswith(".idb")


def _prepare_workdir(root, target):
    """Create a temporary working directory."""
    base = os.path.abspath(root or os.getcwd())
    os.makedirs(base, exist_ok=True)
    name = os.path.basename(target) if target else "input"
    safe = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in name)
    return tempfile.mkdtemp(prefix=f"aida_taint_{safe}_", dir=base)


def _prepare_scan_input(target, workdir_root, logger):
    """Prepare the input file for scanning (copy to temp dir if needed)."""
    if not target:
        return None, None, None
    workdir = _prepare_workdir(workdir_root, target)
    logger.log(f"Working directory: {workdir}")
    if _is_idb(target):
        return target, workdir, target
    try:
        dst = os.path.join(workdir, os.path.basename(target))
        shutil.copy2(target, dst)
        logger.log(f"Copied input -> {dst}")
        return dst, workdir, target
    except Exception as e:
        logger.log(f"Failed to copy input: {e}", level="ERROR")
        return target, workdir, target


def _close_database():
    """Close the database if possible."""
    if idapro and hasattr(idapro, "close_database"):
        try:
            idapro.close_database()
        except Exception:
            pass


def _print_findings(findings, output_path):
    """Print findings to stdout or file."""
    out = None
    if output_path:
        out = open(output_path, "w", encoding="utf-8")
    try:
        for finding in findings:
            line = json.dumps(finding, ensure_ascii=False)
            if out:
                out.write(line + "\n")
            else:
                print(line)
    finally:
        if out:
            out.close()


def _run_single_scan(target, args, ruleset, logger):
    """Run analysis for a single target."""
    scan_path = target
    input_path = target
    workdir = None
    
    path_finder = PathFinder(ruleset, logger)
    taint_scanner = IntraTaintScanner(ruleset, logger=logger, debug=True)
    findings = []
    
    try:
        if target:
            scan_path, workdir, input_path = _prepare_scan_input(target, args.workdir, logger)
            if not _open_database(scan_path, logger):
                return []
            _wait_analysis(logger)
            _ensure_function_analysis(logger)
        
        logger.log("Starting path analysis...")
        paths = []
        try:
            path_finder.identify_markers()
            paths = path_finder.find_paths() or []
        except Exception as e:
            logger.log(f"Path analysis failed: {e}", level="ERROR")
            import traceback
            traceback.print_exc()
        logger.log("Starting intra-function taint analysis...")
        try:
            reports = taint_scanner.scan_paths(paths)
            for report in reports or []:
                for finding in report.get("findings", []):
                    findings.append(finding)
        except Exception as e:
            logger.log(f"Intra-function taint analysis failed: {e}", level="ERROR")
            import traceback
            traceback.print_exc()
    finally:
        if scan_path:
            _close_database()
        
        if workdir and not args.keep and os.path.exists(workdir):
            try:
                shutil.rmtree(workdir)
            except Exception as e:
                logger.log(f"Failed to cleanup workdir {workdir}: {e}", level="WARN")
                
    return findings


def main():
    parser = argparse.ArgumentParser(description="Run Source-to-Sink Path Discovery")
    parser.add_argument("target", nargs="?", help="Path to input binary, IDB/I64, or directory")
    parser.add_argument("--rules", default="cwe-78", help="Rule id to run (default: cwe-78)")
    parser.add_argument("--rules-file", help="Path to custom rules JSON")
    parser.add_argument("--output", help="Write findings JSONL to this path")
    parser.add_argument("--workdir", help="Root directory for scan workspaces")
    parser.add_argument("--keep", action="store_true", help="Keep temporary workspace")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    logger = ida_utils.Logger(verbose=args.verbose)

    if args.rules_file:
        ruleset = _load_rules(args.rules_file)
    else:
        if args.rules.lower() not in ("cwe-78", "cwe78"):
            logger.log(f"Unknown ruleset: {args.rules}", level="ERROR")
            sys.exit(1)
        ruleset = default_cwe78_rules()

    all_findings = []
    for target in _iter_targets(args.target):
        findings = _run_single_scan(target, args, ruleset, logger)
        all_findings.extend(findings)

    _print_findings(all_findings, args.output)
    
    if ida_nalt:
        logger.log(f"Findings: {len(all_findings)}")

if __name__ == "__main__":
    main()

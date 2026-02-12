import argparse
import json
import os
import shutil
import sys
import tempfile

from . import ida_utils
from . import microcode as taint_mod
from .microcode import analyze_function, WorklistTaintEngine
from .taint_rules import RuleSet, default_cwe78_rules

try:
    import idapro
    import ida_auto
    import ida_funcs
    import ida_hexrays
    import ida_nalt
    import idautils
except ImportError:
    ida_auto = None
    ida_funcs = None
    ida_hexrays = None
    ida_nalt = None
    idautils = None


def _load_rules(path):
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


def _resolve_maturity(name):
    hexrays = taint_mod.ida_hexrays or ida_hexrays
    if hexrays is None:
        return None
    levels = {
        "MMAT_GENERATED": hexrays.MMAT_GENERATED,
        "MMAT_PREOPTIMIZED": hexrays.MMAT_PREOPTIMIZED,
        "MMAT_LOCOPT": hexrays.MMAT_LOCOPT,
        "MMAT_CALLS": hexrays.MMAT_CALLS,
        "MMAT_GLBOPT1": hexrays.MMAT_GLBOPT1,
        "MMAT_GLBOPT2": hexrays.MMAT_GLBOPT2,
        "MMAT_GLBOPT3": hexrays.MMAT_GLBOPT3,
        "MMAT_LVARS": hexrays.MMAT_LVARS,
    }
    return levels.get(name, hexrays.MMAT_LVARS)


def _open_database(target, logger):
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
    if ida_auto is None:
        return
    logger.log("Waiting for auto-analysis...")
    monitor = ida_utils.AutoAnalysisMonitor(logger.log)
    monitor.hook()
    ida_auto.auto_wait()
    monitor.unhook()


def _ensure_function_analysis(logger):
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


def _collect_functions():
    funcs = []
    if idautils is None:
        return funcs
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        funcs.append((ea, name))
    return funcs


def _iter_targets(target):
    if not target:
        return [None]
    if not os.path.isdir(target):
        return [target]
    targets = []
    for root, _, files in os.walk(target):
        for fname in files:
            if fname.lower().endswith((".i64", ".idb")):
                targets.append(os.path.join(root, fname))
    if targets:
        return sorted(targets)
    for root, _, files in os.walk(target):
        for fname in files:
            targets.append(os.path.join(root, fname))
    return sorted(targets)


def _is_idb(path):
    if not path:
        return False
    low = path.lower()
    return low.endswith(".i64") or low.endswith(".idb")


def _prepare_workdir(target):
    temp_base = tempfile.gettempdir()
    os.makedirs(temp_base, exist_ok=True)
    name = os.path.basename(target) if target else "input"
    safe = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in name)
    return tempfile.mkdtemp(prefix=f"aida_scan_{safe}_", dir=temp_base)


def _prepare_scan_input(target, logger):
    if not target:
        return None, None, None
    workdir = _prepare_workdir(target)
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
    if idapro and hasattr(idapro, "close_database"):
        try:
            idapro.close_database()
        except Exception:
            pass

def _print_findings(findings, output_path):
    out = None
    if output_path:
        out = open(output_path, "w", encoding="utf-8")
    try:
        for finding in findings:
            if hasattr(finding, 'to_dict'):
                finding = finding.to_dict()
            line = json.dumps(finding, ensure_ascii=False)
            if out:
                out.write(line + "\n")
            else:
                print(line)
    finally:
        if out:
            out.close()


def main():
    parser = argparse.ArgumentParser(description="Run IDA Microcode taint scan")
    parser.add_argument("target", nargs="?", help="Path to input binary, IDB/I64, or directory")
    parser.add_argument("--rules", default="cwe-78", help="Rule id to run (default: cwe-78)")
    parser.add_argument("--rules-file", help="Path to custom rules JSON")
    parser.add_argument("--maturity", default="MMAT_LVARS", help="Microcode maturity level")
    parser.add_argument("--output", help="Write findings JSONL to this path")
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

    maturity = _resolve_maturity(args.maturity)
    if maturity is None:
        logger.log("Hex-Rays decompiler not available", level="ERROR")
        sys.exit(1)

    engine = WorklistTaintEngine(ruleset, logger=logger, verbose=args.verbose)
    findings = []
    for target in _iter_targets(args.target):
        scan_path = target
        input_path = target
        workdir = None
        try:
            if target:
                scan_path, workdir, input_path = _prepare_scan_input(target, logger)
                if not _open_database(scan_path, logger):
                    continue
                _wait_analysis(logger)
                _ensure_function_analysis(logger)
            hexrays = taint_mod.ida_hexrays or ida_hexrays
            if hexrays is None or not hexrays.init_hexrays_plugin():
                logger.log("Hex-Rays decompiler not available", level="ERROR")
                continue
            logger.log("Starting global taint analysis...")
            try:
                result = engine.scan_global(maturity)
                findings.extend(result)
            except Exception as e:
                logger.log(f"Global scan failed: {e}", level="ERROR")
                import traceback
                traceback.print_exc()
        finally:
            if scan_path:
                _close_database()
            
            if workdir and os.path.exists(workdir):
                try:
                    shutil.rmtree(workdir)
                except Exception as e:
                    logger.log(f"Failed to cleanup workdir {workdir}: {e}", level="WARN")

    _print_findings(findings, args.output)

    if ida_nalt:
        logger.log(f"Findings: {len(findings)}")

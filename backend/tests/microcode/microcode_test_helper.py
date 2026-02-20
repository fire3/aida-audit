#!/usr/bin/env python3
"""
IDA Microcode Test Helper

Analyzes functions in IDA database and outputs microcode information.

Usage:
    python3 microcode_test_helper.py <binary|idb|dir>
"""

import argparse
import json
import os
import sys

_script_dir = os.path.dirname(os.path.abspath(__file__))
_backend_path = os.path.dirname(_script_dir)
if _backend_path not in sys.path:
    sys.path.insert(0, _backend_path)

from aida_cli import ida_utils
from aida_cli.microcode import analyze_function

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
    idapro = None


def _resolve_maturity(name):
    hexrays = ida_hexrays
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


def _close_database():
    if idapro and hasattr(idapro, "close_database"):
        try:
            idapro.close_database()
        except Exception:
            pass


def _print_func_info(func_info, output_path=None):
    out = None
    if output_path:
        out = open(output_path, "w", encoding="utf-8")
    try:
        for insn in func_info.insns:
            line = insn.to_string()
            if out:
                out.write(line + "\n")
            else:
                print(line)
    finally:
        if out:
            out.close()


def main():
    parser = argparse.ArgumentParser(description="IDA Microcode Test Helper")
    parser.add_argument("target", nargs="?", help="Path to binary, IDB/I64, or directory")
    parser.add_argument("--maturity", default="MMAT_LVARS", help="Microcode maturity level")
    parser.add_argument("--output", help="Write output to this path")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if not args.target:
        print("Error: missing target. Usage: python microcode_test_helper.py <binary|idb|dir>")
        sys.exit(1)

    logger = ida_utils.Logger(verbose=args.verbose)

    maturity = _resolve_maturity(args.maturity)
    if maturity is None:
        logger.log("Hex-Rays decompiler not available", level="ERROR")
        sys.exit(1)

    for target in _iter_targets(args.target):
        try:
            if target:
                if not _open_database(target, logger):
                    continue
                _wait_analysis(logger)
                _ensure_function_analysis(logger)

            if ida_hexrays is None or not ida_hexrays.init_hexrays_plugin():
                logger.log("Hex-Rays decompiler not available", level="ERROR")
                continue

            logger.log("Analyzing functions...")
            func_count = 0
            for ea in idautils.Functions():
                func = ida_funcs.get_func(ea)
                if func is None:
                    continue
                func_name = ida_funcs.get_func_name(ea)
                func_count += 1

                try:
                    func_info = analyze_function(func, maturity)
                    if func_info and func_info.insns:
                        _print_func_info(func_info, args.output)
                except Exception as e:
                    logger.log(f"Failed to analyze {func_name}: {e}", level="ERROR")

            logger.log(f"Analyzed {func_count} functions")

        finally:
            if target:
                _close_database()


if __name__ == "__main__":
    main()
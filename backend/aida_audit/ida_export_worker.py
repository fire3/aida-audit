import os
import sys
import argparse

# Ensure local modules can be imported
script_dir = os.path.dirname(os.path.abspath(__file__))
# idalib_dir check removed as files are local

import ida_utils
from binary_database import BinaryDatabase
from ida_exporter import IDAExporter

# Try to import IDA modules
try:
    import idapro
except ImportError:
    idapro = None

try:
    import ida_auto
    import ida_pro
    import ida_ida
    import idc
    import ida_nalt
except ImportError:
    print("Error: This script must be run within IDA Pro.")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Export IDA Pro database to SQLite binary.db")
    parser.add_argument("input_file", nargs='?', help="Path to input binary file (optional if running in IDA)")
    parser.add_argument("-o", "--output", help="Path to output SQLite database (default: binary.db in same dir)")
    parser.add_argument("--mode", choices=["standard", "master", "worker"], default="standard")
    parser.add_argument("--funcs-file", help="Function list path: output file in master mode, input file in worker mode")
    parser.add_argument("--fast", action="store_true", help="Enable fast analysis mode (disable some heavy analysis steps)")
    parser.add_argument("--save-idb", help="Save analyzed IDB/I64 to this path (optional; extension auto-chosen if omitted)")
    parser.add_argument("--role", choices=["target", "dependency"], help="Role of the binary: target (main) or dependency")
    args, unknown = parser.parse_known_args()

    if args.mode in ("master", "worker") and not args.funcs_file:
        print("Error: --funcs-file is required for master/worker mode.")
        sys.exit(1)

    logger = ida_utils.Logger(verbose=False, plain=True)
    timer = ida_utils.PerformanceTimer()

    opened_db = False
    if args.input_file and idapro:
        logger.log(f"Initializing IDA for {args.input_file}...")
        try:
            idapro.open_database(args.input_file, run_auto_analysis=True)
            opened_db = True
        except Exception as e:
            logger.log(f"Failed to open database: {e}")
            sys.exit(1)

    logger.log("Starting export script...")
    
    root_filename = None
    if args.output:
        db_path = os.path.abspath(args.output)
        root_filename = ida_nalt.get_input_file_path()
        if not root_filename and args.input_file:
            root_filename = args.input_file
            
    else:
        root_filename = ida_nalt.get_input_file_path()
        if not root_filename and args.input_file:
            root_filename = args.input_file
            
        if root_filename:
             db_path = os.path.splitext(root_filename)[0] + ".db"
        else:
             logger.log("Error: No input file provided or detected. Please specify an input file or run within an active IDA session.")
             sys.exit(1)

    logger.log(f"Output Database: {db_path}")

    if args.fast:
        logger.log("Fast analysis mode enabled.")
        af = ida_ida.inf_get_af()
        disable_mask = 0x20 | 0x2000 | 0x10000
        new_af = af & ~disable_mask
        ida_ida.inf_set_af(new_af)

    logger.log("Waiting for auto-analysis...")
    monitor = ida_utils.AutoAnalysisMonitor(logger.log)
    monitor.hook()
    
    analysis_start = timer.start_step("AutoAnalysis")
    ida_auto.auto_wait()
    
    import ida_funcs
    func_count = ida_funcs.get_func_qty()
    if func_count == 0:
        logger.log("Warning: No functions found after auto_wait. Attempting to force analysis...")
        import ida_segment
        ida_auto.set_auto_state(True)
        seg = ida_segment.get_first_seg()
        while seg:
             ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)
             seg = ida_segment.get_next_seg(seg.start_ea)
        
        ida_auto.auto_wait()
        func_count = ida_funcs.get_func_qty()
        logger.log(f"Function count after forced analysis: {func_count}")

    timer.end_step("AutoAnalysis")
    
    monitor.unhook()
    logger.log("Auto-analysis finished.")

    if args.save_idb:
        try:
            import ida_loader

            save_spec = os.path.abspath(args.save_idb)
            if save_spec.lower().endswith((".i64", ".idb")):
                save_path = save_spec
            else:
                existing_path = None
                try:
                    existing_path = ida_nalt.get_idb_path()
                except Exception:
                    existing_path = None

                ext = ""
                if existing_path:
                    ext = os.path.splitext(existing_path)[1].lower()
                if ext not in (".i64", ".idb"):
                    ext = ".i64"

                save_path = save_spec + ext

            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            ok = ida_loader.save_database(save_path, 0)
            if ok:
                logger.log(f"Saved IDA database: {save_path}")
                try:
                    if hasattr(ida_loader, 'DBFL_KILL'):
                        ida_loader.set_database_flag(ida_loader.DBFL_KILL)
                except Exception:
                    pass
            else:
                logger.log(f"Failed to save IDA database: {save_path}", level="WARN")
        except Exception as e:
            logger.log(f"Failed to save IDA database: {e}", level="WARN")

    try:
        db = BinaryDatabase(db_path, logger)
        db.connect()
        db.create_schema()
        
        exporter = IDAExporter(db, logger, timer, input_file=root_filename, role=args.role)
        
        if args.mode == "worker":
            logger.log(f"Worker mode: Loading functions from {args.funcs_file}...")
            import json
            with open(args.funcs_file, 'r') as f:
                func_list = json.load(f)
            
            logger.log(f"Worker processing {len(func_list)} functions...")
            exporter.export_pseudocode(function_list=func_list)
            
        elif args.mode == "master":
            logger.log("Master mode: Exporting metadata and structure (skipping pseudocode)...")
            exporter.dump_function_list(args.funcs_file)
            exporter.export_all_but_pseudocode()
        else:
            exporter.export_all()
        
        db.close()
        logger.log("Export completed successfully.")
        
    except Exception as e:
        logger.log(f"Export failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if ida_pro.qexit:
             if opened_db or idc.batch(0) == 1:
                 logger.log("Exiting IDA...")
                 ida_pro.qexit(0)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import argparse
import time
import glob
import shutil
import concurrent.futures
import threading
from datetime import datetime

# Configuration
PYTHON_CMD = "/home/fire3/opt/miniconda3/bin/python"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
DEFAULT_TEST_DIR = os.path.join(PROJECT_ROOT, "tests_cpg", "CWE78", "arm64")
DEFAULT_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "scan_results_cwe78")

print_lock = threading.Lock()

def run_command(cmd, cwd=None, timeout=None, env=None):
    """Run a shell command and return result."""
    try:
        start_time = time.time()
        result = subprocess.run(
            cmd,
            cwd=cwd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env
        )
        duration = time.time() - start_time
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration": duration,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": "Timeout expired",
            "duration": timeout,
            "returncode": -1
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "duration": 0,
            "returncode": -1
        }

def parse_scan_output(output):
    """Parse scan command output (multiple JSON objects)."""
    findings = []
    
    # Extract JSON part (everything after the log lines)
    # We look for the first occurrence of '{'
    start_idx = output.find('{')
    if start_idx == -1:
        return []
        
    json_text = output[start_idx:]
    decoder = json.JSONDecoder()
    pos = 0
    
    while pos < len(json_text):
        # Skip whitespace
        while pos < len(json_text) and json_text[pos].isspace():
            pos += 1
        if pos >= len(json_text):
            break
            
        try:
            obj, idx = decoder.raw_decode(json_text[pos:])
            findings.append(obj)
            pos += idx
        except json.JSONDecodeError:
            # If we fail to parse, try to skip to next '{'
            next_start = json_text.find('{', pos + 1)
            if next_start != -1:
                pos = next_start
            else:
                break
                
    return findings

def process_test_case(file_path, output_dir, clean, keep, verbose):
    filename = os.path.basename(file_path)
    
    case_dir = os.path.join(output_dir, filename)
    os.makedirs(case_dir, exist_ok=True)
    
    case_result = {
        "file": filename,
        "status": "unknown",
        "scan_time": 0,
        "findings": []
    }
    
    # Prepare environment with backend in PYTHONPATH
    env = os.environ.copy()
    if "PYTHONPATH" in env:
        env["PYTHONPATH"] = f"{BACKEND_DIR}:{env['PYTHONPATH']}"
    else:
        env["PYTHONPATH"] = BACKEND_DIR
        
    # Step 1: Scan (Handles export implicitly)
    # Use python -m aida_cli.cli scan directly on the binary
    scan_cmd = f"{PYTHON_CMD} -m aida_cli.cli scan \"{file_path}\" --rules cwe-78"
    scan_res = run_command(scan_cmd, cwd=PROJECT_ROOT, env=env)
    case_result["scan_time"] = scan_res["duration"]
    
    # Save scan logs
    with open(os.path.join(case_dir, "scan.stdout.log"), "w") as f:
        f.write(scan_res["stdout"])
    with open(os.path.join(case_dir, "scan.stderr.log"), "w") as f:
        f.write(scan_res["stderr"])
        
    if not scan_res["success"]:
        case_result["status"] = "scan_failed"
        return case_result
        
    # Step 2: Analyze
    findings = parse_scan_output(scan_res["stdout"])
    case_result["findings"] = findings
    
    has_cwe78 = any(f.get("rule_id") == "cwe-78" or f.get("rule") == "cwe-78" for f in findings)
    
    # Fallback check if rule_id is not in top level, check full dict
    if not has_cwe78 and findings:
         has_cwe78 = True # Since we only requested cwe-78 rules.
    
    if has_cwe78:
        case_result["status"] = "detected"
    else:
        case_result["status"] = "missed"
        
    if not keep:
        try:
            # We want to keep logs, but delete the rest (IDB, temporary files)
            # Strategy:
            # 1. Read log content
            # 2. Delete directory
            # 3. Re-create directory
            # 4. Write logs back
            # Alternatively: delete specific files. But IDB files can vary.
            # Simpler: remove everything EXCEPT .log files
            
            for f in os.listdir(case_dir):
                if not f.endswith(".log"):
                    full_path = os.path.join(case_dir, f)
                    if os.path.isdir(full_path):
                        shutil.rmtree(full_path)
                    else:
                        os.remove(full_path)
        except Exception as e:
            # Can't print easily in thread
            pass
            
    return case_result

def main():
    parser = argparse.ArgumentParser(description="Regression Test for CWE78")
    parser.add_argument("testcases_dir", default=DEFAULT_TEST_DIR, help="Directory containing test binaries")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory to save results")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of tests (0 for all)")
    parser.add_argument("--filter", help="Filter test cases by filename substring")
    parser.add_argument("--clean", action="store_true", help="Clean output directory before running")
    parser.add_argument("--keep", action="store_true", help="Keep temporary artifacts after test")
    parser.add_argument("-j", "--jobs", type=int, default=1, help="Number of parallel test cases")
    parser.add_argument("--verbose", action="store_true", help="Show verbose output")
    
    args = parser.parse_args()

    # Use provided directory or default
    test_dir = args.testcases_dir if args.testcases_dir else DEFAULT_TEST_DIR

    # Setup directories
    if args.clean and os.path.exists(args.output_dir):
        print(f"Cleaning output directory: {args.output_dir}")
        shutil.rmtree(args.output_dir)
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Collect test files
    if not os.path.exists(test_dir):
        print(f"Error: Test directory not found: {test_dir}")
        sys.exit(1)
        
    all_files = sorted(os.listdir(test_dir))
    test_files = []
    for f in all_files:
        path = os.path.join(test_dir, f)
        if not os.path.isfile(path):
            continue
        # Skip known non-binaries if any (based on extension)
        if f.endswith(('.json', '.i64', '.idb', '.c', '.h', '.md')):
            continue
        
        if args.filter and args.filter not in f:
            continue
            
        test_files.append(path)
    
    if args.limit > 0:
        test_files = test_files[:args.limit]
        
    print(f"Found {len(test_files)} test files.")
    print(f"Output directory: {args.output_dir}")
    print(f"Parallel jobs: {args.jobs}")
    if args.filter:
        for f in test_files:
            case_name = os.path.basename(f)
            print(f"  Logs: {args.output_dir}/{case_name}/scan.stdout.log")
            print(f"  Logs: {args.output_dir}/{case_name}/scan.stderr.log")
    print("-" * 60)
    
    results = {
        "timestamp": datetime.now().isoformat(),
        "total": len(test_files),
        "processed": 0,
        "export_failures": 0,
        "scan_failures": 0,
        "detected": 0,
        "missed": 0,
        "details": []
    }
    
    start_total = time.time()
    
    # Process files in parallel
    completed_count = 0
    total_count = len(test_files)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        # Create a map of future to filename for error reporting
        future_to_file = {
            executor.submit(process_test_case, f, args.output_dir, args.clean, args.keep, args.verbose): f 
            for f in test_files
        }
        
        for future in concurrent.futures.as_completed(future_to_file):
            file_path = future_to_file[future]
            filename = os.path.basename(file_path)
            
            try:
                case_result = future.result()
                
                with print_lock:
                    completed_count += 1
                    status = case_result["status"]
                    print(f"[{completed_count}/{total_count}] {filename}: {status}")
                    
                    results["processed"] += 1
                    results["details"].append(case_result)
                    
                    if status == "detected":
                        results["detected"] += 1
                    elif status == "missed":
                        results["missed"] += 1
                    elif status == "export_failed":
                        results["export_failures"] += 1
                        print(f"  Export failed for {filename}")
                    elif status.startswith("scan_failed"):
                        results["scan_failures"] += 1
                        print(f"  Scan failed for {filename}")
                        
            except Exception as e:
                with print_lock:
                    print(f"Error processing {filename}: {e}")
                    # Count as failure?
                    results["processed"] += 1 # technically processed but failed
                    case_result = {
                        "file": filename,
                        "status": "script_error",
                        "error": str(e)
                    }
                    results["details"].append(case_result)

    duration_total = time.time() - start_total
    results["duration_total"] = duration_total
    
    # Summary
    print("-" * 60)
    print(f"Total Files: {results['total']}")
    print(f"Processed:   {results['processed']}")
    print(f"Detected:    {results['detected']}")
    print(f"Missed:      {results['missed']}")
    print(f"Export Fail: {results['export_failures']}")
    print(f"Scan Fail:   {results['scan_failures']}")
    
    if results['processed'] > 0:
        rate = (results['detected'] / results['processed']) * 100
        print(f"Detection Rate: {rate:.2f}%")

    missed_cases = [d["file"] for d in results["details"] if d["status"] == "missed"]
    if missed_cases:
        print("\nMissed Cases:")
        for case in missed_cases:
            print(f"  {case}")
    
    report_path = os.path.join(args.output_dir, "report.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Report saved to {report_path}")

if __name__ == "__main__":
    main()

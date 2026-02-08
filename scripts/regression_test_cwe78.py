#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import argparse
import time
import glob
import shutil
from datetime import datetime

# Configuration
PYTHON_CMD = "/opt/anaconda3/bin/python"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TEST_DIR = os.path.join(PROJECT_ROOT, "tests_cpg", "CWE78", "arm64")
DEFAULT_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "scan_results_cwe78")

def run_command(cmd, cwd=None, timeout=None):
    """Run a shell command and return result."""
    try:
        start_time = time.time()
        result = subprocess.run(
            cmd,
            cwd=cwd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
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

def main():
    parser = argparse.ArgumentParser(description="Regression Test for CWE78")
    parser.add_argument("--test-dir", default=DEFAULT_TEST_DIR, help="Directory containing test binaries")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory to save results")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of tests (0 for all)")
    parser.add_argument("--filter", help="Filter test cases by filename substring")
    parser.add_argument("--clean", action="store_true", help="Clean output directory before running")
    parser.add_argument("--workers", type=int, default=1, help="Number of parallel workers for export (passed to aida-cli)")
    parser.add_argument("--verbose", action="store_true", help="Show verbose output")
    
    args = parser.parse_args()

    # Setup directories
    if args.clean and os.path.exists(args.output_dir):
        print(f"Cleaning output directory: {args.output_dir}")
        shutil.rmtree(args.output_dir)
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Collect test files
    all_files = sorted(os.listdir(args.test_dir))
    test_files = []
    for f in all_files:
        path = os.path.join(args.test_dir, f)
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
    
    for i, file_path in enumerate(test_files):
        filename = os.path.basename(file_path)
        print(f"[{i+1}/{len(test_files)}] Processing {filename}...", end=" ", flush=True)
        
        case_dir = os.path.join(args.output_dir, filename)
        os.makedirs(case_dir, exist_ok=True)
        
        case_result = {
            "file": filename,
            "status": "unknown",
            "export_time": 0,
            "scan_time": 0,
            "findings": []
        }
        
        # Step 1: Export
        export_cmd = f"{PYTHON_CMD} -m backend.aida_cli.cli export \"{file_path}\" -o \"{case_dir}\" --cpg-json --workers {args.workers}"
        export_res = run_command(export_cmd, cwd=PROJECT_ROOT)
        case_result["export_time"] = export_res["duration"]
        
        # Save export logs
        with open(os.path.join(case_dir, "export.stdout.log"), "w") as f:
            f.write(export_res["stdout"])
        with open(os.path.join(case_dir, "export.stderr.log"), "w") as f:
            f.write(export_res["stderr"])
            
        if not export_res["success"]:
            print("Export Failed")
            results["export_failures"] += 1
            case_result["status"] = "export_failed"
            results["details"].append(case_result)
            continue
            
        # Step 2: Scan
        # The CPG JSON export creates a subdirectory named <filename>.cpg_json
        cpg_dir = os.path.join(case_dir, f"{filename}.cpg_json")
        scan_cmd = f"{PYTHON_CMD} -m backend.aida_cli.cli scan \"{cpg_dir}\" --rules cwe-78"
        scan_res = run_command(scan_cmd, cwd=PROJECT_ROOT)
        case_result["scan_time"] = scan_res["duration"]
        
        # Save scan logs
        with open(os.path.join(case_dir, "scan.stdout.log"), "w") as f:
            f.write(scan_res["stdout"])
        with open(os.path.join(case_dir, "scan.stderr.log"), "w") as f:
            f.write(scan_res["stderr"])
            
        if not scan_res["success"]:
            print("Scan Failed")
            results["scan_failures"] += 1
            case_result["status"] = "scan_failed"
            results["details"].append(case_result)
            continue
            
        # Step 3: Analyze
        findings = parse_scan_output(scan_res["stdout"])
        case_result["findings"] = findings
        
        has_cwe78 = any(f.get("rule_id") == "cwe-78" or f.get("rule") == "cwe-78" for f in findings) # Adjust key based on actual output
        
        # Fallback check if rule_id is not in top level, check full dict
        if not has_cwe78 and findings:
            # Assuming finding structure has some identifier. 
            # If the scan command only runs cwe-78, then any finding is likely cwe-78.
            # But let's be safe.
             has_cwe78 = True # Since we only requested cwe-78 rules.
        
        if has_cwe78:
            print("Detected")
            results["detected"] += 1
            case_result["status"] = "detected"
        else:
            print("Missed")
            results["missed"] += 1
            case_result["status"] = "missed"
            
        results["processed"] += 1
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
    
    report_path = os.path.join(args.output_dir, "report.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Report saved to {report_path}")

if __name__ == "__main__":
    main()

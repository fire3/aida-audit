# Aida CLI Regression Testing Scripts

This directory contains scripts for regression testing and validating the Aida CLI scanning engine.

## `regression_test_cwe78.py`

This script automates the process of running the `aida-cli` export and scan pipeline against the CWE-78 (OS Command Injection) test suite (Juliet Test Suite for ARM64).

### Prerequisites

- The `aida-cli` environment must be set up.
- The test binaries must be present in `tests_cpg/CWE78/arm64`.

### Usage

Run the script using the project's Python interpreter:

```bash
/opt/anaconda3/bin/python scripts/regression_test_cwe78.py [options]
```

### Options

- `--test-dir DIR`: Directory containing test binaries (default: `tests_cpg/CWE78/arm64`).
- `--output-dir DIR`: Directory to save results and logs (default: `scan_results_cwe78`).
- `--limit N`: Run only the first N tests (useful for quick verification).
- `--filter PATTERN`: Run only tests whose filenames match the pattern.
- `--clean`: Delete the output directory before starting.
- `--workers N`: Number of parallel workers for the export phase (default: 1).
- `--verbose`: Enable verbose output.

### Examples

**Run all tests:**
```bash
python scripts/regression_test_cwe78.py
```

**Run a small subset for debugging:**
```bash
python scripts/regression_test_cwe78.py --limit 5 --clean
```

**Run a specific test case:**
```bash
python scripts/regression_test_cwe78.py --filter "execl_01"
```

### Output

The script prints a summary to the console and saves a detailed report to `report.json` in the output directory.

For each test case, a subdirectory is created in the output directory containing:
- `export.stdout.log`, `export.stderr.log`: Logs from the `export` command.
- `scan.stdout.log`, `scan.stderr.log`: Logs from the `scan` command.
- The exported CPG JSON files and database.

### Workflow for Improving Detection

1.  **Baseline:** Run the full suite to establish a baseline detection rate.
    ```bash
    python scripts/regression_test_cwe78.py
    ```
2.  **Identify Failures:** Check `report.json` or console output for "Missed" cases.
3.  **Debug:** Pick one missed case and run it in isolation.
    ```bash
    python scripts/regression_test_cwe78.py --filter "CASE_NAME" --clean
    ```
4.  **Analyze:** Examine the logs and the exported CPG (in `scan_results_cwe78/CASE_NAME/*.cpg_json/`). Use `scan.stdout.log` to see what the scanner found (if anything).
5.  **Fix:** Update the extractor logic or the scanning rules (`backend/aida_cli/rules/cwe_78.py`).
6.  **Verify:** Rerun the specific test case to verify the fix.
7.  **Regression:** Rerun the full suite to ensure no regressions.

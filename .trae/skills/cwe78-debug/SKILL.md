---
name: "cwe78-debug"
description: "Debugs CWE78 regression test misses. Invoke when analyzing scan failures or 'missed' results in regression tests."
---

# CWE78 Regression Test Debugging Guide

This skill provides context and steps for debugging missed detections or failures in the CWE78 regression test suite.

## Environment

- **Python Interpreter**: `/home/fire3/opt/miniconda3/bin/python`
- **Project Root**: `/home/fire3/SRC/aida-mcp`
- **Environment Variables**:
  - `PYTHONPATH`: Must include `backend` directory (handled automatically by the test script).

## Key Scripts

### 1. Regression Test Script
- **Path**: `scripts/regression_test_cwe78.py`
- **Key Arguments**:
  - `-j N`: Run N parallel jobs (default: 1).
  - `--keep`: Preserve artifacts (IDB files, logs) in `scan_results_cwe78/` after execution.
  - `--verbose`: Enable detailed logging (propagates to `aida-cli scan`).
  - `--filter <name>`: Run specific test cases matching the name.
  - `--limit N`: Run only first N test cases.

### 2. Aida CLI Scan Command
- **Implementation**: `backend/aida_cli/scan_cmd.py`
- **Usage**: `python -m aida_cli.cli scan <target_binary> --rules cwe-78`

## Debugging Workflow

If a test case returns `missed` or `scan_failed`:

### 1. Reproduce the Issue
Run the specific test case in isolation with debugging flags enabled:

```bash
/home/fire3/opt/miniconda3/bin/python scripts/regression_test_cwe78.py \
  --filter <case_name> \
  --keep \
  --verbose \
```

### 2. Inspect Artifacts
Check the output directory: `scan_results_cwe78/<case_name>/`

- **scan.stdout.log**: Main scan output. Check for "Global scan failed" or empty findings list.
- **scan.stderr.log**: Python tracebacks or IDA/Hex-Rays errors.
- **export.stdout.log**: IDB generation logs. Ensure the IDB file was actually created.

### 3. Common Failure Modes

#### "missed" (Detection failed)
- **Cause**: The scanner ran but found no vulnerabilities.
- **Check**: `scan.stdout.log` for partial traces.
- **Analysis**:
  - Verify if the **Source** (e.g., `socket`, `getenv`) is recognized.
  - Verify if the **Sink** (e.g., `execl`, `system`) is recognized.
  - Check **Taint Propagation** breaks (e.g., pointer aliasing, complex arithmetic).
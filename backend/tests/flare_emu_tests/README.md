# Flare-Emu AIDA Test Suite

This directory contains test cases and scripts to verify the functionality of `flare_emu_aida`, which allows emulation of binaries using `flare_emu` backed by an AIDA exported SQLite database instead of IDA Pro.

## Directory Structure

*   `src/`: Contains C/C++ source code for test binaries.
*   `bin/`: (To be created) Contains compiled binaries and exported databases.
*   `run_tests.py`: Python script to run emulation tests using `flare_emu_aida`.

## Prerequisites

1.  **Python 3.x**
2.  **Unicorn Engine** (`pip install unicorn`)
3.  **AIDA Backend** (installed or in PYTHONPATH)
4.  **C Compiler** (GCC, Clang, or MSVC) to compile test cases.
5.  **IDA Pro + AIDA Plugin** to export the test binary to SQLite.

## How to Run Tests

### 1. Compile the Test Binary

Compile `src/test_basic.c` into a binary (e.g., `test_basic.exe` or `test_basic.o`).

**Windows (MSVC):**
```cmd
cl /Fe:bin\test_basic.exe src\test_basic.c /LD
```
(Using `/LD` to create a DLL is recommended so functions are exported and easy to find, but EXE with symbols also works if PDB is available or functions are not stripped).

**Linux (GCC):**
```bash
gcc -shared -o bin/test_basic.so src/test_basic.c
```

### 2. Export to AIDA Database

Use IDA Pro with the AIDA plugin to export the binary to a SQLite database.

```bash
# Using the CLI tool (if configured) or IDA GUI
python backend/aida_cli/ida_export_worker.py bin/test_basic.exe --output bin/test_basic.db
```

### 3. Run the Test Runner

Set the `AIDA_TEST_DB` environment variable to the path of the exported database and run the python script.

**Windows (PowerShell):**
```powershell
$env:AIDA_TEST_DB = "bin\test_basic.db"
python run_tests.py
```

**Linux/Mac:**
```bash
export AIDA_TEST_DB=bin/test_basic.db
python run_tests.py
```

## Test Cases

The `run_tests.py` script includes several test cases defined in `TEST_CASES` list:

*   `test_add`: Simple addition (Argument passing in registers).
*   `test_strlen`: String length calculation (Memory reading).
*   `test_xor_crypt`: XOR encryption (Memory writing).
*   `test_fib`: Fibonacci sequence (Recursion and stack usage).
*   `test_complex_path`: Loop and conditional logic (Control flow).

## Extending Tests

To add more tests:
1.  Add a new function to `src/test_basic.c`.
2.  Recompile and re-export the binary.
3.  Add a new entry to `TEST_CASES` in `run_tests.py` with the function name, arguments, and expected result.

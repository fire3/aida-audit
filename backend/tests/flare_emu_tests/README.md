# Flare-Emu AIDA Test Suite

This directory contains the test framework and test cases for `flare_emu_aida`. The framework automates the process of compiling test binaries, exporting them to AIDA databases (using IDA Pro), and running emulation tests defined in YAML/DSL.

## Directory Structure

*   `test_runner.py`: The main test execution script.
*   `cases/`: Directory containing test cases.
    *   `linux/`, `windows/`: Platform-specific test cases.
    *   Each test case is a directory (e.g., `cases/linux/dsl_demo/`) containing:
        *   `test_config.yaml`: Test configuration file.
        *   `*.c`: Source code for the test binary.
        *   `*.dsl`: Flare-Emu Text DSL scripts.

## How to Run Tests

Ensure you have the necessary dependencies installed (Python 3, Unicorn, PyYAML) and IDA Pro available if you need to re-export databases.

### Run All Tests

```bash
python backend/tests/flare_emu_tests/test_runner.py
```

### Run Specific Test Case

Use the `--case` argument to filter by test case directory name.

```bash
python backend/tests/flare_emu_tests/test_runner.py --case dsl_demo
```

### Options

*   `--force-build`: Force recompilation of the test binary.
*   `--force-export`: Force re-export of the AIDA database (requires IDA Pro).
*   `--ida-path`: Specify path to IDA executable (if not in PATH).

## Creating New Tests

1.  **Create a Directory**: Create a new directory in `cases/<platform>/<test_name>`.
2.  **Add Source Code**: Create a C file (e.g., `test.c`) with functions you want to test. Ensure functions are exported (e.g., not `static`).
3.  **Create DSL Scripts**: Write `.dsl` files for your test logic. See [DSL Syntax Guide](../../aida_cli/templates/flare_emu_dsl_guide.md) for details.
4.  **Create Configuration**: Create `test_config.yaml` to define build steps and test definitions.

### Configuration File (`test_config.yaml`)

The configuration file defines how to build the binary and maps tests to DSL scripts.

```yaml
binary: test_demo              # Target binary name
source: test_demo.c            # Source file (for reference/build)
targets:                       # Build configurations per platform
  linux:
    build_cmd: gcc -g -O0 -shared -fPIC -o test_demo test_demo.c
    binary: test_demo
  windows:
    build_cmd: cl /Fe:test_demo.exe test_demo.c /LD
    binary: test_demo.exe

tests:
  - name: test_basic_add       # Test name
    description: Test addition function
    script_file: test_add.dsl  # Path to DSL script (relative to case directory)
  
  - name: test_inline          # You can also use inline scripts
    script: |
      $res = call test_add(10, 20)
      assert $res == 30
```

### DSL Script (`.dsl`)

DSL scripts define the emulation steps.

```text
$res = call test_add(10, 20)
assert $res == 30
```

For full DSL syntax documentation, refer to `backend/aida_cli/templates/flare_emu_dsl_guide.md`.

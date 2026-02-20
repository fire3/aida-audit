import os
import sys
import argparse
import logging
import json
import shutil
import unittest
import subprocess
import glob
import platform

# Ensure backend directory is in path
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.abspath(os.path.join(current_dir, "../.."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from aida_cli.flare_emu_aida import AidaEmuHelper
from aida_cli.flare_emu_dsl import DSLRunner, TextDSLParser

# Constants
CASES_DIR = os.path.join(current_dir, "cases", platform.system().lower())
DEFAULT_IDA_EXPORT_SCRIPT = os.path.join(backend_dir, "aida_cli", "ida_export_worker.py")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("TestRunner")

class TestRunner:
    def __init__(self, cases_dir=CASES_DIR, filter_case=None, force_export=False, force_build=False, ida_path=None):
        self.cases_dir = cases_dir
        self.filter_case = filter_case
        self.force_export = force_export
        self.force_build = force_build
        self.ida_path = ida_path
        self.results = {}
        self.os_type = platform.system().lower() # windows, linux, darwin

    def discover_cases(self):
        cases = []
        if not os.path.exists(self.cases_dir):
            logger.error(f"Cases directory not found: {self.cases_dir}")
            return cases
            
        for name in os.listdir(self.cases_dir):
            case_path = os.path.join(self.cases_dir, name)
            if not os.path.isdir(case_path):
                continue
                
            if self.filter_case and self.filter_case not in name:
                continue
                
            config_path = os.path.join(case_path, "test_config.json")
            if os.path.exists(config_path):
                cases.append((name, case_path, config_path))
        return cases

    def get_target_config(self, config):
        """Get build config for current OS"""
        targets = config.get("targets", {})
        if self.os_type in targets:
            return targets[self.os_type]
        # Fallback check (e.g. if running on WSL but targeting windows binary?)
        # For now strict check
        return None

    def build_binary(self, case_path, source_file, target_config):
        build_cmd = target_config.get("build_cmd")
        if not build_cmd:
            logger.warning(f"No build command for {self.os_type} in {case_path}")
            return False

        logger.info(f"Building binary: {build_cmd}")
        try:
            # Run build command in case directory
            result = subprocess.run(build_cmd, cwd=case_path, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Build failed:\n{result.stderr}\n{result.stdout}")
                return False
            return True
        except Exception as e:
            logger.error(f"Build exception: {e}")
            return False

    def cleanup_case_files(self, case_path, binary_name):
        """Clean up binary, AIDA DB, and IDA database files."""
        binary_path = os.path.join(case_path, binary_name)
        
        # Files to remove:
        # 1. The binary itself
        # 2. The AIDA DB (.db)
        # 3. IDA database files (.i64, .idb) - checking both appended and replaced extension
        
        files_to_remove = [
            binary_path,
            binary_path + ".db",
            binary_path + ".i64",
            binary_path + ".idb",
        ]
        
        # specific handling for IDA DB naming conventions
        # If binary is "test.exe", IDA makes "test.i64" (usually) or "test.exe.i64" depending on version/settings
        # We'll try to catch common variations
        base_name = os.path.splitext(binary_name)[0]
        if base_name != binary_name:
             files_to_remove.append(os.path.join(case_path, base_name + ".i64"))
             files_to_remove.append(os.path.join(case_path, base_name + ".idb"))

        # Deduplicate list
        files_to_remove = list(set(files_to_remove))

        for f in files_to_remove:
            if os.path.exists(f):
                try:
                    if os.path.isdir(f):
                        shutil.rmtree(f)
                    else:
                        os.remove(f)
                    logger.info(f"Removed file: {f}")
                except OSError as e:
                    logger.warning(f"Failed to remove {f}: {e}")

    def prepare_case(self, case_name, case_path, config_path):
        logger.info(f"Preparing case: {case_name}")
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config for {case_name}: {e}")
            return None

        # Determine target binary
        target_config = self.get_target_config(config)
        binary_name = None
        
        if target_config:
            binary_name = target_config.get("binary")
        
        if not binary_name:
            # Legacy fallback
            binary_name = config.get("binary")
            
        if not binary_name:
             logger.error(f"No binary specified for {self.os_type} in config.")
             return None

        # Clean up existing files to ensure clean start
        self.cleanup_case_files(case_path, binary_name)

        binary_path = os.path.join(case_path, binary_name)
        # Use .so.db / .dll.db convention to match aida_cli export
        db_path = binary_path + ".db"
        source_file = config.get("source")
        
        # Check if build needed - always true since we cleaned up
        needs_build = True

        if needs_build:
            if not target_config:
                 logger.error(f"Build needed but no target config for {self.os_type}.")
                 # If binary missing, fail. If just old, maybe proceed? No, safer to fail or warn.
                 if not os.path.exists(binary_path):
                     return None
            else:
                if not self.build_binary(case_path, source_file, target_config):
                    if not os.path.exists(binary_path):
                        logger.error("Build failed and no previous binary exists. Aborting case.")
                        return None
                    logger.warning("Build failed, trying to use existing binary.")

        # Check export needed
        needs_export = self.force_export
        if not os.path.exists(db_path):
            needs_export = True
        elif os.path.getsize(db_path) == 0:
            logger.info(f"DB is empty for {case_name}. Re-exporting.")
            needs_export = True
        elif os.path.getmtime(binary_path) > os.path.getmtime(db_path):
            logger.info(f"Binary is newer than DB for {case_name}. Re-exporting.")
            needs_export = True
            
        if needs_export:
            if not self.run_export(binary_path, db_path):
                logger.error(f"Export failed for {case_name}. Skipping tests.")
                return None
                
        return {
            "name": case_name,
            "case_path": case_path,
            "config": config,
            "db_path": db_path,
            "binary_name": binary_name
        }

    def run_export(self, binary_path, db_path):
        output_dir = os.path.dirname(db_path)
        logger.info(f"Running export for {binary_path} -> {output_dir}")
        
        # Remove empty DB if exists to force re-export
        if os.path.exists(db_path) and os.path.getsize(db_path) == 0:
             logger.warning(f"Removing empty DB file: {db_path}")
             try:
                 os.remove(db_path)
             except OSError as e:
                 logger.error(f"Failed to remove empty DB: {e}")

        # Use local aida_cli.cli export command
        # To avoid relative import error, we should run it as a module but with proper PYTHONPATH
        # The correct way to run a module inside a package from outside is:
        # python -m aida_cli.cli ...
        # But we must ensure 'backend' is in PYTHONPATH so it can find 'aida_cli'
        
        # Ensure environment has backend in PYTHONPATH
        env = os.environ.copy()
        if backend_dir not in env.get("PYTHONPATH", ""):
            env["PYTHONPATH"] = backend_dir + os.pathsep + env.get("PYTHONPATH", "")
            
        cmd = [sys.executable, "-m", "aida_cli.cli", "export", binary_path, "--output", output_dir]

        try:
            # We don't check for IDA specifically here, assuming user environment is set up
            # as they claimed "aida_cli.cli export command works"
            
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            logger.info(f"Export command finished with return code {result.returncode}")
            
            # Print stdout and stderr for debugging as requested
            if result.stdout:
                logger.info(f"STDOUT:\n{result.stdout}")
            if result.stderr:
                logger.info(f"STDERR:\n{result.stderr}")

            if result.returncode != 0:
                logger.error(f"Export command failed:\n{result.stderr}\n{result.stdout}")
                return False
            
            # Check if DB was created and is valid
            if not os.path.exists(db_path):
                logger.error(f"Export command succeeded but DB not found: {db_path}")
                return False
                
            size = os.path.getsize(db_path)
            logger.info(f"DB file size: {size} bytes")
            if size == 0:
                logger.error(f"Export command succeeded but DB is empty: {db_path}")
                return False

            # Verify tables exist
            try:
                import sqlite3
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                logger.info(f"Tables in DB: {tables}")
                conn.close()
            except Exception as e:
                logger.error(f"Failed to inspect DB tables: {e}")

            return True
        except Exception as e:
            logger.error(f"Failed to run export: {e}")
            return False

    def run_tests(self):
        cases = self.discover_cases()
        if not cases:
            logger.warning("No test cases found.")
            return

        for name, case_path, config_path in cases:
            case_data = self.prepare_case(name, case_path, config_path)
            if not case_data:
                continue
                
            self.execute_case_tests(case_data)
            
            # Post-cleanup to ensure clean environment
            binary_name = case_data.get("binary_name")
            if binary_name:
                self.cleanup_case_files(case_path, binary_name)
        
        self.print_summary()

    def execute_case_tests(self, case_data):
        case_name = case_data["name"]
        db_path = case_data["db_path"]
        config = case_data["config"]
        
        logger.info(f"Running tests for {case_name} using DB: {db_path}")
        
        try:
            eh = AidaEmuHelper(db_path, verbose=0)
        except Exception as e:
            logger.error(f"Failed to initialize emulator: {e}")
            self.results[case_name] = False
            return

        suite = unittest.TestSuite()
        
        for test_def in config.get("tests", []):
            # Inject case path for resolving script files
            test_def["_case_path"] = case_data["case_path"]
            suite.addTest(DynamicTestCase(eh, test_def))
            
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        self.results[case_name] = result.wasSuccessful()

    def print_summary(self):
        logger.info("-" * 40)
        logger.info("Test Summary")
        logger.info("-" * 40)
        all_passed = True
        for case, success in self.results.items():
            status = "PASSED" if success else "FAILED"
            logger.info(f"{case:<30}: {status}")
            if not success:
                all_passed = False
        logger.info("-" * 40)
        return all_passed


class DynamicTestCase(unittest.TestCase):
    def __init__(self, eh, test_def):
        super(DynamicTestCase, self).__init__()
        self.eh = eh
        self.test_def = test_def
        self._testMethodName = "run_dynamic_test"
        self._testMethodDoc = test_def.get("description", test_def["name"])

    def run_dynamic_test(self):
        # Check if this is a DSL test or legacy test
        if "script" in self.test_def:
            self._run_text_dsl_test(self.test_def["script"])
        elif "script_file" in self.test_def:
            # Resolve path relative to case dir
            script_path = os.path.join(self.test_def.get("_case_path", ""), self.test_def["script_file"])
            if not os.path.exists(script_path):
                self.fail(f"Script file not found: {script_path}")
            with open(script_path, "r") as f:
                script = f.read()
            self._run_text_dsl_test(script)
        elif "steps" in self.test_def:
            self._run_dsl_test()
        else:
            self._run_legacy_test()

    def _run_text_dsl_test(self, script):
        parser = TextDSLParser()
        try:
            scenario = parser.parse(script)
            # Merge name/description from test_def if available
            scenario["name"] = self.test_def.get("name", scenario["name"])
            runner = DSLRunner(self.eh)
            runner.run(scenario)
        except Exception as e:
            self.fail(f"Text DSL Execution failed: {e}")

    def _run_dsl_test(self):
        runner = DSLRunner(self.eh)
        try:
            runner.run(self.test_def)
        except Exception as e:
            self.fail(f"DSL Execution failed: {e}")

    def _run_legacy_test(self):
        # Convert legacy format to DSL steps internally or just run legacy logic
        # For simplicity and robustness, let's keep legacy logic separate for now
        # but we could refactor to use DSLRunner too.
        
        func_name = self.test_def["name"]
        args = self.test_def.get("args", [])
        expected_ret = self.test_def.get("expected_return")
        expected_mem = self.test_def.get("expected_memory")
        
        # Convert to DSL structure
        steps = []
        
        # Call step
        steps.append({
            "type": "call",
            "function": func_name,
            "args": args,
            "return_var": "retval" if expected_ret is not None else None
        })
        
        # Assert step
        checks = []
        if expected_ret is not None:
            # We need to know which register holds return value based on arch
            # DSLRunner handles this if we use "register" check with correct name
            # Or we can use the return_var feature we just added
            # But wait, legacy logic handles arch-specific return register manually.
            # Let's trust DSLRunner's abstraction if we use return_var?
            # Actually, DSLRunner._handle_call stores return value in variable from register
            # So we can check the variable.
            checks.append({
                "type": "variable",
                "name": "retval",
                "value": expected_ret
            })
            
        if expected_mem:
            # Legacy expected_memory format: {"arg_index": 1, "content": "..."}
            # We need to resolve arg pointer.
            # This is tricky because in legacy logic, args are allocated and pointers stored.
            # DSLRunner re-implements arg preparation.
            # If we want to use DSLRunner, we should let it handle args.
            pass

        # To avoid breaking changes and complex migration of legacy logic right now,
        # I will use the existing legacy implementation for _run_legacy_test
        # and only use DSLRunner for new tests.
        # But wait, the prompt asked to "adjust test_runner.py to use this DSL".
        # So I should try to migrate legacy tests to use DSL if possible, or at least support both.
        # Let's stick to the plan: use DSLRunner for DSL tests, and keep legacy logic for now,
        # OR refactor legacy logic to construct a DSL object and run it.
        
        # Refactoring legacy to use DSLRunner:
        dsl_scenario = {
            "name": func_name,
            "steps": []
        }
        
        # 1. Alloc args if needed (DSLRunner handles this inside 'call' step for simple cases)
        # But legacy expected_memory refers to arg by index.
        # DSLRunner doesn't easily expose arg pointers unless we alloc them explicitly first.
        
        # If expected_mem is used, we need to explicit alloc
        call_args = []
        setup_steps = []
        
        for i, arg in enumerate(args):
            # Check if this arg needs explicit alloc for later verification
            is_mem_check_target = False
            if expected_mem and expected_mem.get("arg_index") == i:
                is_mem_check_target = True
                
            if isinstance(arg, dict) and arg.get("type") in ["string", "bytes"]:
                # It's a pointer type
                if is_mem_check_target:
                    # Explicit alloc
                    var_name = f"arg_{i}"
                    setup_steps.append({
                        "type": "alloc",
                        "content": arg.get("value"),
                        "var": var_name
                    })
                    call_args.append({"type": "ptr", "value": f"${var_name}"})
                else:
                    call_args.append(arg)
            else:
                call_args.append(arg)
                
        dsl_scenario["steps"].extend(setup_steps)
        
        dsl_scenario["steps"].append({
            "type": "call",
            "function": func_name,
            "args": call_args,
            "return_var": "retval"
        })
        
        checks = []
        if expected_ret is not None:
             checks.append({
                "type": "variable",
                "name": "retval",
                "value": expected_ret
            })
            
        if expected_mem:
            arg_idx = expected_mem.get("arg_index")
            content = expected_mem.get("content")
            # We assumed we created a var for this
            var_name = f"arg_{arg_idx}"
            checks.append({
                "type": "memory",
                "addr": f"${var_name}",
                "content": content
            })
            
        if checks:
            dsl_scenario["steps"].append({
                "type": "assert",
                "checks": checks
            })
            
        # Run via DSLRunner
        runner = DSLRunner(self.eh)
        try:
            runner.run(dsl_scenario)
        except Exception as e:
            self.fail(f"Legacy (via DSL) Execution failed: {e}")
            
    # Keep the original implementation as fallback or reference if needed?
    # No, I will replace it.


    def __str__(self):
        return f"{self.test_def['name']} ({self.test_def.get('description', '')})"


def main():
    parser = argparse.ArgumentParser(description="Flare-Emu AIDA Test Runner")
    parser.add_argument("--case", help="Filter specific test case name")
    parser.add_argument("--force-export", action="store_true", help="Force re-export of DB")
    parser.add_argument("--force-build", action="store_true", help="Force re-build of binary")
    parser.add_argument("--ida-path", help="Path to IDA executable (for export)")
    args = parser.parse_args()

    runner = TestRunner(
        filter_case=args.case, 
        force_export=args.force_export, 
        force_build=args.force_build,
        ida_path=args.ida_path
    )
    runner.run_tests()

if __name__ == "__main__":
    main()

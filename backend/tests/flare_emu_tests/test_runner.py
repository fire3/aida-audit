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

        # Use aida_cli module export command
        cmd = [sys.executable, "-m", "aida_cli.cli", "export", binary_path, "--output", output_dir]
        
        # Ensure environment has backend in PYTHONPATH
        env = os.environ.copy()
        if backend_dir not in env.get("PYTHONPATH", ""):
            env["PYTHONPATH"] = backend_dir + os.pathsep + env.get("PYTHONPATH", "")

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
        func_name = self.test_def["name"]
        args = self.test_def.get("args", [])
        expected_ret = self.test_def.get("expected_return")
        expected_mem = self.test_def.get("expected_memory")
        
        addr = self.eh.analysisHelper.getNameAddr(func_name)
        if addr is None:
            self.fail(f"Function {func_name} not found.")

        real_args = []
        allocated_ptrs = []
        
        # Argument preparation
        for arg in args:
            val = arg
            if isinstance(arg, dict):
                type_ = arg.get("type", "int")
                val_raw = arg.get("value")
                
                if type_ == "string":
                    if isinstance(val_raw, str):
                        val_raw = val_raw.encode("utf-8") + b"\x00"
                    mem = self.eh.allocEmuMem(len(val_raw))
                    self.eh.writeEmuMem(mem, val_raw)
                    val = mem
                elif type_ == "bytes":
                    if isinstance(val_raw, str):
                        val_raw = val_raw.encode("utf-8") # Simple encoding
                    mem = self.eh.allocEmuMem(len(val_raw))
                    self.eh.writeEmuMem(mem, val_raw)
                    val = mem
                
            real_args.append(val)

        # Register setup
        arch = self.eh.analysisHelper.getArch()
        bitness = self.eh.analysisHelper.getBitness()
        registers = {}
        stack = []
        
        if arch == "X86":
            if bitness == 64:
                # Windows x64 (RCX, RDX, R8, R9) - Assumes Windows binary for now
                # TODO: Check binary format (PE vs ELF) from AnalysisHelper to switch ABI?
                # AidaAnalysisHelper sets filetype to PE/ELF.
                ftype = self.eh.analysisHelper.getFileType()
                
                if ftype == "PE":
                    regs = ["rcx", "rdx", "r8", "r9"]
                    stack = [0] * 4 # Shadow space
                    for i, arg in enumerate(real_args):
                        if i < 4: registers[regs[i]] = arg
                        else: stack.append(arg)
                else:
                    # System V AMD64 (RDI, RSI, RDX, RCX, R8, R9)
                    regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
                    for i, arg in enumerate(real_args):
                        if i < 6: registers[regs[i]] = arg
                        else: stack.append(arg)
                        
                stack.insert(0, 0xDEADBEEF) # Return addr
            else:
                # x86 cdecl
                for arg in reversed(real_args):
                    stack.append(arg)
                stack.insert(0, 0xDEADBEEF)
        
        try:
            self.eh.emulateRange(addr, registers=registers, stack=stack)
        except Exception as e:
            self.fail(f"Emulation error: {e}")

        # Return value check
        if expected_ret is not None:
            ret_val = 0
            if arch == "X86":
                reg = "rax" if bitness == 64 else "eax"
                ret_val = self.eh.getRegVal(reg)
            self.assertEqual(ret_val, expected_ret, f"Return value mismatch. Expected {expected_ret}, got {ret_val}")

        # Memory check
        if expected_mem:
            arg_idx = expected_mem.get("arg_index")
            content = expected_mem.get("content")
            if isinstance(content, str):
                content = content.encode("utf-8")
                
            if arg_idx is not None and arg_idx < len(real_args):
                ptr = real_args[arg_idx]
                actual = self.eh.getEmuBytes(ptr, len(content))
                self.assertEqual(actual, content, "Memory content mismatch")

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

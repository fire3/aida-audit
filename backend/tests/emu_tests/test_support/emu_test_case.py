import os
import sys
import subprocess
import tempfile
import shutil
from typing import Optional, Dict, Any, List
from pathlib import Path

# Add backend to path for aida_emu
# From tests/test_support/ to backend/aida_cli/
backend_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "backend", "aida_cli"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)


class EmulatorTestCase:
    """测试支持基类 - 封装编译、导出、模拟器创建流程"""
    
    def __init__(self, program_dir: str, program_name: str):
        self.program_dir = program_dir
        self.program_name = program_name
        self.binary_path: Optional[str] = None
        self.db_path: Optional[str] = None
        self.emu: Optional[Any] = None
        self._tmpdir: Optional[tempfile.TemporaryDirectory] = None
    
    def compile(self, cc: str = "gcc", cflags: str = "-O0 -g") -> bool:
        """编译程序"""
        make_result = subprocess.run(
            ["make", f"CC={cc}", f"CFLAGS={cflags}"],
            cwd=self.program_dir,
            capture_output=True,
            text=True
        )
        
        if make_result.returncode != 0:
            print(f"[ERROR] Compilation failed:")
            print(make_result.stderr)
            return False
        
        self.binary_path = os.path.join(self.program_dir, self.program_name)
        if not os.path.exists(self.binary_path):
            # 尝试查找编译产物
            program_files = list(Path(self.program_dir).glob("*"))
            executables = [f for f in program_files if os.access(f, os.X_OK)]
            if executables:
                self.binary_path = str(executables[0])
        
        print(f"[INFO] Compiled: {self.binary_path}")
        return os.path.exists(self.binary_path)
    
    def export_db(self, output_dir: str, backend: str = "ida") -> bool:
        """导出数据库"""
        if not self.binary_path or not os.path.exists(self.binary_path):
            print("[ERROR] Binary not found, cannot export")
            return False
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Find the backend/aida_cli directory
        project_root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        backend_dir = os.path.join(project_root, "aida_cli")
        
        cmd = [
            sys.executable, "-m", "aida_cli.cli", "export",
            self.binary_path,
            "-o", output_dir,
            "--backend", backend
        ]
        
        result = subprocess.run(
            cmd,
            cwd=backend_dir,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"[ERROR] Export failed:")
            print(result.stderr)
            return False
        
        # 查找生成的 db 文件 - 命名格式是 {binary_name}.db
        binary_name = os.path.basename(self.binary_path)
        expected_db = os.path.join(output_dir, f"{binary_name}.db")
        
        if os.path.exists(expected_db):
            self.db_path = expected_db
            print(f"[INFO] Exported DB: {self.db_path}")
            return True
        
        # Fallback: 查找任何 db 文件
        for f in os.listdir(output_dir):
            if f.endswith(".db") and not f.startswith("aida_audit"):
                self.db_path = os.path.join(output_dir, f)
                print(f"[INFO] Exported DB: {self.db_path}")
                return True
        
        print("[ERROR] No DB file generated")
        return False
    
    def create_emulator(self, stack_va: int = None, stack_size: int = 0x100000) -> Any:
        """创建模拟器"""
        from aida_emu import AidaEmulator
        
        if not self.db_path or not os.path.exists(self.db_path):
            raise RuntimeError("Database not available")
        
        self.emu = AidaEmulator.from_database(self.db_path)
        self.emu.setup_stack(stack_va, stack_size)
        print(f"[INFO] Emulator created for {self.program_name}")
        return self.emu
    
    def find_function_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """通过名称查找函数"""
        if not self.emu or not self.emu.db:
            return None
        
        self.emu.db.cursor.execute("""
            SELECT function_va, name, demangled_name, start_va, end_va, size
            FROM functions 
            WHERE name = ? OR demangled_name = ?
        """, (name, name))
        
        row = self.emu.db.cursor.fetchone()
        if row:
            return {
                "va": row[0],
                "name": row[1],
                "demangled_name": row[2],
                "start_va": row[3],
                "end_va": row[4],
                "size": row[5],
            }
        return None
    
    def find_function_by_va(self, va: int) -> Optional[Dict[str, Any]]:
        """通过地址查找函数"""
        if not self.emu or not self.emu.db:
            return None
        
        return self.emu.get_function(va)
    
    def run_function(self, func_va: int, *args) -> int:
        """运行函数并返回结果"""
        if not self.emu:
            raise RuntimeError("Emulator not created")
        return self.emu.call(func_va, *args)
    
    def cleanup(self):
        """清理资源"""
        if self.emu:
            self.emu.close()
            self.emu = None
        print(f"[INFO] Cleaned up: {self.program_name}")


def run_test_case(program_dir: str, program_name: str, 
                  test_func_name: str, test_args: List, expected_result: int,
                  stack_va: int = None, stack_size: int = 0x100000) -> Dict[str, Any]:
    """便捷函数: 运行单个测试用例"""
    test_case = EmulatorTestCase(program_dir, program_name)
    
    result = {
        "program": program_name,
        "function": test_func_name,
        "args": test_args,
        "expected": expected_result,
        "actual": None,
        "passed": False,
        "error": None,
    }
    
    try:
        # 编译
        if not test_case.compile():
            result["error"] = "Compilation failed"
            return result
        
        # 导出
        with tempfile.TemporaryDirectory() as tmpdir:
            if not test_case.export_db(tmpdir):
                result["error"] = "Export failed"
                return result
            
            # 创建模拟器
            test_case.create_emulator(stack_va, stack_size)
            
            # 查找函数
            func = test_case.find_function_by_name(test_func_name)
            if not func:
                result["error"] = f"Function '{test_func_name}' not found"
                return result
            
            # 运行
            result["actual"] = test_case.run_function(func["va"], *test_args)
            result["passed"] = result["actual"] == expected_result
            
    except Exception as e:
        result["error"] = str(e)
    finally:
        test_case.cleanup()
    
    return result


def print_test_result(result: Dict[str, Any]):
    """打印测试结果"""
    status = "PASS" if result["passed"] else "FAIL"
    print(f"[{status}] {result['program']}::{result['function']}({result['args']})")
    print(f"       Expected: {result['expected']}, Got: {result['actual']}")
    if result["error"]:
        print(f"       Error: {result['error']}")
import os
import sys
import tempfile

# Add paths
test_support_dir = os.path.join(os.path.dirname(__file__), "..", "test_support")
backend_dir = os.path.join(os.path.dirname(__file__), "..", "backend", "aida_cli")

for p in [test_support_dir, backend_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from test_support import EmulatorTestCase


class TestAddFunction:
    """测试 add(int a, int b) 函数"""
    
    @classmethod
    def setup_class(cls):
        """编译和导出"""
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        
        cls.test_case = EmulatorTestCase(program_dir, "add")
        
        # 编译
        if not cls.test_case.compile():
            raise RuntimeError("Compilation failed")
        
        # 导出到临时目录
        cls.tmpdir = tempfile.TemporaryDirectory()
        if not cls.test_case.export_db(cls.tmpdir.name):
            cls.tmpdir.cleanup()
            raise RuntimeError("Export failed")
        
        # 创建模拟器
        cls.test_case.create_emulator()
    
    @classmethod
    def teardown_class(cls):
        """清理"""
        if hasattr(cls, 'test_case'):
            cls.test_case.cleanup()
        if hasattr(cls, 'tmpdir'):
            cls.tmpdir.cleanup()
    
    def test_add_positive_numbers(self):
        """add(3, 5) = 8"""
        func = self.test_case.find_function_by_name("add")
        assert func is not None, "Function 'add' not found"
        
        result = self.test_case.run_function(func["va"], 3, 5)
        assert result == 8, f"Expected 8, got {result}"
    
    def test_add_negative_numbers(self):
        """add(-3, 5) = 2"""
        func = self.test_case.find_function_by_name("add")
        result = self.test_case.run_function(func["va"], -3, 5)
        assert result == 2, f"Expected 2, got {result}"
    
    def test_add_zero(self):
        """add(0, 0) = 0"""
        func = self.test_case.find_function_by_name("add")
        result = self.test_case.run_function(func["va"], 0, 0)
        assert result == 0, f"Expected 0, got {result}"
    
    def test_add_large_numbers(self):
        """add(1000000, 2000000) = 3000000"""
        func = self.test_case.find_function_by_name("add")
        result = self.test_case.run_function(func["va"], 1000000, 2000000)
        assert result == 3000000, f"Expected 3000000, got {result}"


class TestSubFunction:
    """测试 sub(int a, int b) 函数"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        cls.test_case = EmulatorTestCase(program_dir, "add")
        
        if not cls.test_case.compile():
            raise RuntimeError("Compilation failed")
        
        cls.tmpdir = tempfile.TemporaryDirectory()
        if not cls.test_case.export_db(cls.tmpdir.name):
            cls.tmpdir.cleanup()
            raise RuntimeError("Export failed")
        
        cls.test_case.create_emulator()
    
    @classmethod
    def teardown_class(cls):
        if hasattr(cls, 'test_case'):
            cls.test_case.cleanup()
        if hasattr(cls, 'tmpdir'):
            cls.tmpdir.cleanup()
    
    def test_sub_positive(self):
        """sub(10, 3) = 7"""
        func = self.test_case.find_function_by_name("sub")
        assert func is not None, "Function 'sub' not found"
        
        result = self.test_case.run_function(func["va"], 10, 3)
        assert result == 7, f"Expected 7, got {result}"
    
    def test_sub_negative_result(self):
        """sub(3, 10) = -7"""
        func = self.test_case.find_function_by_name("sub")
        result = self.test_case.run_function(func["va"], 3, 10)
        assert result == -7, f"Expected -7, got {result}"


class TestMulFunction:
    """测试 mul(int a, int b) 函数"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        cls.test_case = EmulatorTestCase(program_dir, "add")
        
        if not cls.test_case.compile():
            raise RuntimeError("Compilation failed")
        
        cls.tmpdir = tempfile.TemporaryDirectory()
        if not cls.test_case.export_db(cls.tmpdir.name):
            cls.tmpdir.cleanup()
            raise RuntimeError("Export failed")
        
        cls.test_case.create_emulator()
    
    @classmethod
    def teardown_class(cls):
        if hasattr(cls, 'test_case'):
            cls.test_case.cleanup()
        if hasattr(cls, 'tmpdir'):
            cls.tmpdir.cleanup()
    
    def test_mul_positive(self):
        """mul(4, 7) = 28"""
        func = self.test_case.find_function_by_name("mul")
        assert func is not None, "Function 'mul' not found"
        
        result = self.test_case.run_function(func["va"], 4, 7)
        assert result == 28, f"Expected 28, got {result}"
    
    def test_mul_zero(self):
        """mul(100, 0) = 0"""
        func = self.test_case.find_function_by_name("mul")
        result = self.test_case.run_function(func["va"], 100, 0)
        assert result == 0, f"Expected 0, got {result}"
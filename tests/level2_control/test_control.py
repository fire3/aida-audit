import os
import sys
import tempfile

test_support_dir = os.path.join(os.path.dirname(__file__), "..", "test_support")
backend_dir = os.path.join(os.path.dirname(__file__), "..", "backend", "aida_cli")

for p in [test_support_dir, backend_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from test_support import EmulatorTestCase


class TestMaxFunction:
    """测试 max(int a, int b) 函数"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        
        cls.test_case = EmulatorTestCase(program_dir, "control")
        
        if not cls.test_case.compile():
            raise RuntimeError("Compilation failed")
        
        cls.tmpdir = tempfile.TemporaryDirectory()
        if not cls.test_case.export_db(cls.tmpdir.name):
            cls.tmpdir.cleanup()
            raise RuntimeError("Export failed")
        
        # 使用更大的栈空间用于递归测试
        cls.test_case.create_emulator(stack_size=0x200000)
    
    @classmethod
    def teardown_class(cls):
        if hasattr(cls, 'test_case'):
            cls.test_case.cleanup()
        if hasattr(cls, 'tmpdir'):
            cls.tmpdir.cleanup()
    
    def test_max_first_larger(self):
        """max(10, 5) = 10"""
        func = self.test_case.find_function_by_name("max")
        assert func is not None, "Function 'max' not found"
        
        result = self.test_case.run_function(func["va"], 10, 5)
        assert result == 10, f"Expected 10, got {result}"
    
    def test_max_second_larger(self):
        """max(3, 8) = 8"""
        func = self.test_case.find_function_by_name("max")
        result = self.test_case.run_function(func["va"], 3, 8)
        assert result == 8, f"Expected 8, got {result}"
    
    def test_max_equal(self):
        """max(5, 5) = 5"""
        func = self.test_case.find_function_by_name("max")
        result = self.test_case.run_function(func["va"], 5, 5)
        assert result == 5, f"Expected 5, got {result}"
    
    def test_max_negative(self):
        """max(-3, -8) = -3"""
        func = self.test_case.find_function_by_name("max")
        result = self.test_case.run_function(func["va"], -3, -8)
        assert result == -3, f"Expected -3, got {result}"


class TestFactorialFunction:
    """测试 factorial(int n) 函数 (递归)"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        cls.test_case = EmulatorTestCase(program_dir, "control")
        
        if not cls.test_case.compile():
            raise RuntimeError("Compilation failed")
        
        cls.tmpdir = tempfile.TemporaryDirectory()
        if not cls.test_case.export_db(cls.tmpdir.name):
            cls.tmpdir.cleanup()
            raise RuntimeError("Export failed")
        
        # 递归需要更大的栈
        cls.test_case.create_emulator(stack_size=0x400000)
    
    @classmethod
    def teardown_class(cls):
        if hasattr(cls, 'test_case'):
            cls.test_case.cleanup()
        if hasattr(cls, 'tmpdir'):
            cls.tmpdir.cleanup()
    
    def test_factorial_0(self):
        """factorial(0) = 1"""
        func = self.test_case.find_function_by_name("factorial")
        assert func is not None, "Function 'factorial' not found"
        
        result = self.test_case.run_function(func["va"], 0)
        assert result == 1, f"Expected 1, got {result}"
    
    def test_factorial_1(self):
        """factorial(1) = 1"""
        func = self.test_case.find_function_by_name("factorial")
        result = self.test_case.run_function(func["va"], 1)
        assert result == 1, f"Expected 1, got {result}"
    
    def test_factorial_5(self):
        """factorial(5) = 120"""
        func = self.test_case.find_function_by_name("factorial")
        result = self.test_case.run_function(func["va"], 5)
        assert result == 120, f"Expected 120, got {result}"
    
    def test_factorial_10(self):
        """factorial(10) = 3628800"""
        func = self.test_case.find_function_by_name("factorial")
        result = self.test_case.run_function(func["va"], 10)
        assert result == 3628800, f"Expected 3628800, got {result}"


class TestAbsFunction:
    """测试 abs_val(int a) 函数"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        cls.test_case = EmulatorTestCase(program_dir, "control")
        
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
    
    def test_abs_positive(self):
        """abs_val(5) = 5"""
        func = self.test_case.find_function_by_name("abs_val")
        assert func is not None, "Function 'abs_val' not found"
        
        result = self.test_case.run_function(func["va"], 5)
        assert result == 5, f"Expected 5, got {result}"
    
    def test_abs_negative(self):
        """abs_val(-5) = 5"""
        func = self.test_case.find_function_by_name("abs_val")
        result = self.test_case.run_function(func["va"], -5)
        assert result == 5, f"Expected 5, got {result}"
    
    def test_abs_zero(self):
        """abs_val(0) = 0"""
        func = self.test_case.find_function_by_name("abs_val")
        result = self.test_case.run_function(func["va"], 0)
        assert result == 0, f"Expected 0, got {result}"
import os
import sys
import tempfile

test_support_dir = os.path.join(os.path.dirname(__file__), "..", "test_support")
backend_dir = os.path.join(os.path.dirname(__file__), "..", "backend", "aida_cli")

for p in [test_support_dir, backend_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from test_support import EmulatorTestCase


class TestSumArrayFunction:
    """测试 sum_array(int* arr, int len) 函数"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        
        cls.test_case = EmulatorTestCase(program_dir, "full")
        
        if not cls.test_case.compile():
            raise RuntimeError("Compilation failed")
        
        cls.tmpdir = tempfile.TemporaryDirectory()
        if not cls.test_case.export_db(cls.tmpdir.name):
            cls.tmpdir.cleanup()
            raise RuntimeError("Export failed")
        
        cls.test_case.create_emulator(stack_size=0x200000)
    
    @classmethod
    def teardown_class(cls):
        if hasattr(cls, 'test_case'):
            cls.test_case.cleanup()
        if hasattr(cls, 'tmpdir'):
            cls.tmpdir.cleanup()
    
    def test_sum_array_basic(self):
        """sum_array([1,2,3,4,5], 5) = 15"""
        func = self.test_case.find_function_by_name("sum_array")
        assert func is not None, "Function 'sum_array' not found"
        
        arr = [1, 2, 3, 4, 5]
        arr_va = 0x600000
        for i, val in enumerate(arr):
            self.test_case.emu.mem.write_u32(arr_va + i * 4, val)
        
        result = self.test_case.run_function(func["va"], arr_va, len(arr))
        assert result == 15, f"Expected 15, got {result}"
    
    def test_sum_array_empty(self):
        """sum_array([], 0) = 0"""
        func = self.test_case.find_function_by_name("sum_array")
        result = self.test_case.run_function(func["va"], 0x600000, 0)
        assert result == 0, f"Expected 0, got {result}"
    
    def test_sum_array_single(self):
        """sum_array([42], 1) = 42"""
        func = self.test_case.find_function_by_name("sum_array")
        arr_va = 0x600100
        self.test_case.emu.mem.write_u32(arr_va, 42)
        
        result = self.test_case.run_function(func["va"], arr_va, 1)
        assert result == 42, f"Expected 42, got {result}"


class TestStrLenFunction:
    """测试 str_len(const char* s) 函数"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        cls.test_case = EmulatorTestCase(program_dir, "full")
        
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
    
    def test_str_len_hello(self):
        """str_len("hello") = 5"""
        func = self.test_case.find_function_by_name("str_len")
        assert func is not None, "Function 'str_len' not found"
        
        str_va = 0x600200
        test_str = b"hello\x00"
        self.test_case.emu.mem.write(str_va, test_str)
        
        result = self.test_case.run_function(func["va"], str_va)
        assert result == 5, f"Expected 5, got {result}"
    
    def test_str_len_empty(self):
        """str_len("") = 0"""
        func = self.test_case.find_function_by_name("str_len")
        
        str_va = 0x600300
        self.test_case.emu.mem.write(str_va, b"\x00")
        
        result = self.test_case.run_function(func["va"], str_va)
        assert result == 0, f"Expected 0, got {result}"
    
    def test_str_len_world(self):
        """str_len("world") = 5"""
        func = self.test_case.find_function_by_name("str_len")
        
        str_va = 0x600400
        test_str = b"world\x00"
        self.test_case.emu.mem.write(str_va, test_str)
        
        result = self.test_case.run_function(func["va"], str_va)
        assert result == 5, f"Expected 5, got {result}"


class TestFindMaxFunction:
    """测试 find_max(int* arr, int len) 函数"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        cls.test_case = EmulatorTestCase(program_dir, "full")
        
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
    
    def test_find_max_basic(self):
        """find_max([1,2,3,4,5], 5) = 5"""
        func = self.test_case.find_function_by_name("find_max")
        assert func is not None, "Function 'find_max' not found"
        
        arr = [1, 2, 3, 4, 5]
        arr_va = 0x600500
        for i, val in enumerate(arr):
            self.test_case.emu.mem.write_u32(arr_va + i * 4, val)
        
        result = self.test_case.run_function(func["va"], arr_va, len(arr))
        assert result == 5, f"Expected 5, got {result}"
    
    def test_find_max_negative(self):
        """find_max([-5,-2,-10,-1], 4) = -1"""
        func = self.test_case.find_function_by_name("find_max")
        
        arr = [-5, -2, -10, -1]
        arr_va = 0x600600
        for i, val in enumerate(arr):
            self.test_case.emu.mem.write_u32(arr_va + i * 4, val)
        
        result = self.test_case.run_function(func["va"], arr_va, len(arr))
        assert result == -1, f"Expected -1, got {result}"
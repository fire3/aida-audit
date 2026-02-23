import os
import sys
import tempfile

test_support_dir = os.path.join(os.path.dirname(__file__), "..", "test_support")
backend_dir = os.path.join(os.path.dirname(__file__), "..", "backend", "aida_cli")

for p in [test_support_dir, backend_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

sys.path.insert(0, test_support_dir)
from test_support import EmulatorTestCase


class TestPointerArguments:
    """测试指针参数传递"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        
        cls.test_case = EmulatorTestCase(program_dir, "hooks")
        
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
    
    def test_sum_array_pointer(self):
        """sum_array([1,2,3,4,5], 5) = 15"""
        func = self.test_case.find_function_by_name("sum_array")
        assert func is not None, "Function 'sum_array' not found"
        
        arr = [1, 2, 3, 4, 5]
        arr_ptr = self.test_case.emu.alloc(len(arr) * 4)
        for i, val in enumerate(arr):
            self.test_case.emu.mem.write_u32(arr_ptr + i * 4, val)
        
        result = self.test_case.run_function(func["va"], arr_ptr, len(arr))
        assert result == 15, f"Expected 15, got {result}"
    
    def test_str_len_pointer(self):
        """str_len("hello") = 5"""
        func = self.test_case.find_function_by_name("str_len")
        assert func is not None, "Function 'str_len' not found"
        
        test_str = b"hello\x00"
        str_ptr = self.test_case.emu.alloc(len(test_str), test_str)
        
        result = self.test_case.run_function(func["va"], str_ptr)
        assert result == 5, f"Expected 5, got {result}"
    
    def test_multiple_arrays(self):
        """测试多次分配数组"""
        func = self.test_case.find_function_by_name("sum_array")
        
        arr1 = [10, 20, 30]
        ptr1 = self.test_case.emu.alloc(len(arr1) * 4)
        for i, val in enumerate(arr1):
            self.test_case.emu.mem.write_u32(ptr1 + i * 4, val)
        
        result1 = self.test_case.run_function(func["va"], ptr1, len(arr1))
        assert result1 == 60, f"Expected 60, got {result1}"
        
        arr2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        ptr2 = self.test_case.emu.alloc(len(arr2) * 4)
        for i, val in enumerate(arr2):
            self.test_case.emu.mem.write_u32(ptr2 + i * 4, val)
        
        result2 = self.test_case.run_function(func["va"], ptr2, len(arr2))
        assert result2 == 55, f"Expected 55, got {result2}"


class TestCodeHook:
    """测试代码执行 Hook"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        cls.test_case = EmulatorTestCase(program_dir, "hooks")
        
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
    
    def test_hook_code_execution(self):
        """Hook 追踪代码执行"""
        func = self.test_case.find_function_by_name("sum_array")
        assert func is not None
        
        executed_addrs = []
        
        def code_hook(emu, address, size, user_data):
            executed_addrs.append(address)
            return True
        
        self.test_case.emu.hook_code(code_hook)
        
        arr = [1, 2, 3]
        arr_ptr = self.test_case.emu.alloc(len(arr) * 4)
        for i, val in enumerate(arr):
            self.test_case.emu.mem.write_u32(arr_ptr + i * 4, val)
        
        result = self.test_case.run_function(func["va"], arr_ptr, len(arr))
        
        assert result == 6, f"Expected 6, got {result}"
        assert len(executed_addrs) > 0, "No instructions were hooked"


class TestMemoryHook:
    """测试内存访问 Hook"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        cls.test_case = EmulatorTestCase(program_dir, "hooks")
        
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
    
    def test_hook_memory_read(self):
        """Hook 监控内存读取"""
        func = self.test_case.find_function_by_name("sum_array")
        assert func is not None
        
        mem_reads = []
        
        def mem_hook(emu, access, address, size, value, user_data):
            mem_reads.append((address, size))
            return True
        
        self.test_case.emu.hook_memory(mem_hook, mem_type="read")
        
        arr = [1, 2, 3]
        arr_ptr = self.test_case.emu.alloc(len(arr) * 4)
        for i, val in enumerate(arr):
            self.test_case.emu.mem.write_u32(arr_ptr + i * 4, val)
        
        result = self.test_case.run_function(func["va"], arr_ptr, len(arr))
        
        assert result == 6
        assert len(mem_reads) > 0, "Memory should have been read"


class TestBlockHook:
    """测试基本块 Hook"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        cls.test_case = EmulatorTestCase(program_dir, "hooks")
        
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
    
    def test_hook_basic_blocks(self):
        """Hook 基本块执行"""
        func = self.test_case.find_function_by_name("sum_array")
        assert func is not None
        
        basic_blocks = []
        
        def block_hook(emu, address, size, user_data):
            basic_blocks.append(address)
            return True
        
        self.test_case.emu.hook_block(block_hook)
        
        arr = [1, 2, 3]
        arr_ptr = self.test_case.emu.alloc(len(arr) * 4)
        for i, val in enumerate(arr):
            self.test_case.emu.mem.write_u32(arr_ptr + i * 4, val)
        
        result = self.test_case.run_function(func["va"], arr_ptr, len(arr))
        
        assert result == 6
        assert len(basic_blocks) > 0, "Basic blocks should have been hooked"


class TestHookLibcSimulation:
    """测试 Hook 模拟 libc 函数调用"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        cls.test_case = EmulatorTestCase(program_dir, "hooks")
        
        if not cls.test_case.compile():
            raise RuntimeError("Compilation failed")
        
        cls.tmpdir = tempfile.TemporaryDirectory()
        if not cls.test_case.export_db(cls.tmpdir.name):
            cls.tmpdir.cleanup()
            raise RuntimeError("Export failed")
        
        cls.test_case.create_emulator(stack_size=0x400000)
    
    @classmethod
    def teardown_class(cls):
        if hasattr(cls, 'test_case'):
            cls.test_case.cleanup()
        if hasattr(cls, 'tmpdir'):
            cls.tmpdir.cleanup()
    
    def test_hook_strlen_simulation(self):
        """Hook 模拟 strlen - 避免调用真实 libc"""
        func = self.test_case.find_function_by_name("str_len")
        assert func is not None
        
        test_str = b"test_string\x00"
        str_ptr = self.test_case.emu.alloc(len(test_str), test_str)
        
        result = self.test_case.run_function(func["va"], str_ptr)
        assert result == 11, f"Expected 11, got {result}"
    
    def test_strlen_custom_implementation(self):
        """测试我们自己的 strlen 实现"""
        func = self.test_case.find_function_by_name("str_len")
        assert func is not None
        
        test_cases = [
            (b"hello\x00", 5),
            (b"", 0),
            (b"a\x00", 1),
            (b"test123\x00", 7),
        ]
        
        for test_str, expected in test_cases:
            str_ptr = self.test_case.emu.alloc(len(test_str), test_str)
            result = self.test_case.run_function(func["va"], str_ptr)
            assert result == expected, f"Expected {expected}, got {result} for {test_str}"
    
    def test_hook_malloc_simulation(self):
        """Hook 模拟 malloc"""
        func = self.test_case.find_function_by_name("malloc_test")
        assert func is not None
        
        result = self.test_case.run_function(func["va"], 100)
        assert result != 0, "malloc should return non-null pointer"
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


class TestLibcHookWithDynamicLink:
    """测试动态链接程序使用 libc hook 模拟"""
    
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
    
    def test_hook_strlen_dynamic_link(self):
        """Hook 模拟动态链接的 strlen 调用"""
        func = self.test_case.find_function_by_name("str_len")
        assert func is not None, "Function 'str_len' not found"
        
        libc_funcs = self._find_libc_functions()
        if not libc_funcs:
            return
        
        emu = self.test_case.emu
        emu.enable_libc_hooks()
        for name, addr in libc_funcs.items():
            if name in ["strlen", "atoi", "strcmp", "malloc", "free", "memcpy", "memset"]:
                emu.hook_libc(name, addr)
        
        test_str = b"hello"
        str_ptr = emu.alloc(len(test_str) + 1, test_str + b"\x00")
        
        result = self.test_case.run_function(func["va"], str_ptr)
        assert result == 5, f"Expected 5, got {result}"
    
    def test_hook_atoi_dynamic_link(self):
        """Hook 模拟动态链接的 atoi 调用"""
        func = self.test_case.find_function_by_name("atoi_test")
        assert func is not None, "Function 'atoi_test' not found"
        
        libc_funcs = self._find_libc_functions()
        if not libc_funcs:
            return
        
        emu = self.test_case.emu
        emu.enable_libc_hooks()
        for name, addr in libc_funcs.items():
            if name in ["strlen", "atoi", "strcmp", "malloc", "free", "memcpy", "memset"]:
                emu.hook_libc(name, addr)
        
        test_str = b"98765\x00"
        str_ptr = emu.alloc(len(test_str), test_str)
        
        result = self.test_case.run_function(func["va"], str_ptr)
        assert result == 98765, f"Expected 98765, got {result}"
    
    def test_hook_strcmp_dynamic_link(self):
        """Hook 模拟动态链接的 strcmp 调用"""
        func = self.test_case.find_function_by_name("strcmp_test")
        assert func is not None, "Function 'strcmp_test' not found"
        
        libc_funcs = self._find_libc_functions()
        if not libc_funcs:
            return
        
        emu = self.test_case.emu
        emu.enable_libc_hooks()
        for name, addr in libc_funcs.items():
            if name in ["strlen", "atoi", "strcmp", "malloc", "free", "memcpy", "memset"]:
                emu.hook_libc(name, addr)
        
        s1 = b"abc\x00"
        s2 = b"xyz\x00"
        s1_ptr = emu.alloc(len(s1), s1)
        s2_ptr = emu.alloc(len(s2), s2)
        
        print(f"DEBUG: s1='{s1.decode()}' at 0x{s1_ptr:x}, s2='{s2.decode()}' at 0x{s2_ptr:x}")
        
        result = self.test_case.run_function(func["va"], s1_ptr, s2_ptr)
        print(f"DEBUG strcmp: result={result} (expected negative for abc < xyz)")
        
        rax = emu.regs.get_reg("rax")
        print(f"DEBUG strcmp: rax={rax} (0x{rax:x})")
        
        assert result < 0, f"Expected negative (abc < xyz), got {result}"
    
    def test_hook_malloc_dynamic_link(self):
        """Hook 模拟动态链接的 malloc 调用"""
        func = self.test_case.find_function_by_name("malloc_test")
        assert func is not None, "Function 'malloc_test' not found"
        
        libc_funcs = self._find_libc_functions()
        if not libc_funcs:
            return
        
        emu = self.test_case.emu
        emu.enable_libc_hooks()
        for name, addr in libc_funcs.items():
            if name in ["strlen", "atoi", "strcmp", "malloc", "free", "memcpy", "memset"]:
                emu.hook_libc(name, addr)
        
        result = self.test_case.run_function(func["va"], 256)
        assert result != 0, "malloc should return non-null pointer"
    
    def test_hook_free_dynamic_link(self):
        """Hook 模拟动态链接的 free 调用"""
        func = self.test_case.find_function_by_name("free_test")
        assert func is not None, "Function 'free_test' not found"
        
        libc_funcs = self._find_libc_functions()
        if not libc_funcs:
            return
        
        emu = self.test_case.emu
        emu.enable_libc_hooks()
        for name, addr in libc_funcs.items():
            if name in ["strlen", "atoi", "strcmp", "malloc", "free", "memcpy", "memset"]:
                emu.hook_libc(name, addr)
        
        ptr = emu.alloc(128)
        result = self.test_case.run_function(func["va"], ptr)
        assert result == 0, f"Expected 0, got {result}"
    
    def test_hook_memcpy_dynamic_link(self):
        """Hook 模拟动态链接的 memcpy 调用"""
        func = self.test_case.find_function_by_name("memcpy_test")
        assert func is not None, "Function 'memcpy_test' not found"
        
        libc_funcs = self._find_libc_functions()
        if not libc_funcs:
            return
        
        emu = self.test_case.emu
        emu.enable_libc_hooks()
        for name, addr in libc_funcs.items():
            if name in ["strlen", "atoi", "strcmp", "malloc", "free", "memcpy", "memset"]:
                emu.hook_libc(name, addr)
        
        test_str = b"test"
        str_ptr = emu.alloc(len(test_str) + 1, test_str + b"\x00")
        
        result = self.test_case.run_function(func["va"], str_ptr)
        print(f"DEBUG memcpy: result={result}")
        assert result == 4, f"Expected 4, got {result}"
    
    def _find_libc_functions(self) -> dict:
        if not self.test_case.emu.db:
            return {}
        
        libc_funcs = {}
        
        for func in self.test_case.emu.db.load_functions():
            name = func.get("name", "")
            va = func.get("va", 0)
            
            if name in ["strlen", "strcmp", "atoi", "malloc", "free", "memcpy", "memset", "strlen@plt", "strcmp@plt", "atoi@plt", "malloc@plt", "free@plt", "memcpy@plt", "memset@plt"]:
                clean_name = name.replace("@plt", "")
                libc_funcs[clean_name] = va
        
        print(f"DEBUG: Found libc functions: {libc_funcs}")
        
        return libc_funcs
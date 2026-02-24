import os
import sys
import tempfile
import pytest

test_support_dir = os.path.join(os.path.dirname(__file__), "..", "test_support")
backend_dir = os.path.join(os.path.dirname(__file__), "..", "backend", "aida_cli")

for p in [test_support_dir, backend_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

sys.path.insert(0, test_support_dir)
from test_support import EmulatorTestCase


class TestSubHook:
    """测试子函数 Hook"""
    
    @classmethod
    def setup_class(cls):
        program_dir = os.path.join(os.path.dirname(__file__), "program")
        cls.test_case = EmulatorTestCase(program_dir, "sub_hook")
        
        if not cls.test_case.compile():
            # If compile failed, maybe it was already compiled? Or use the one we just made.
            pass
            
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
    
    def test_hook_sub_function(self):
        """测试 hook 子函数调用"""
        func = self.test_case.find_function_by_name("main")
        sub_func = self.test_case.find_function_by_name("sub_func")
        if sub_func is None:
             sub_func = self.test_case.find_function_by_name("_sub_func")
        
        assert func is not None, "main function not found"
        assert sub_func is not None, "sub_func function not found"
        
        hooked_args = []
        
        def sub_func_hook(emu, address, size, user_data):
            # Only interested if address matches sub_func entry
            if address == sub_func["va"]:
                # Read arguments
                # Assuming standard calling convention detected by emulator
                # or default for arch.
                # Since we compile with -O0, args should be in regs or stack.
                # Emulator.detect_convention should handle it.
                
                arg1 = emu.regs.get_arg(0)
                arg2 = emu.regs.get_arg(1)
                hooked_args.append((arg1, arg2))
            return True
            
        # Register code hook
        self.test_case.emu.hook_code(sub_func_hook)
        
        # Run main
        result = self.test_case.run_function(func["va"])
        
        assert len(hooked_args) == 1, f"Expected 1 hook call, got {len(hooked_args)}"
        assert hooked_args[0] == (10, 20), f"Expected args (10, 20), got {hooked_args[0]}"
        assert result == 200, f"Expected result 200, got {result}"

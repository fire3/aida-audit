from typing import Optional, Callable, Any, Dict, List
import struct

try:
    import unicorn
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


class SubFuncHook:
    """
    Sub-function hook - 用于hook内部子函数
    
    当模拟函数A时，如果A调用了复杂的子函数B，可以用这个hook拦截B的调用，
    用自定义handler替代执行，从而专注于A的核心逻辑。
    
    用法示例:
        # 假设要模拟函数 at 0x401000，但该函数调用了复杂的子函数 complex_sub
        # 我们想用简单的模拟替代 complex_sub
        
        def complex_sub_handler(emu, func_va, call_site, ret_addr):
            # 读取参数
            arg0 = emu.get_arg(0)
            arg1 = emu.get_arg(1)
            
            # 自定义逻辑 - 比如直接返回固定值
            emu.set_ret_value(0x12345)
            
            # 返回 True 表示已处理，Emulator会自动跳转到返回地址
            return True
        
        # 注册hook
        emu.hook_subfunction(0x401100, complex_sub_handler)
        
        # 运行模拟
        emu.run(start=0x401000)
    """
    
    TRAP_INSN = {
        "x86_64": b"\xcc",
        "x86_32": b"\xcc",
        "arm": b"\xef\x00\x00\x01",
        "arm64": b"\xd4\x00\x00\x00",
    }
    
    RET_ADDR_OFFSET = {
        "x86_64": 0,
        "x86_32": 0,
        "arm": 0,
        "arm64": 0,
    }
    
    def __init__(self, emulator, func_va: int, callback: Callable, 
                 user_data: Any = None, preserve_return: bool = True):
        """
        Args:
            emulator: AidaEmulator实例
            func_va: 要hook的子函数的虚拟地址
            callback: 回调函数，签名为:
                callback(emu, func_va, call_site, ret_addr, user_data) -> bool
                - emu: AidaEmulator实例
                - func_va: 被hook的函数地址
                - call_site: 调用该函数的指令地址
                - ret_addr: 返回地址
                - user_data: 用户数据
                - 返回 True 表示已处理，Emulator会自动设置返回值并跳转到ret_addr
                - 返回 False 表示未处理，继续正常执行
            user_data: 传递给回调的用户数据
            preserve_return: 是否自动处理返回地址（弹出栈上的返回地址并跳转）
        """
        self.emulator = emulator
        self.func_va = func_va
        self.callback = callback
        self.user_data = user_data
        self.preserve_return = preserve_return
        self.enabled = False
        self._backup_data: Optional[bytes] = None
        self._trap_insn: bytes = b"\xcc"
        
        self._setup_trap()
    
    def _setup_trap(self):
        """设置trap指令"""
        arch = self.emulator.arch
        if arch == "arm" and self.emulator.mode == unicorn.UC_MODE_THUMB:
            self._trap_insn = b"\xde\xad"
        else:
            self._trap_insn = self.TRAP_INSN.get(arch, b"\xcc")
    
    def _get_func_name(self) -> str:
        """获取函数名"""
        func = self.emulator.get_function(self.func_va)
        if func:
            return func.get("name", f"sub_{self.func_va:x}")
        return f"sub_{self.func_va:x}"
    
    def enable(self) -> bool:
        """启用hook - 替换函数入口为trap指令"""
        if self.enabled:
            return True
        
        try:
            # 备份原始指令
            self._backup_data = self.emulator.read_memory(self.func_va, 16)
            if not self._backup_data:
                print(f"[SubFuncHook] Failed to read memory at 0x{self.func_va:x}")
                return False
            
            # 写入trap指令
            trap_16 = self._trap_insn * (16 // len(self._trap_insn))
            self.emulator.write_memory(self.func_va, trap_16)
            
            self.enabled = True
            return True
        except Exception as e:
            print(f"[SubFuncHook] Failed to enable hook: {e}")
            return False
    
    def disable(self) -> bool:
        """禁用hook - 恢复原始指令"""
        if not self.enabled:
            return True
        
        try:
            if self._backup_data:
                self.emulator.write_memory(self.func_va, self._backup_data)
            self.enabled = False
            return True
        except Exception as e:
            print(f"[SubFuncHook] Failed to disable hook: {e}")
            return False
    
    def execute_handler(self, call_site: int, ret_addr: int) -> bool:
        """
        执行handler回调
        
        Args:
            call_site: 调用该函数的指令地址
            ret_addr: 返回地址
            
        Returns:
            True 如果handler已处理（设置了返回值并准备返回）
            False 如果handler未处理
        """
        if not self.callback:
            return False
        
        try:
            result = self.callback(
                self.emulator, 
                self.func_va, 
                call_site, 
                ret_addr,
                self.user_data
            )
            return result if result is not None else False
        except Exception as e:
            print(f"[SubFuncHook] Handler error for {self._get_func_name()}: {e}")
            return False
    
    def handle_trap(self, call_site: int, ret_addr: int) -> bool:
        """
        处理trap触发 - 执行handler并返回
        
        Args:
            call_site: 触发trap的位置（即函数入口）
            ret_addr: 返回地址
            
        Returns:
            True 如果成功处理
        """
        # 检测调用约定，以便handler可以正确读取参数
        self.emulator.detect_convention(self.func_va)
        
        # 执行用户的handler
        handled = self.execute_handler(call_site, ret_addr)
        
        if handled and self.preserve_return:
            # 跳过返回地址
            ptr_size = 8 if self.emulator.arch in ("x86_64", "arm64") else 4
            sp = self.emulator.get_sp()
            self.emulator.set_sp(sp + ptr_size)
            
            # 跳转到返回地址
            self.emulator.set_pc(ret_addr)
        
        return handled


class SubFuncHookManager:
    """
    子函数hook管理器
    
    管理多个子函数的hook，支持:
    - 按地址hook函数
    - 按函数名hook函数（需要数据库）
    - 批量enable/disable
    """
    
    def __init__(self, emulator):
        self.emulator = emulator
        self._hooks: Dict[int, SubFuncHook] = {}  # func_va -> SubFuncHook
        self._name_to_va: Dict[str, int] = {}  # function_name -> func_va
        self._code_handle = None
        self._enabled = False
        self._setup = False
    
    def _ensure_setup(self):
        """确保已设置code hook"""
        if self._setup:
            return
        
        def code_callback(uc, address, size, user_data):
            return self._handle_code(address)
        
        self._code_handle = self.emulator.hooks.add_code_hook(code_callback)
        self._setup = True
    
    def register(self, func_va: int, callback: Callable, 
                 user_data: Any = None, preserve_return: bool = True,
                 auto_enable: bool = True) -> Optional[SubFuncHook]:
        """
        注册一个子函数hook
        
        Args:
            func_va: 函数地址
            callback: 处理回调
            user_data: 用户数据
            preserve_return: 是否自动处理返回
            auto_enable: 是否立即启用
            
        Returns:
            SubFuncHook实例
        """
        hook = SubFuncHook(
            self.emulator, 
            func_va, 
            callback,
            user_data,
            preserve_return
        )
        
        self._hooks[func_va] = hook
        
        # 尝试获取函数名
        func = self.emulator.get_function(func_va)
        if func:
            self._name_to_va[func.get("name", "")] = func_va
            clean_name = func.get("name", "").lstrip(".").replace("@plt", "")
            self._name_to_va[clean_name] = func_va
        
        if auto_enable:
            self._ensure_setup()
            hook.enable()
            self._enabled = True
        
        return hook
    
    def register_by_name(self, func_name: str, callback: Callable,
                        user_data: Any = None, 
                        preserve_return: bool = True) -> Optional[SubFuncHook]:
        """
        按函数名注册hook（需要数据库）
        
        Args:
            func_name: 函数名
            其他参数同register
            
        Returns:
            SubFuncHook实例
        """
        if not self.emulator.db:
            print(f"[SubFuncHookManager] No database available for name lookup")
            return None
        
        # 查找函数
        funcs = self.emulator.db.load_functions()
        target_func = None
        for func in funcs:
            name = func.get("name", "")
            if name == func_name or name.lstrip(".").replace("@plt", "") == func_name:
                target_func = func
                break
        
        if not target_func:
            print(f"[SubFuncHookManager] Function not found: {func_name}")
            return None
        
        func_va = target_func.get("start_va")
        if not func_va:
            print(f"[SubFuncHookManager] Function has no address: {func_name}")
            return None
        
        return self.register(func_va, callback, user_data, preserve_return)
    
    def unregister(self, func_va: int) -> bool:
        """
        注销hook
        
        Args:
            func_va: 函数地址
            
        Returns:
            是否成功
        """
        hook = self._hooks.get(func_va)
        if not hook:
            return False
        
        hook.disable()
        del self._hooks[func_va]
        return True
    
    def enable(self, func_va: int) -> bool:
        """启用指定hook"""
        hook = self._hooks.get(func_va)
        if hook:
            self._ensure_setup()
            return hook.enable()
        return False
    
    def disable(self, func_va: int) -> bool:
        """禁用指定hook"""
        hook = self._hooks.get(func_va)
        if hook:
            return hook.disable()
        return False
    
    def enable_all(self):
        """启用所有hook"""
        self._ensure_setup()
        for hook in self._hooks.values():
            hook.enable()
        self._enabled = True
    
    def disable_all(self):
        """禁用所有hook"""
        for hook in self._hooks.values():
            hook.disable()
        self._enabled = False
    
    def _handle_code(self, address: int) -> bool:
        """
        处理code hook回调
        
        检查是否触发了某个sub-function hook的trap
        """
        # 检查地址是否匹配任何hook
        hooked_func = None
        for func_va, hook in self._hooks.items():
            # 直接匹配或int3后的PC-1
            if address == func_va or address == func_va + 1:
                hooked_func = hook
                break
        
        if not hooked_func:
            return True  # 没有hook，传递
        
        if not hooked_func.enabled:
            return True
        
        # 获取返回地址
        sp = self.emulator.get_sp()
        ptr_size = 8 if self.emulator.arch in ("x86_64", "arm64") else 4
        ret_addr = self.emulator.read_ptr(sp, ptr_size)
        
        if ret_addr is None:
            print(f"[SubFuncHookManager] Failed to read return address at SP=0x{sp:x}")
            return True
        
        call_site = hooked_func.func_va
        
        # 处理hook
        handled = hooked_func.handle_trap(call_site, ret_addr)
        
        # 返回False表示已处理（不再执行原函数）
        return not handled
    
    def get_hook(self, func_va: int) -> Optional[SubFuncHook]:
        """获取指定地址的hook"""
        return self._hooks.get(func_va)
    
    def get_hooks(self) -> Dict[int, SubFuncHook]:
        """获取所有hook"""
        return dict(self._hooks)
    
    def clear(self):
        """清除所有hook"""
        self.disable_all()
        self._hooks.clear()
        self._name_to_va.clear()

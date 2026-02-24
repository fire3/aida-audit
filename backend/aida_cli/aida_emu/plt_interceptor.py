"""
PLT Interceptor - 使用软中断(int3/brk)拦截PLT外部函数调用
"""
from typing import Optional, Dict, Any, List, Callable
import struct

try:
    import unicorn
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


class PLTInterceptor:
    """PLT函数拦截器 - 使用软中断机制捕获外部函数调用"""

    # 各架构的软中断指令
    TRAP_INSN = {
        "x86_64": b"\xcc",           # int3
        "x86_32": b"\xcc",           # int3
        "arm": b"\xef\x00\x00\x01",  # svc 0 (ARM32) - note: may not trigger HOOK_INTR
        "arm64": b"\xd4\x00\x00\x00", # brk #0 (ARM64)
    }

    # 各架构返回地址相对于SP的偏移
    # call指令会将返回地址压栈，所以返回地址在 [sp] 位置
    RET_ADDR_OFFSET = {
        "x86_64": 0,
        "x86_32": 0,
        "arm": 0,
        "arm64": 0,
    }

    def __init__(self, emulator):
        self.emu = emulator
        self._plt_entries: Dict[int, str] = {}  # address -> function_name
        self._backup_data: Dict[int, bytes] = {}  # address -> original instructions
        self._trap_insn: bytes = b"\xcc"
        self._setup = False
        self._interrupt_handle = None
        self._code_handle = None
        self._plt_start: int = 0
        self._plt_end: int = 0

    def _get_trap_insn(self) -> bytes:
        """获取当前架构的软中断指令"""
        arch = self.emu.arch
        if arch == "arm" and self.emu.mode == unicorn.UC_MODE_THUMB:
            # Thumb模式下使用未定义指令
            return b"\xde\xad"
        return self.TRAP_INSN.get(arch, b"\xcc")

    def _supports_interrupt_hook(self) -> bool:
        """检查当前架构是否支持中断hook"""
        # ARM的SVC不会触发UC_HOOK_INTR，需要使用code hook
        return self.emu.arch not in ("arm", "arm64")

    def setup(self, db) -> bool:
        """初始化PLT拦截器"""
        if self._setup:
            return True

        self._trap_insn = self._get_trap_insn()

        # 获取所有PLT函数
        if not db:
            return False

        # 收集PLT段信息
        plt_start, plt_end = self._find_plt_segment(db)
        if plt_start is None:
            print("[PLTInterceptor] Could not find PLT segment")
            return False

        print(f"[PLTInterceptor] PLT segment: 0x{plt_start:x} - 0x{plt_end:x}")

        # 保存PLT范围供后续使用
        self._plt_start = plt_start
        self._plt_end = plt_end

        # 获取在PLT地址范围内的所有函数
        plt_funcs = self._get_plt_functions_in_range(db, plt_start, plt_end)

        if not plt_funcs:
            print("[PLTInterceptor] No PLT functions found in range")
            return False

        print(f"[PLTInterceptor] Found {len(plt_funcs)} PLT functions")

        # 替换PLT入口为软中断
        self._replace_plt_entries(plt_funcs, plt_start, plt_end)

        # 注册中断hook
        self._register_interrupt_hook()

        self._setup = True
        print(f"[PLTInterceptor] Setup complete: {len(self._plt_entries)} PLT entries intercepted")
        return True

    def _is_plt_function(self, name: str) -> bool:
        """判断是否为PLT函数"""
        # 方法1: 函数名以 @plt 结尾或以 . 开头
        if name.endswith("@plt") or name.startswith("."):
            return True
        # 方法2: 函数名是常见的libc/system函数（通过地址范围判断更准确）
        # 这里的函数名没有@plt后缀，需要通过后续的地址范围过滤
        return False

    def _is_plt_address(self, va: int) -> bool:
        """判断地址是否在PLT段范围内"""
        if not hasattr(self, '_plt_start') or not hasattr(self, '_plt_end'):
            return False
        return self._plt_start <= va < self._plt_end

    def _find_plt_segment(self, db) -> tuple:
        """查找PLT段的起止地址（可能多个段合并）"""
        segments = db.load_segments()
        plt_ranges = []  # 收集所有PLT相关段

        for seg in segments:
            name = seg.get("name", "")
            # 匹配各种PLT段名称：.plt, .plt.sec, .plt.got等
            if ".plt" in name and "shstrtab" not in name:
                plt_start = seg.get("start_va", 0)
                end_va = seg.get("end_va", 0)
                size = end_va - plt_start if end_va > plt_start else 0
                if size > 0:
                    plt_ranges.append((plt_start, plt_start + size))

        # 合并所有PLT范围
        if plt_ranges:
            plt_ranges.sort()
            # 合并重叠/相邻的范围
            merged = [plt_ranges[0]]
            for start, end in plt_ranges[1:]:
                if start <= merged[-1][1]:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], end))
                else:
                    merged.append((start, end))

            # 返回第一个范围作为主PLT段
            return merged[0]

        return None, None

    def _get_plt_functions_in_range(self, db, plt_start: int, plt_end: int) -> List[Dict]:
        """获取在PLT地址范围内的所有函数"""
        funcs = db.load_functions()
        plt_funcs = []
        for f in funcs:
            va = f.get("start_va", 0)
            if plt_start <= va < plt_end:
                plt_funcs.append(f)
        return plt_funcs

    def _replace_plt_entries(self, plt_funcs: List[Dict], plt_start: int, plt_end: int):
        """替换PLT入口为软中断"""
        # 注意：内存已经在_load_segments中映射为RWX，无需再修改权限

        # 备份并替换每个PLT函数
        for func in plt_funcs:
            va = func.get("start_va", 0)
            if va == 0:
                continue

            name = func.get("name", "")
            # 清理函数名
            clean_name = name.lstrip(".").replace("@plt", "")

            try:
                # 备份原始指令（至少16字节以覆盖最大PLT条目）
                original = self.emu.read_memory(va, 16)
                if original:
                    self._backup_data[va] = original

                # 写入软中断指令
                self.emu.write_memory(va, self._trap_insn)

                self._plt_entries[va] = clean_name
            except Exception as e:
                print(f"[PLTInterceptor] Failed to replace PLT entry at 0x{va:x}: {e}")

    def _register_interrupt_hook(self):
        """注册中断hook（x86/x64）或code hook（ARM）"""
        if self._supports_interrupt_hook():
            def interrupt_callback(uc, intno, user_data):
                return self._handle_interrupt(uc, intno)
            self._interrupt_handle = self.emu.hooks.add_interrupt_hook(interrupt_callback)
        else:
            self._register_code_hook()

    def _register_code_hook(self):
        """注册code hook用于ARM（因为SVC不触发中断hook）"""
        def code_callback(uc, address, size, user_data):
            return self._handle_code(address, size)

        self._code_handle = self.emu.hooks.add_code_hook(code_callback)

    def _handle_code(self, address: int, size: int) -> bool:
        """处理code hook（ARM PLT拦截）"""
        # 检查是否在PLT范围内
        if not self._is_plt_address(address):
            return True

        # 获取函数名
        func_name = self._plt_entries.get(address)
        if not func_name:
            return True

        # 获取返回地址 - 在ARM中，BL会将返回地址保存到LR寄存器
        lr = self.emu.regs.get_reg('lr')
        if lr is None or lr == 0:
            print(f"[PLTInterceptor] Failed to read LR at PC=0x{address:x}")
            return True

        ret_addr = lr
        sp = self.emu.get_sp()

        print(f"[PLTInterceptor] Intercepted: {func_name}() at PC=0x{address:x}, SP=0x{sp:x}, ret_addr=0x{ret_addr:x}")

        # 执行libc hook处理
        result = self._execute_libc_hook(func_name)

        # 设置返回值
        if result is not None:
            self.emu.regs.set_ret_value(result)
            self.emu._libc_intercepted = True

        # 跳转到返回地址
        self.emu.set_pc(ret_addr)

        return True

    def _handle_interrupt(self, uc, intno) -> bool:
        """处理软中断"""
        pc = self.emu.get_pc()

        # 检查是否在PLT范围内
        plt_addr = self._get_plt_address(pc)
        if plt_addr is None:
            print(f"[PLTInterceptor] Interrupt 0x{intno:x} at PC=0x{pc:x} - not PLT, passing through")
            return True  # 不是PLT中断，继续传播

        # 获取函数名
        func_name = self._plt_entries.get(plt_addr)
        if not func_name:
            print(f"[PLTInterceptor] Interrupt at PLT 0x{plt_addr:x} but no function name")
            return True

        # 获取返回地址
        # 注意：call指令将返回地址压入栈顶
        # 在call之后，SP指向返回地址（不是SP+8）
        sp = self.emu.get_sp()
        ret_addr = self.emu.read_ptr(sp)
        if ret_addr is None:
            print(f"[PLTInterceptor] Failed to read return address at SP=0x{sp:x}")
            return True

        print(f"[PLTInterceptor] Intercepted: {func_name}() at PC=0x{pc:x}, SP=0x{sp:x}, ret_addr=0x{ret_addr:x}")

        # 执行libc hook处理
        result = self._execute_libc_hook(func_name)

        # 设置返回值
        if result is not None:
            self.emu.regs.set_ret_value(result)
            # 标记已被拦截，这样emulator.call知道如何处理返回值
            self.emu._libc_intercepted = True

        # 跳过返回地址（call指令压入的返回地址）
        # 恢复SP：pop返回地址
        # ARM32是32位指针，ARM64/x86_64是64位
        ptr_size = 8 if self.emu.arch in ("x86_64", "arm64") else 4
        self.emu.set_sp(sp + ptr_size)

        # 跳转到返回地址
        self.emu.set_pc(ret_addr)

        # 返回False表示已处理，不传播中断
        return False

    def _get_plt_address(self, pc: int) -> Optional[int]:
        """从PC获取PLT地址（处理int3导致PC偏移的情况）"""
        # 检查PC是否直接匹配PLT地址
        if pc in self._plt_entries:
            return pc

        # int3执行后PC可能指向下一字节（x86）
        # 检查PC-1是否是PLT地址
        if (pc - 1) in self._plt_entries:
            return pc - 1

        return None

    def _execute_libc_hook(self, func_name: str):
        """执行libc hook处理"""
        if not self.emu.libc.is_enabled():
            return None

        try:
            return self.emu.libc.libc.execute(func_name)
        except Exception as e:
            print(f"[PLTInterceptor] libc hook error for {func_name}: {e}")
            return None

    def restore_plt(self):
        """恢复PLT原始指令（用于调试）"""
        for va, original in self._backup_data.items():
            try:
                self.emu.write_memory(va, original)
            except:
                pass
        self._backup_data.clear()

    def cleanup(self):
        """清理资源"""
        if self._interrupt_handle:
            try:
                self.emu.hooks._hooks.remove(self._interrupt_handle)
            except:
                pass
        self.restore_plt()
        self._plt_entries.clear()
        self._setup = False
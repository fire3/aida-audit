from typing import Optional, Callable, Any, Dict, List
import os
import tempfile
import shutil

try:
    import unicorn
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False

from .db_loader import DbLoader
from .regs import Regs, REGISTER_MAP
from .memory import MemoryMapper
from .call_conv import CallConvention, detect_call_convention, get_default_convention
from .hooks import HookManager
from .libc_sim import LibcHookManager


class AidaEmulator:
    def __init__(self, arch: str = "x86_64", mode: int = 0, db_path: Optional[str] = None):
        self.arch = arch
        self.mode = mode
        self.db_path = db_path
        self.db: Optional[DbLoader] = None
        self.metadata: Dict[str, Any] = {}
        
        self.uc = None
        if UNICORN_AVAILABLE:
            reg_info = REGISTER_MAP.get(arch, REGISTER_MAP["x86_64"])
            uc_arch = reg_info.get("unicorn_arch", unicorn.UC_ARCH_X86)
            uc_mode = reg_info.get("unicorn_mode", unicorn.UC_MODE_64)
            self.uc = unicorn.Uc(uc_arch, uc_mode)
        
        self.regs = Regs(self.uc, arch, mode)
        self.mem = MemoryMapper(self.uc)
        self.hooks = HookManager(self.uc)
        
        self._running = False
        self._entry_point: Optional[int] = None
        self._end_address: Optional[int] = None
        self._timeout: int = 0
        self._count: int = 0
        
        self._call_convention: Optional[CallConvention] = None
        self._stack_va: Optional[int] = None
        self._heap_va: Optional[int] = None
        self._heap_current: Optional[int] = None
        self._libc_auto_hook_setup = False
        
        self.libc = LibcHookManager(self)

    @classmethod
    def from_database(cls, db_path: str, arch: Optional[str] = None) -> "AidaEmulator":
        db = DbLoader(db_path)
        db.connect()
        
        metadata = db.load_metadata()
        
        if not arch:
            arch_str = metadata.get("arch", "64-bit").lower()
            processor = metadata.get("processor", "").lower()
            
            if "64-bit" in arch_str:
                if "aarch64" in processor or "arm64" in processor:
                    arch = "arm64"
                else:
                    arch = "x86_64"
            else:
                if "arm" in processor:
                    arch = "arm"
                elif "mips" in processor:
                    is_be = metadata.get("endian", "").lower() == "big endian"
                    arch = "mips" if is_be else "mipsel"
                else:
                    arch = "x86_32"
        
        mode = 0
        if arch == "arm_thumb":
            mode = unicorn.UC_MODE_THUMB
            arch = "arm"
        
        emu = cls(arch, mode, db_path)
        emu.db = db
        emu.metadata = metadata
        
        emu._load_segments(db)
        
        return emu

    @classmethod
    def from_binary(cls, binary_path: str, output_dir: Optional[str] = None,
                    keep_db: bool = False) -> "AidaEmulator":
        """
        从二进制文件直接创建模拟器，内部自动调用 IDA 导出数据库。
        
        Args:
            binary_path: 二进制文件路径
            output_dir: 输出目录，默认为临时目录
            keep_db: 是否保留导出的数据库文件
        
        Returns:
            AidaEmulator 实例
        
        Note:
            需要 IDA Pro
        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")
        
        if output_dir is None:
            temp_dir = tempfile.mkdtemp(prefix="aida_emu_")
            cleanup_temp = True
        else:
            os.makedirs(output_dir, exist_ok=True)
            temp_dir = output_dir
            cleanup_temp = False
        
        try:
            db_path = os.path.join(temp_dir, os.path.basename(binary_path) + ".db")
            
            try:
                from aida_cli.export_cmd import ExportOrchestrator
            except ImportError:
                raise ImportError(
                    "Failed to import aida_cli.export_cmd. "
                    "Make sure aida_cli is properly installed."
                )
            
            cmd = ExportOrchestrator(workers=1, verbose=False)
            
            success = cmd.process_single_file(
                binary_path,
                db_path,
                save_idb=None
            )
            
            if not success:
                raise RuntimeError(f"Failed to export binary: {binary_path}")
            
            emu = cls.from_database(db_path)
            
            if not keep_db:
                try:
                    os.remove(db_path)
                except OSError:
                    pass
                if cleanup_temp and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            
            return emu
            
        except Exception:
            if cleanup_temp and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            raise

    def _load_segments(self, db: DbLoader):
        segments = db.load_segments()
        
        for seg in segments:
            content = db.load_segment_content(seg["seg_id"])
            self.mem.map_segment(
                name=seg["name"],
                start_va=seg["start_va"],
                end_va=seg["end_va"],
                perm_r=seg["perm_r"],
                perm_w=seg["perm_w"],
                perm_x=seg["perm_x"],
                content=content
            )

    def setup_stack(self, stack_va: Optional[int] = None, stack_size: int = 0x100000) -> int:
        if stack_va is None:
            if self.arch == "x86_64":
                stack_va = 0x7fff_0000
            elif self.arch == "x86_32":
                stack_va = 0x7fff_0000
            elif self.arch in ("arm", "arm64"):
                stack_va = 0x7fff_f000
            else:
                stack_va = 0x7fff_0000
        
        self._stack_va = self.mem.allocate_stack(stack_va, stack_size)
        self.regs.set_sp(self._stack_va + stack_size - 8)
        
        return self._stack_va

    def setup_heap(self, heap_va: Optional[int] = None, heap_size: int = 0x100000) -> int:
        if heap_va is None:
            if self.arch == "x86_64":
                heap_va = 0x600000
            elif self.arch == "x86_32":
                heap_va = 0x400000
            else:
                heap_va = 0x600000
        
        self._heap_va = self.mem.allocate_heap(heap_va, heap_size)
        self._heap_current = heap_va
        
        return self._heap_va
    
    def alloc(self, size: int, data: Optional[bytes] = None) -> int:
        if self._heap_va is None:
            self.setup_heap()
        
        heap_curr = self._heap_current if self._heap_current else self._heap_va
        
        if data is not None:
            size = max(size, len(data))
        
        size = (size + 7) & ~7
        
        addr = heap_curr
        
        self.mem.map(
            name=f"alloc_{addr:x}",
            va=addr,
            size=size,
            read=True,
            write=True,
            execute=False,
            content=data
        )
        
        self._heap_current = addr + size
        
        return addr

    def set_pc(self, address: int):
        self._entry_point = address
        self.regs.set_pc(address)

    def get_pc(self) -> int:
        return self.regs.get_pc() or 0

    def set_sp(self, value: int):
        self.regs.set_sp(value)

    def get_sp(self) -> int:
        return self.regs.get_sp() or 0

    def set_reg(self, name: str, value: int):
        self.regs.set_reg(name, value)

    def get_reg(self, name: str) -> int:
        return self.regs.get_reg(name) or 0

    def set_arg(self, index: int, value: int):
        if self._call_convention:
            if index < len(self._call_convention.args):
                self.regs.set_reg(self._call_convention.args[index], value)
            else:
                sp = self.get_sp()
                offset = 8 + (index - len(self._call_convention.args)) * 8
                self.mem.write_u64(sp + offset, value)
        else:
            self.regs.set_arg(index, value)

    def set_args(self, *args):
        for i, arg in enumerate(args):
            self.set_arg(i, arg)

    def detect_convention(self, func_va: int) -> CallConvention:
        if self.db:
            self._call_convention = detect_call_convention(self.db, func_va, self.arch)
        else:
            self._call_convention = get_default_convention(self.arch)
        return self._call_convention

    def get_convention(self) -> Optional[CallConvention]:
        return self._call_convention

    def hook_code(self, callback: Callable, user_data: Any = None) -> bool:
        def wrapped(uc, address, size, user_data):
            return callback(self, address, size, user_data)
        
        return self.hooks.add_code_hook(wrapped, user_data) is not None

    def hook_block(self, callback: Callable, user_data: Any = None) -> bool:
        def wrapped(uc, address, size, user_data):
            return callback(self, address, size, user_data)
        
        return self.hooks.add_block_hook(wrapped, user_data) is not None

    def hook_libc(self, func_name: str, address: int) -> bool:
        self.libc.register_address(func_name, address)
        return True

    def enable_libc_hooks(self):
        self.libc.enable()
        self._setup_libc_auto_hook()

    def disable_libc_hooks(self):
        self.libc.disable()

    def _setup_libc_auto_hook(self):
        if hasattr(self, '_libc_auto_hook_setup') and self._libc_auto_hook_setup:
            return
        
        call_target_cache = {}
        
        def libc_call_hook(emu, address, size, user_data):
            if not emu.libc.is_enabled():
                return True
            
            if address not in call_target_cache:
                call_target_cache[address] = emu._resolve_call_target(address)
            
            target_addr = call_target_cache[address]
            
            if target_addr:
                name = emu.libc.libc.get_name_by_address(target_addr)
                if name:
                    result = emu.libc.libc.execute(name)
                    emu.regs.set_ret_value(result)
                    emu._libc_intercepted = True
                    emu.set_pc(address + size)
                    return True
            return True
        
        self.hook_code(libc_call_hook)
        self._libc_auto_hook_setup = True
    
    def _resolve_call_target(self, address: int) -> Optional[int]:
        if not self.db:
            return None
        
        data = self.read_memory(address, 16)
        if not data:
            return None
        
        target_addr = None
        
        if self.arch == "x86_64" or self.arch == "x86_32":
            if len(data) >= 5 and data[0] == 0xE8:
                offset = int.from_bytes(data[1:5], 'little', signed=True)
                target_addr = address + 5 + offset
            elif len(data) >= 6 and data[0] == 0xFF and (data[1] == 0x15 or data[1] == 0x10 or data[1] == 0x25):
                offset = int.from_bytes(data[2:6], 'little', signed=True)
                target_addr = address + 6 + offset
        
        if not target_addr:
            return None
        
        func = self.db.load_function(target_addr)
        if func:
            name = func.get("name", "")
            libc_name = name.lstrip(".")
            for suffix in ["@plt", "@GLIBC"]:
                libc_name = libc_name.replace(suffix, "")
            libc_name = libc_name.lower()
            
            registered_addr = self.libc.libc.get_address_by_name(libc_name)
            if registered_addr:
                return registered_addr
        
        return target_addr

    def hook_memory(self, callback: Callable, 
                    mem_type: str = "all", user_data: Any = None) -> bool:
        def wrapped(uc, access, address, size, value, user_data):
            return callback(self, access, address, size, value, user_data)
        
        from .hooks import MEMORY_HOOK_TYPES
        hook_type = MEMORY_HOOK_TYPES.get(mem_type, 0)
        
        return self.hooks.add_memory_hook(wrapped, hook_type, user_data) is not None

    def hook_interrupt(self, callback: Callable, user_data: Any = None) -> bool:
        def wrapped(uc, intno, user_data):
            return callback(self, intno, user_data)
        
        return self.hooks.add_interrupt_hook(wrapped, user_data) is not None

    def run(self, start: Optional[int] = None, end: Optional[int] = None, 
            timeout: int = 0, count: int = 0):
        if not self.uc:
            raise RuntimeError("Unicorn not available")
        
        if start is not None:
            self.set_pc(start)
        
        if end is not None:
            self._end_address = end
        
        self._timeout = timeout
        self._count = count
        self._running = True
        
        begin = self._entry_point or start
        if begin is None:
            raise ValueError("No entry point specified")
        
        end_addr = self._end_address
        
        try:
            if end_addr:
                self.uc.emu_start(begin, end_addr, timeout, count)
            else:
                self.uc.emu_start(begin, 0xFFFFFFFFFFFFFFFF, timeout, count)
        except unicorn.UcError as e:
            self._running = False
            raise EmulationError(f"Emulation error: {e}") from e
        
        self._running = False

    def stop(self):
        if self.uc and self._running:
            self.uc.emu_stop()
        self._running = False

    def reset(self):
        self.stop()
        if self.uc:
            self.uc = unicorn.Uc(self.regs._reg_info.get("unicorn_arch", unicorn.UC_ARCH_X86),
                                 self.regs._reg_info.get("unicorn_mode", unicorn.UC_MODE_64))
            self.regs = Regs(self.uc, self.arch, self.mode)
            self.mem = MemoryMapper(self.uc)
            self.hooks = HookManager(self.uc)

    def call(self, func_va: int, *args) -> int:
        self.detect_convention(func_va)
        
        sp = self.get_sp()
        
        ret_addr = 0x41414141
        
        self.mem.map("call_ret", ret_addr, 0x1000, True, True, False, b"\xf4" * 0x1000)
        self.mem.write_u64(sp, ret_addr)
        self.set_sp(sp - 8)
        
        self.set_args(*args)
        
        self.set_pc(func_va)
        
        self._libc_intercepted = False
        self._call_return_addr = ret_addr
        
        try:
            self.run(start=func_va)
        except EmulationError:
            pass
        
        if self._libc_intercepted:
            return self.regs.get_ret_value(signed=True) or 0
        
        result = self.regs.get_ret_value(signed=True)
        return result if result is not None else 0

    def read_memory(self, va: int, size: int) -> Optional[bytes]:
        return self.mem.read(va, size)

    def write_memory(self, va: int, data: bytes) -> bool:
        return self.mem.write(va, data)

    def read_ptr(self, va: int, size: int = 8) -> Optional[int]:
        if size == 8:
            return self.mem.read_u64(va)
        elif size == 4:
            return self.mem.read_u32(va)
        elif size == 2:
            return self.mem.read_u16(va)
        elif size == 1:
            return self.mem.read_u8(va)
        return None

    def write_ptr(self, va: int, value: int, size: int = 8) -> bool:
        if size == 8:
            return self.mem.write_u64(va, value)
        elif size == 4:
            return self.mem.write_u32(va, value)
        elif size == 2:
            return self.mem.write_u16(va, value)
        elif size == 1:
            return self.mem.write_u8(va, value)
        return False

    def get_stack_value(self, offset: int = 0, size: int = 8) -> Optional[int]:
        sp = self.get_sp()
        return self.read_ptr(sp + offset, size)

    def set_stack_value(self, offset: int, value: int, size: int = 8) -> bool:
        sp = self.get_sp()
        return self.write_ptr(sp + offset, value, size)

    def get_function(self, va: int) -> Optional[Dict[str, Any]]:
        if self.db:
            return self.db.load_function(va)
        return None

    def get_instructions(self, start_va: int, end_va: int) -> List[Dict[str, Any]]:
        if self.db:
            return self.db.load_instructions(start_va, end_va)
        return []

    def get_call_targets(self, func_va: int) -> List[int]:
        if self.db:
            return self.db.load_call_targets(func_va)
        return []

    def is_running(self) -> bool:
        return self._running

    def close(self):
        self.stop()
        if self.db:
            self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class EmulationError(Exception):
    pass
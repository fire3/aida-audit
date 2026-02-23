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
        
        self.plt_start: Optional[int] = None
        self.plt_end: Optional[int] = None
        self.got_start: Optional[int] = None
        self.got_size: Optional[int] = None
        self._plt_to_func: Dict[int, str] = {}
        self._plt_hook_setup: bool = False
        self._plt_hook_callback: Optional[Callable] = None
        
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
        
        # Collect all segments that should be mapped contiguously
        # We'll create one large mapping and fill in the contents at correct offsets
        
        # Get the min and max addresses across all segments
        min_va = None
        max_va = None
        for seg in segments:
            if seg["start_va"] == 0:
                continue
            if min_va is None or seg["start_va"] < min_va:
                min_va = seg["start_va"]
            if max_va is None or seg["end_va"] > max_va:
                max_va = seg["end_va"]
        
        if min_va is None or max_va is None:
            return
        
        total_size = max_va - min_va
        
        # Align to page size
        aligned_min_va = min_va & ~0xFFF
        aligned_size = ((total_size + (min_va - aligned_min_va) + 0xFFF) & ~0xFFF)
        
        # Map one large region for all segments
        # Use combined permissions (RX for code+rodata, RW for data)
        combined_perms = True  # Map with RWX initially
        
        self.uc.mem_map(aligned_min_va, aligned_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE | unicorn.UC_PROT_EXEC)
        
        # Fill the region with segment contents at correct offsets
        for seg in segments:
            if seg["start_va"] == 0:
                continue
                
            content = db.load_segment_content(seg["seg_id"])
            if not content:
                content = b'\x00' * (seg["end_va"] - seg["start_va"])
            
            # Write content at the correct offset
            offset = seg["start_va"] - aligned_min_va
            try:
                self.uc.mem_write(aligned_min_va + offset, content)
            except unicorn.UcError as e:
                print(f"Warning: Failed to write {seg['name']}: {e}")
            
            # Track this region
            self.mem._mapped_regions[seg["start_va"]] = {
                "id": self.mem._next_map_id,
                "name": seg["name"],
                "va": seg["start_va"],
                "size": seg["end_va"] - seg["start_va"],
                "aligned_va": aligned_min_va,
                "aligned_size": aligned_size,
                "perm_r": seg["perm_r"],
                "perm_w": seg["perm_w"],
                "perm_x": seg["perm_x"],
            }
            self.mem._next_map_id += 1
        
        self._init_got(db, segments)
    
    def _init_got(self, db: DbLoader, segments: List[Dict[str, Any]]):
        got_seg = None
        plt_seg = None
        for seg in segments:
            if seg["name"] == ".got":
                got_seg = seg
            elif seg["name"] == ".plt":
                plt_seg = seg
        
        if not got_seg or not plt_seg:
            return
        
        import_funcs = db.get_imports() if hasattr(db, 'get_imports') else []
        
        got_start = got_seg["start_va"]
        got_size = got_seg["size"]
        plt_start = plt_seg["start_va"]
        plt_size = plt_seg["end_va"] - plt_seg["start_va"]
        
        resolved_count = 0
        
        # The GOT structure is:
        # GOT[0] = resolver address
        # GOT[1..n] = addresses of imported functions
        # 
        # PLT entries are at plt_start + i*16
        # Each PLT[i] should have GOT[i+1] point to the function address
        #
        # For unresolved symbols, GOT[i+1] should point to PLT[i] (to jump to resolver)
        # For resolved symbols, GOT[i+1] should point to the actual function address
        
        # We need to figure out which GOT entry corresponds to which import
        # The import "address" field seems to be the address in the binary where the
        # pointer to the function is stored, not the GOT offset
        
        # Let's use a simpler approach: iterate through PLT entries and set up
        # the corresponding GOT entries
        
        # First, compute how many PLT entries we have
        num_plt_entries = plt_size // 16
        
        # Check if there's a symbol table that maps PLT to imports
        # Otherwise, we'll just leave GOT entries pointing to PLT stubs
        
        # Initialize all GOT entries (except GOT[0]) to point to their PLT entries
        for i in range(1, num_plt_entries):
            got_addr = got_start + i * 4
            plt_entry_addr = plt_start + i * 16
            
            if got_start <= got_addr < got_start + got_size:
                # Write PLT entry address to GOT
                self.mem.write_u32(got_addr, plt_entry_addr)
                resolved_count += 1
        
        if resolved_count > 0:
            print(f"Initialized {resolved_count} GOT entries")
        
        self.plt_start = plt_start
        self.plt_end = plt_seg["end_va"]
        self.got_start = got_start
        self.got_size = got_size
        
        self._setup_plt_function_map(db)

    def _setup_plt_function_map(self, db: DbLoader):
        if not self.plt_start or not self.got_start:
            return
        
        imports = db.get_imports() if hasattr(db, 'get_imports') else []
        
        plt_size = self.plt_end - self.plt_start
        num_plt_entries = plt_size // 16
        
        import_funcs = []
        for imp in imports:
            name = imp.get("name", "")
            if name.endswith("@plt"):
                import_funcs.append(name[:-4])
            elif "@" in name:
                import_funcs.append(name.split("@")[0])
            else:
                import_funcs.append(name)
        
        for i in range(1, min(num_plt_entries, len(import_funcs))):
            plt_entry_addr = self.plt_start + i * 16
            func_name = import_funcs[i - 1] if i - 1 < len(import_funcs) else f"unknown_{i}"
            self._plt_to_func[plt_entry_addr] = func_name
        
        if self._plt_to_func:
            print(f"Mapped {len(self._plt_to_func)} PLT entries to function names")

    def is_plt_address(self, addr: int) -> bool:
        if self.plt_start is None or self.plt_end is None:
            return False
        return self.plt_start <= addr < self.plt_end

    def get_plt_function_name(self, addr: int) -> Optional[str]:
        plt_entry = addr & ~0xF
        if plt_entry in self._plt_to_func:
            return self._plt_to_func[plt_entry]
        
        for plt_addr, name in self._plt_to_func.items():
            if plt_addr <= addr < plt_addr + 16:
                return name
        
        return None

    def enable_plt_hooks(self, callback: Optional[Callable[["AidaEmulator", int, str], Any]] = None):
        if self._plt_hook_setup:
            return
        
        self._plt_hook_callback = callback
        hooked_functions: set = set()
        
        def plt_hook(emu: "AidaEmulator", address: int, size: int, user_data: Any):
            if not emu.is_plt_address(address):
                return True
            
            func_name = emu.get_plt_function_name(address)
            if not func_name:
                return True
            
            if func_name not in hooked_functions:
                print(f"\n{'='*60}")
                print(f"[PLT HOOK] Function call intercepted at 0x{address:x}")
                print(f"{'='*60}")
                print(f"  Target function: {func_name}")
                print(f"")
                print(f"  To handle this call, you need to:")
                print(f"    emu.hook_libc('{func_name}', <handler_address>)")
                print(f"  Or provide a custom implementation that returns a value")
                print(f"{'='*60}\n")
                hooked_functions.add(func_name)
                
                if emu._plt_hook_callback:
                    emu._plt_hook_callback(emu, address, func_name)
            
            return True
        
        self.hook_code(plt_hook)
        self._plt_hook_setup = True
        print("PLT hooks enabled - will intercept all PLT calls")

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
        
        self._libc_auto_hook_setup = True
        
        def plt_libc_callback(emu: "AidaEmulator", address: int, func_name: str):
            if not emu.libc.is_enabled():
                return
            
            registered_addr = emu.libc.libc.get_address_by_name(func_name.lower())
            if registered_addr is not None:
                result = emu.libc.libc.execute(func_name.lower())
                if result is not None:
                    emu.regs.set_ret_value(result)
                    emu._libc_intercepted = True
                    emu.set_pc(address + 4)
        
        self.enable_plt_hooks(callback=plt_libc_callback)
    
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
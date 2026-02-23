from typing import Dict, Callable, Any, Optional, List
from .memory import MemoryMapper


class LibcSimulator:
    def __init__(self, emu):
        self.emu = emu
        self._handlers: Dict[str, Callable] = {}
        self._address_to_name: Dict[int, str] = {}
        self._name_to_address: Dict[str, int] = {}
        self._setup_default_handlers()
    
    def _setup_default_handlers(self):
        self.register("strlen", self._strlen)
        self.register("strcmp", self._strcmp)
        self.register("strncmp", self._strncmp)
        self.register("strcpy", self._strcpy)
        self.register("strncpy", self._strncpy)
        self.register("memcpy", self._memcpy)
        self.register("memset", self._memset)
        self.register("atoi", self._atoi)
        self.register("atol", self._atol)
        self.register("malloc", self._malloc)
        self.register("free", self._free)
    
    def register(self, name: str, handler: Callable[[], int]):
        self._handlers[name] = handler
    
    def register_address(self, name: str, address: int):
        self._name_to_address[name] = address
        self._address_to_name[address] = name
    
    def get_handler(self, name: str) -> Optional[Callable]:
        return self._handlers.get(name)
    
    def get_name_by_address(self, address: int) -> Optional[str]:
        return self._address_to_name.get(address)
    
    def get_address_by_name(self, name: str) -> Optional[int]:
        return self._name_to_address.get(name)
    
    def _read_string(self, addr: int) -> str:
        if addr == 0:
            return ""
        result = []
        while True:
            byte = self.emu.mem.read_u8(addr)
            if byte is None or byte == 0:
                break
            result.append(chr(byte))
            addr += 1
        return "".join(result)
    
    def _write_string(self, addr: int, s: str) -> bool:
        data = s.encode("utf-8") + b"\x00"
        return self.emu.mem.write(addr, data)
    
    def _strlen(self) -> int:
        addr = self.emu.regs.get_arg(0)
        if addr is None:
            return 0
        s = self._read_string(addr)
        return len(s)
    
    def _strcmp(self) -> int:
        s1_addr = self.emu.regs.get_arg(0)
        s2_addr = self.emu.regs.get_arg(1)
        if s1_addr is None or s2_addr is None:
            return 0
        s1 = self._read_string(s1_addr)
        s2 = self._read_string(s2_addr)
        if s1 < s2:
            return -1
        elif s1 > s2:
            return 1
        return 0
    
    def _strncmp(self) -> int:
        s1_addr = self.emu.regs.get_arg(0)
        s2_addr = self.emu.regs.get_arg(1)
        n = self.emu.regs.get_arg(2)
        if s1_addr is None or s2_addr is None or n is None:
            return 0
        s1 = self._read_string(s1_addr)[:n]
        s2 = self._read_string(s2_addr)[:n]
        if s1 < s2:
            return -1
        elif s1 > s2:
            return 1
        return 0
    
    def _strcpy(self) -> int:
        dest_addr = self.emu.regs.get_arg(0)
        src_addr = self.emu.regs.get_arg(1)
        if dest_addr is None or src_addr is None:
            return 0
        s = self._read_string(src_addr)
        self._write_string(dest_addr, s)
        return dest_addr
    
    def _strncpy(self) -> int:
        dest_addr = self.emu.regs.get_arg(0)
        src_addr = self.emu.regs.get_arg(1)
        n = self.emu.regs.get_arg(2)
        if dest_addr is None or src_addr is None or n is None:
            return 0
        s = self._read_string(src_addr)[:n]
        self.emu.mem.write(dest_addr, s.encode("utf-8"))
        if len(s) < n:
            padding = b"\x00" * (n - len(s))
            self.emu.mem.write(dest_addr + len(s), padding)
        return dest_addr
    
    def _memcpy(self) -> int:
        dest_addr = self.emu.regs.get_arg(0)
        src_addr = self.emu.regs.get_arg(1)
        n = self.emu.regs.get_arg(2)
        if dest_addr is None or src_addr is None or n is None:
            return 0
        data = self.emu.mem.read(src_addr, n)
        if data:
            self.emu.mem.write(dest_addr, bytes(data))
        return dest_addr
    
    def _memset(self) -> int:
        addr = self.emu.regs.get_arg(0)
        byte = self.emu.regs.get_arg(1)
        n = self.emu.regs.get_arg(2)
        if addr is None or byte is None or n is None:
            return 0
        self.emu.mem.write(addr, bytes([byte & 0xFF]) * n)
        return addr
    
    def _atoi(self) -> int:
        addr = self.emu.regs.get_arg(0)
        if addr is None:
            return 0
        s = self._read_string(addr)
        try:
            return int(s)
        except ValueError:
            return 0
    
    def _atol(self) -> int:
        return self._atoi()
    
    def _malloc(self) -> int:
        size = self.emu.regs.get_arg(0)
        if size is None or size <= 0:
            return 0
        ptr = self.emu.alloc(size)
        return ptr
    
    def _free(self) -> int:
        return 0
    
    def execute(self, name: str) -> int:
        handler = self._handlers.get(name)
        if handler:
            return handler()
        return 0
    
    def list_functions(self) -> List[str]:
        return list(self._handlers.keys())


class LibcHookManager:
    def __init__(self, emu):
        self.emu = emu
        self.libc = LibcSimulator(emu)
        self._enabled = False
        self._intercept_calls = True
    
    def enable(self):
        self._enabled = True
    
    def disable(self):
        self._enabled = False
    
    def is_enabled(self) -> bool:
        return self._enabled
    
    def register_function(self, name: str, handler: Callable[[], int]):
        self.libc.register(name, handler)
    
    def register_address(self, name: str, address: int):
        self.libc.register_address(name, address)
    
    def handle_call(self, call_addr: int) -> bool:
        if not self._enabled:
            return False
        
        func_name = self.libc.get_name_by_address(call_addr)
        if func_name:
            result = self.libc.execute(func_name)
            self.emu.regs.set_ret_value(result)
            return True
        return False
    
    def get_function_address(self, name: str) -> Optional[int]:
        return self.libc.get_address_by_name(name)
from typing import Optional, Callable, Any, Dict, List
from enum import Enum

try:
    import unicorn
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


class HookType(Enum):
    CODE = 1
    BLOCK = 2
    INTERRUPT = 3
    MEMORY_READ = 4
    MEMORY_WRITE = 5
    MEMORY_FETCH = 6
    MEMORY_READ_UNMAPPED = 7
    MEMORY_WRITE_UNMAPPED = 8
    MEMORY_FETCH_UNMAPPED = 9
    MEMORY_UNMAPPED = 10


class HookHandle:
    def __init__(self, hook_id: int, hook_type: HookType):
        self.hook_id = hook_id
        self.hook_type = hook_type
        self.enabled = True

    def disable(self):
        self.enabled = False

    def enable(self):
        self.enabled = True


class CodeHook:
    def __init__(self, uc: Optional["unicorn.Uc"], callback: Callable, user_data: Any = None, 
                 begin: int = 1, end: int = 0):
        self.uc = uc
        self.callback = callback
        self.user_data = user_data
        self.begin = begin
        self.end = end
        self.handle: Optional[HookHandle] = None

    def register(self) -> bool:
        if not self.uc:
            return False
        try:
            self._hook_callback = self._wrap_callback(self.callback)
            hook_id = self.uc.hook_add(unicorn.UC_HOOK_CODE, self._hook_callback, self.user_data, 
                                       self.begin, self.end)
            self.handle = HookHandle(hook_id, HookType.CODE)
            return True
        except unicorn.UcError:
            return False

    def unregister(self):
        if self.uc and self.handle:
            try:
                self.uc.hook_del(self.handle.hook_id)
            except:
                pass
            self.handle = None

    def _wrap_callback(self, callback: Callable) -> Callable:
        def wrapper(uc, address, size, user_data):
            return callback(uc, address, size, user_data)
        return wrapper


class BlockHook:
    def __init__(self, uc: Optional["unicorn.Uc"], callback: Callable, user_data: Any = None):
        self.uc = uc
        self.callback = callback
        self.user_data = user_data
        self.handle: Optional[HookHandle] = None

    def register(self) -> bool:
        if not self.uc:
            return False
        try:
            self._hook_callback = self._wrap_callback(self.callback)
            hook_id = self.uc.hook_add(unicorn.UC_HOOK_BLOCK, self._hook_callback, self.user_data)
            self.handle = HookHandle(hook_id, HookType.BLOCK)
            return True
        except unicorn.UcError:
            return False

    def unregister(self):
        if self.uc and self.handle:
            try:
                self.uc.hook_del(self.handle.hook_id)
            except:
                pass
            self.handle = None

    def _wrap_callback(self, callback: Callable) -> Callable:
        def wrapper(uc, address, size, user_data):
            return callback(uc, address, size, user_data)
        return wrapper


class MemoryHook:
    def __init__(self, uc: Optional["unicorn.Uc"], callback: Callable, 
                 mem_type: int = 0, user_data: Any = None):
        self.uc = uc
        self.callback = callback
        self.mem_type = mem_type
        self.user_data = user_data
        self.handle: Optional[HookHandle] = None

    @property
    def default_mem_type(self) -> int:
        if UNICORN_AVAILABLE:
            return (unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE | 
                    unicorn.UC_HOOK_MEM_FETCH | unicorn.UC_HOOK_MEM_UNMAPPED)
        return 0

    def register(self) -> bool:
        if not self.uc:
            return False
        try:
            self._hook_callback = self._wrap_callback(self.callback)
            hook_id = self.uc.hook_add(self.mem_type, self._hook_callback, self.user_data)
            self.handle = HookHandle(hook_id, HookType.MEMORY_READ)
            return True
        except unicorn.UcError:
            return False

    def unregister(self):
        if self.uc and self.handle:
            try:
                self.uc.hook_del(self.handle.hook_id)
            except:
                pass
            self.handle = None

    def _wrap_callback(self, callback: Callable) -> Callable:
        def wrapper(uc, access, address, size, value, user_data):
            return callback(uc, access, address, size, value, user_data)
        return wrapper


class InterruptHook:
    def __init__(self, uc: Optional["unicorn.Uc"], callback: Callable, user_data: Any = None):
        self.uc = uc
        self.callback = callback
        self.user_data = user_data
        self.handle: Optional[HookHandle] = None

    def register(self) -> bool:
        if not self.uc:
            return False
        try:
            self._hook_callback = self._wrap_callback(self.callback)
            hook_id = self.uc.hook_add(unicorn.UC_HOOK_INTR, self._hook_callback, self.user_data)
            self.handle = HookHandle(hook_id, HookType.INTERRUPT)
            return True
        except unicorn.UcError:
            return False

    def unregister(self):
        if self.uc and self.handle:
            try:
                self.uc.hook_del(self.handle.hook_id)
            except:
                pass
            self.handle = None

    def _wrap_callback(self, callback: Callable) -> Callable:
        def wrapper(uc, intno, user_data):
            return callback(uc, intno, user_data)
        return wrapper


class HookManager:
    def __init__(self, uc: Optional["unicorn.Uc"]):
        self.uc = uc
        self._hooks: List[HookHandle] = []

    def add_code_hook(self, callback: Callable, user_data: Any = None, 
                      begin: int = 1, end: int = 0) -> Optional[HookHandle]:
        hook = CodeHook(self.uc, callback, user_data, begin, end)
        if hook.register():
            self._hooks.append(hook.handle)
            return hook.handle
        return None

    def add_block_hook(self, callback: Callable, user_data: Any = None) -> Optional[HookHandle]:
        hook = BlockHook(self.uc, callback, user_data)
        if hook.register():
            self._hooks.append(hook.handle)
            return hook.handle
        return None

    def add_memory_hook(self, callback: Callable, 
                        mem_type: int = None,
                        user_data: Any = None) -> Optional[HookHandle]:
        if mem_type is None:
            mem_type = MEMORY_HOOK_TYPES["all"]
        hook = MemoryHook(self.uc, callback, mem_type, user_data)
        if hook.register():
            self._hooks.append(hook.handle)
            return hook.handle
        return None

    def add_interrupt_hook(self, callback: Callable, user_data: Any = None) -> Optional[HookHandle]:
        hook = InterruptHook(self.uc, callback, user_data)
        if hook.register():
            self._hooks.append(hook.handle)
            return hook.handle
        return None

    def clear_all(self):
        for hook in self._hooks:
            try:
                if self.uc:
                    self.uc.hook_del(hook.hook_id)
            except:
                pass
        self._hooks.clear()

    def get_hooks(self) -> List[HookHandle]:
        return list(self._hooks)


MEMORY_HOOK_TYPES = {
    "read": 0,
    "write": 0,
    "fetch": 0,
    "read_unmapped": 0,
    "write_unmapped": 0,
    "fetch_unmapped": 0,
    "unmapped": 0,
    "all": 0,
}

if UNICORN_AVAILABLE:
    MEMORY_HOOK_TYPES = {
        "read": unicorn.UC_HOOK_MEM_READ,
        "write": unicorn.UC_HOOK_MEM_WRITE,
        "fetch": unicorn.UC_HOOK_MEM_FETCH,
        "read_unmapped": unicorn.UC_HOOK_MEM_READ_UNMAPPED,
        "write_unmapped": unicorn.UC_HOOK_MEM_WRITE_UNMAPPED,
        "fetch_unmapped": unicorn.UC_HOOK_MEM_FETCH_UNMAPPED,
        "unmapped": unicorn.UC_HOOK_MEM_UNMAPPED,
        "all": (unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE | 
                unicorn.UC_HOOK_MEM_FETCH | unicorn.UC_HOOK_MEM_UNMAPPED),
    }


def create_memory_hook(uc: Optional["unicorn.Uc"], callback: Callable, 
                       hook_type: str = "all", user_data: Any = None) -> Optional[MemoryHook]:
    mem_type = MEMORY_HOOK_TYPES.get(hook_type, unicorn.UC_HOOK_MEM_ALL)
    hook = MemoryHook(uc, callback, mem_type, user_data)
    if hook.register():
        return hook
    return None
from typing import Optional, Dict, Any, List, Tuple
from .db_loader import DbLoader


CALL_CONVENTIONS: Dict[str, Dict[str, Any]] = {
    "x86_64": {
        "sysv_amd64": {
            "args": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            "stack_align": 16,
            "stack_args": True,
            "caller_cleanup": True,
        },
        "ms_x64": {
            "args": ["rcx", "rdx", "r8", "r9"],
            "stack_align": 16,
            "stack_args": True,
            "caller_cleanup": True,
            "shadow_space": 32,
        },
    },
    "x86_32": {
        "cdecl": {
            "args": [],
            "stack_args": True,
            "caller_cleanup": True,
        },
        "stdcall": {
            "args": [],
            "stack_args": True,
            "caller_cleanup": False,
        },
        "fastcall": {
            "args": ["ecx", "edx"],
            "stack_args": True,
            "caller_cleanup": True,
        },
        "thiscall": {
            "args": ["ecx"],
            "stack_args": True,
            "caller_cleanup": True,
        },
    },
    "arm": {
        "aapcs": {
            "args": ["r0", "r1", "r2", "r3"],
            "stack_args": True,
            "caller_cleanup": True,
        },
    },
    "arm64": {
        "aapcs64": {
            "args": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            "stack_args": True,
            "caller_cleanup": True,
            "stack_align": 16,
        },
    },
    "mips": {
        "o32": {
            "args": ["$a0", "$a1", "$a2", "$a3"],
            "stack_args": True,
            "caller_cleanup": True,
        },
    },
    "mipsel": {
        "o32": {
            "args": ["$a0", "$a1", "$a2", "$a3"],
            "stack_args": True,
            "caller_cleanup": True,
        },
    },
}


class CallConvention:
    def __init__(self, name: str, arch: str, args: List[str], 
                 stack_args: bool = True, caller_cleanup: bool = True,
                 stack_align: int = 0, shadow_space: int = 0):
        self.name = name
        self.arch = arch
        self.args = args
        self.stack_args = stack_args
        self.caller_cleanup = caller_cleanup
        self.stack_align = stack_align
        self.shadow_space = shadow_space

    def __repr__(self):
        return f"CallConvention({self.name}, args={self.args})"


def detect_call_convention(db: DbLoader, func_va: int, arch: str = "x86_64") -> CallConvention:
    insns = db.load_instructions(func_va, func_va + 64)
    
    if not insns:
        return get_default_convention(arch)
    
    prologue = insns[:12]
    
    has_frame = False
    has_push_rbp = False
    has_sub_rsp = False
    ret_n = None
    
    for insn in prologue:
        mnem = insn["mnemonic"].lower()
        ops = [op["text"] for op in insn["operands"]]
        
        if mnem == "push" and "rbp" in ops:
            has_push_rbp = True
        elif mnem == "push" and "ebp" in ops:
            has_push_rbp = True
            has_frame = True
        elif mnem == "mov" and len(ops) >= 2:
            if "rbp" in ops[0] and "rsp" in ops[1]:
                has_frame = True
            elif "ebp" in ops[0] and "esp" in ops[1]:
                has_frame = True
        elif mnem == "sub" and len(ops) >= 2:
            if "rsp" in ops[0]:
                has_sub_rsp = True
            elif "esp" in ops[0]:
                has_sub_rsp = True
    
    end_va = db.get_function_end(func_va)
    if end_va:
        epilogue_insns = db.load_instructions(end_va - 32, end_va)
        for insn in epilogue_insns:
            mnem = insn["mnemonic"].lower()
            if mnem == "ret":
                pass
            elif mnem == "ret" and insn["operands"]:
                try:
                    ret_n = int(insn["operands"][0]["value"], 0)
                except:
                    pass
    
    stack_accesses = analyze_stack_access(prologue, has_frame)
    
    convention = match_convention(arch, has_frame, has_sub_rsp, ret_n, stack_accesses)
    
    return convention


def analyze_stack_access(insns: List[Dict], has_frame: bool) -> List[Tuple[str, int]]:
    accesses = []
    
    for insn in insns:
        mnem = insn["mnemonic"].lower()
        ops = [op["text"] for op in insn["operands"]]
        
        if mnem in ("mov", "lea", "add", "and") and len(ops) >= 2:
            dst = ops[0]
            src = ops[1] if len(ops) > 1 else ""
            
            if has_frame and "rbp" in dst:
                if "+" in src:
                    try:
                        offset = int(src.split("+")[1].rstrip("]"), 0)
                        accesses.append(("rbp", offset))
                    except:
                        pass
                elif "-" in src:
                    try:
                        offset = -int(src.split("-")[1].rstrip("]"), 0)
                        accesses.append(("rbp", offset))
                    except:
                        pass
            
            if has_frame and "ebp" in dst:
                if "+" in src:
                    try:
                        offset = int(src.split("+")[1].rstrip("]"), 0)
                        accesses.append(("ebp", offset))
                    except:
                        pass
                elif "-" in src:
                    try:
                        offset = -int(src.split("-")[1].rstrip("]"), 0)
                        accesses.append(("ebp", offset))
                    except:
                        pass
            
            if "rsp" in dst or "esp" in dst:
                if "+" in src:
                    try:
                        offset = int(src.split("+")[1].rstrip("]"), 0)
                        accesses.append(("rsp", offset))
                    except:
                        pass
                elif "-" in src:
                    try:
                        offset = -int(src.split("-")[1].rstrip("]"), 0)
                        accesses.append(("rsp", offset))
                    except:
                        pass
    
    return accesses


def match_convention(arch: str, has_frame: bool, has_sub_rsp: bool, 
                     ret_n: Optional[int], stack_accesses: List[Tuple[str, int]]) -> CallConvention:
    if arch == "x86_64":
        param_accesses = [(reg, off) for reg, off in stack_accesses 
                          if reg in ("rbp", "ebp") and off >= 8]
        
        if param_accesses:
            param_offsets = sorted([off for _, off in param_accesses])
            if param_offsets == [8, 12, 16, 20]:
                return CallConvention("cdecl", arch, [], stack_args=True, caller_cleanup=True)
            elif ret_n is not None:
                return CallConvention("stdcall", arch, [], stack_args=True, caller_cleanup=False)
        
        if has_frame and has_sub_rsp:
            return CallConvention("sysv_amd64", arch, 
                                  ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
                                  stack_args=True, caller_cleanup=True, stack_align=16)
        
        return CallConvention("sysv_amd64", arch,
                              ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
                              stack_args=True, caller_cleanup=True, stack_align=16)
    
    elif arch == "x86_32":
        param_accesses = [(reg, off) for reg, off in stack_accesses 
                          if reg in ("ebp", "rbp") and off >= 8]
        
        if param_accesses:
            param_offsets = sorted([off for _, off in param_accesses])
            if param_offsets == [8, 12, 16, 20]:
                if ret_n is not None:
                    return CallConvention("stdcall", arch, [], stack_args=True, caller_cleanup=False)
                return CallConvention("cdecl", arch, [], stack_args=True, caller_cleanup=True)
        
        if ret_n is not None and ret_n > 0:
            return CallConvention("stdcall", arch, [], stack_args=True, caller_cleanup=False)
        
        ecx_edx_access = any(reg in ("ecx", "edx") for reg, _ in stack_accesses)
        if ecx_edx_access:
            return CallConvention("fastcall", arch, ["ecx", "edx"], stack_args=True, caller_cleanup=True)
        
        return CallConvention("cdecl", arch, [], stack_args=True, caller_cleanup=True)
    
    elif arch in ("arm", "arm64", "mips", "mipsel"):
        return get_default_convention(arch)
    
    return get_default_convention("x86_64")


def get_default_convention(arch: str) -> CallConvention:
    defaults = {
        "x86_64": ("sysv_amd64", ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]),
        "x86_32": ("cdecl", []),
        "arm": ("aapcs", ["r0", "r1", "r2", "r3"]),
        "arm64": ("aapcs64", ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]),
        "mips": ("o32", ["$a0", "$a1", "$a2", "$a3"]),
        "mipsel": ("o32", ["$a0", "$a1", "$a2", "$a3"]),
    }
    
    name, args = defaults.get(arch, defaults["x86_64"])
    return CallConvention(name, arch, args, stack_args=True, caller_cleanup=True)


def set_function_arguments(emu, convention: CallConvention, *args, sp: int = None):
    for i, arg in enumerate(args):
        if i < len(convention.args):
            emu.set_reg(convention.args[i], arg)
        else:
            if sp is not None:
                offset = i - len(convention.args)
                stack_offset = convention.shadow_space + offset * 8
                emu.mem_write(sp + stack_offset, arg.to_bytes(8, 'little'))


def get_call_convention(name: str, arch: str) -> Optional[CallConvention]:
    arch_convs = CALL_CONVENTIONS.get(arch, {})
    conv_info = arch_convs.get(name)
    if conv_info:
        return CallConvention(name, arch, **conv_info)
    return None


def list_available_conventions(arch: str) -> List[str]:
    return list(CALL_CONVENTIONS.get(arch, {}).keys())
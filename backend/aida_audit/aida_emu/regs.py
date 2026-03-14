from typing import Dict, Optional, Any, List
from enum import Enum

try:
    import unicorn
    from unicorn import x86_const, arm_const, arm64_const, mips_const
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


class Arch(Enum):
    X86_32 = "x86_32"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM_THUMB = "arm_thumb"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPSEL = "mipsel"
    SPARC = "sparc"
    SPARC64 = "sparc64"


class Endian(Enum):
    LITTLE = "little"
    BIG = "big"


REGISTER_MAP: Dict[str, Dict[str, Any]] = {
    "x86_64": {
        "pc": "rip",
        "sp": "rsp",
        "bp": "rbp",
        "ip": "rip",
        "flags": "rflags",
        "args": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        "ret": "rax",
        "ret_high": "rdx",
        "callee_saved": ["rbx", "r12", "r13", "r14", "r15", "rbp", "rsp"],
        "unicorn_arch": unicorn.UC_ARCH_X86,
        "unicorn_mode": unicorn.UC_MODE_64,
    },
    "x86_32": {
        "pc": "eip",
        "sp": "esp",
        "bp": "ebp",
        "ip": "eip",
        "flags": "eflags",
        "args": [],  # cdecl: all on stack
        "ret": "eax",
        "ret_high": "edx",
        "callee_saved": ["ebx", "esi", "edi", "ebp", "esp"],
        "unicorn_arch": unicorn.UC_ARCH_X86,
        "unicorn_mode": unicorn.UC_MODE_32,
    },
    "arm": {
        "pc": "pc",
        "sp": "sp",
        "lr": "lr",
        "args": ["r0", "r1", "r2", "r3"],
        "ret": "r0",
        "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "sp", "lr"],
        "unicorn_arch": unicorn.UC_ARCH_ARM,
        "unicorn_mode": unicorn.UC_MODE_ARM,
    },
    "arm_thumb": {
        "pc": "pc",
        "sp": "sp",
        "lr": "lr",
        "args": ["r0", "r1", "r2", "r3"],
        "ret": "r0",
        "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "sp", "lr"],
        "unicorn_arch": unicorn.UC_ARCH_ARM,
        "unicorn_mode": unicorn.UC_MODE_THUMB,
    },
    "arm64": {
        "pc": "pc",
        "sp": "sp",
        "lr": "x30",
        "args": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        "ret": "x0",
        "callee_saved": ["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "sp", "x29"],
        "unicorn_arch": unicorn.UC_ARCH_ARM64,
        "unicorn_mode": unicorn.UC_MODE_ARM,
    },
    "mips": {
        "pc": "pc",
        "sp": "$sp",
        "ra": "$ra",
        "gp": "$gp",
        "args": ["$a0", "$a1", "$a2", "$a3"],
        "ret": "$v0",
        "ret_high": "$v1",
        "callee_saved": ["$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$sp", "$gp", "$fp"],
        "unicorn_arch": unicorn.UC_ARCH_MIPS,
        "unicorn_mode": unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_BIG_ENDIAN,
    },
    "mipsel": {
        "pc": "pc",
        "sp": "$sp",
        "ra": "$ra",
        "gp": "$gp",
        "args": ["$a0", "$a1", "$a2", "$a3"],
        "ret": "$v0",
        "ret_high": "$v1",
        "callee_saved": ["$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$sp", "$gp", "$fp"],
        "unicorn_arch": unicorn.UC_ARCH_MIPS,
        "unicorn_mode": unicorn.UC_MODE_MIPS32,
    },
    "sparc": {
        "pc": "pc",
        "sp": "sp",
        "fp": "fp",
        "args": ["o0", "o1", "o2", "o3", "o4", "o5"],
        "ret": "o0",
        "callee_saved": ["l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7", "i0", "i1", "i2", "i3", "i4", "i5", "fp", "sp"],
        "unicorn_arch": unicorn.UC_ARCH_SPARC,
        "unicorn_mode": unicorn.UC_MODE_SPARC32,
    },
    "sparc64": {
        "pc": "pc",
        "sp": "sp",
        "fp": "fp",
        "args": ["o0", "o1", "o2", "o3", "o4", "o5"],
        "ret": "o0",
        "callee_saved": ["l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7", "i0", "i1", "i2", "i3", "i4", "i5", "fp", "sp"],
        "unicorn_arch": unicorn.UC_ARCH_SPARC,
        "unicorn_mode": unicorn.UC_MODE_SPARC64,
    },
}


class Regs:
    def __init__(self, uc: Optional["unicorn.Uc"], arch: str, mode: int = 0):
        self.uc = uc
        self.arch = arch
        self.mode = mode
        self._reg_info = REGISTER_MAP.get(arch, REGISTER_MAP["x86_64"])
        self._pc_cache: Optional[int] = None

    @classmethod
    def from_metadata(cls, uc: "unicorn.Uc", metadata: dict) -> "Regs":
        arch_str = metadata.get("arch", "64-bit").lower()
        processor = metadata.get("processor", "").lower()
        
        if "64-bit" in arch_str:
            if "x86" in processor or "amd64" in processor or "x86_64" in processor or "x64" in processor:
                arch = "x86_64"
            elif "aarch64" in processor or "arm64" in processor:
                arch = "arm64"
            else:
                arch = "x86_64"
        else:
            if "arm" in processor:
                arch = "arm"
            elif "mips" in processor:
                arch = "mips"
            elif "sparc" in processor:
                arch = "sparc"
            else:
                arch = "x86_32"
        
        is_be = metadata.get("endian", "").lower() == "big endian"
        if arch in ["mips"] and is_be:
            pass
        elif arch in ["mipsel"] or (arch == "mips" and not is_be):
            arch = "mipsel"
        
        return cls(uc, arch)

    @property
    def pc_name(self) -> str:
        return self._reg_info.get("pc", "pc")

    @property
    def sp_name(self) -> str:
        return self._reg_info.get("sp", "sp")

    def get_pc(self) -> Optional[int]:
        if self.uc:
            return self.uc.reg_read(self._get_uc_reg(self.pc_name))
        return self._pc_cache

    def set_pc(self, value: int):
        if self.uc:
            self.uc.reg_write(self._get_uc_reg(self.pc_name), value)
        self._pc_cache = value

    def get_sp(self) -> Optional[int]:
        if self.uc:
            return self.uc.reg_read(self._get_uc_reg(self.sp_name))
        return None

    def set_sp(self, value: int):
        if self.uc:
            self.uc.reg_write(self._get_uc_reg(self.sp_name), value)

    def get_reg(self, name: str) -> Optional[int]:
        if self.uc:
            return self.uc.reg_read(self._get_uc_reg(name))
        return None

    def set_reg(self, name: str, value: int):
        if self.uc:
            self.uc.reg_write(self._get_uc_reg(name), value)

    def get_args(self) -> List[str]:
        return self._reg_info.get("args", [])

    def get_ret(self) -> str:
        return self._reg_info.get("ret", "rax")

    def get_ret_value(self, signed: bool = False) -> Optional[int]:
        value = self.get_reg(self.get_ret())
        if signed and value is not None:
            if self.arch in ("x86_64", "x86_32"):
                bits = 32
                value = self._to_signed(value, bits)
        return value
    
    def _to_signed(self, value: int, bits: int) -> int:
        if bits == 64:
            if value >= 0x8000000000000000:
                return value - 0x10000000000000000
        elif bits == 32:
            low_32 = value & 0xFFFFFFFF
            if low_32 >= 0x80000000:
                return low_32 - 0x100000000
            return low_32
        elif bits == 16:
            if value >= 0x8000:
                return value - 0x10000
        elif bits == 8:
            if value >= 0x80:
                return value - 0x100
        return value

    def set_ret_value(self, value: int):
        self.set_reg(self.get_ret(), value)

    def get_arg(self, index: int) -> Optional[int]:
        args = self.get_args()
        if index < len(args):
            return self.get_reg(args[index])
        return None

    def set_arg(self, index: int, value: int):
        args = self.get_args()
        if index < len(args):
            self.set_reg(args[index], value)

    def set_args(self, *args):
        for i, arg in enumerate(args):
            self.set_arg(i, arg)

    def get_all_gprs(self) -> Dict[str, int]:
        if not self.uc:
            return {}
        
        gpr_names = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "eip", "rip"
        ] if self.arch == "x86_64" else [
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            "eip"
        ] if self.arch == "x86_32" else []
        
        result = {}
        for name in gpr_names:
            try:
                result[name] = self.uc.reg_read(self._get_uc_reg(name))
            except:
                pass
        return result

    def _get_uc_reg(self, name: str) -> int:
        if not UNICORN_AVAILABLE:
            return 0
        
        reg_map = {
            "x86_64": {
                "rax": x86_const.UC_X86_REG_RAX, "rbx": x86_const.UC_X86_REG_RBX,
                "rcx": x86_const.UC_X86_REG_RCX, "rdx": x86_const.UC_X86_REG_RDX,
                "rsi": x86_const.UC_X86_REG_RSI, "rdi": x86_const.UC_X86_REG_RDI,
                "rbp": x86_const.UC_X86_REG_RBP, "rsp": x86_const.UC_X86_REG_RSP,
                "rip": x86_const.UC_X86_REG_RIP, "rflags": x86_const.UC_X86_REG_RFLAGS,
                "r8": x86_const.UC_X86_REG_R8, "r9": x86_const.UC_X86_REG_R9,
                "r10": x86_const.UC_X86_REG_R10, "r11": x86_const.UC_X86_REG_R11,
                "r12": x86_const.UC_X86_REG_R12, "r13": x86_const.UC_X86_REG_R13,
                "r14": x86_const.UC_X86_REG_R14, "r15": x86_const.UC_X86_REG_R15,
            },
            "x86_32": {
                "eax": x86_const.UC_X86_REG_EAX, "ebx": x86_const.UC_X86_REG_EBX,
                "ecx": x86_const.UC_X86_REG_ECX, "edx": x86_const.UC_X86_REG_EDX,
                "esi": x86_const.UC_X86_REG_ESI, "edi": x86_const.UC_X86_REG_EDI,
                "ebp": x86_const.UC_X86_REG_EBP, "esp": x86_const.UC_X86_REG_ESP,
                "eip": x86_const.UC_X86_REG_EIP, "eflags": x86_const.UC_X86_REG_EFLAGS,
            },
            "arm": {
                "pc": arm_const.UC_ARM_REG_PC, "sp": arm_const.UC_ARM_REG_SP,
                "lr": arm_const.UC_ARM_REG_LR, "r0": arm_const.UC_ARM_REG_R0,
                "r1": arm_const.UC_ARM_REG_R1, "r2": arm_const.UC_ARM_REG_R2,
                "r3": arm_const.UC_ARM_REG_R3, "r4": arm_const.UC_ARM_REG_R4,
                "r5": arm_const.UC_ARM_REG_R5, "r6": arm_const.UC_ARM_REG_R6,
                "r7": arm_const.UC_ARM_REG_R7, "r8": arm_const.UC_ARM_REG_R8,
                "r9": arm_const.UC_ARM_REG_R9, "r10": arm_const.UC_ARM_REG_R10,
                "r11": arm_const.UC_ARM_REG_R11, "r12": arm_const.UC_ARM_REG_R12,
                "fp": arm_const.UC_ARM_REG_R11, "ip": arm_const.UC_ARM_REG_R12,
            },
            "arm64": {
                "pc": arm64_const.UC_ARM64_REG_PC, "sp": arm64_const.UC_ARM64_REG_SP,
                "x0": arm64_const.UC_ARM64_REG_X0, "x1": arm64_const.UC_ARM64_REG_X1,
                "x2": arm64_const.UC_ARM64_REG_X2, "x3": arm64_const.UC_ARM64_REG_X3,
                "x4": arm64_const.UC_ARM64_REG_X4, "x5": arm64_const.UC_ARM64_REG_X5,
                "x6": arm64_const.UC_ARM64_REG_X6, "x7": arm64_const.UC_ARM64_REG_X7,
                "x8": arm64_const.UC_ARM64_REG_X8, "x9": arm64_const.UC_ARM64_REG_X9,
                "x10": arm64_const.UC_ARM64_REG_X10, "x11": arm64_const.UC_ARM64_REG_X11,
                "x12": arm64_const.UC_ARM64_REG_X12, "x13": arm64_const.UC_ARM64_REG_X13,
                "x14": arm64_const.UC_ARM64_REG_X14, "x15": arm64_const.UC_ARM64_REG_X15,
                "x16": arm64_const.UC_ARM64_REG_X16, "x17": arm64_const.UC_ARM64_REG_X17,
                "x18": arm64_const.UC_ARM64_REG_X18, "x19": arm64_const.UC_ARM64_REG_X19,
                "x20": arm64_const.UC_ARM64_REG_X20, "x21": arm64_const.UC_ARM64_REG_X21,
                "x22": arm64_const.UC_ARM64_REG_X22, "x23": arm64_const.UC_ARM64_REG_X23,
                "x24": arm64_const.UC_ARM64_REG_X24, "x25": arm64_const.UC_ARM64_REG_X25,
                "x26": arm64_const.UC_ARM64_REG_X26, "x27": arm64_const.UC_ARM64_REG_X27,
                "x28": arm64_const.UC_ARM64_REG_X28, "x29": arm64_const.UC_ARM64_REG_X29,
                "x30": arm64_const.UC_ARM64_REG_X30,
            },
            "mips": {
                "pc": mips_const.UC_MIPS_REG_PC, "sp": mips_const.UC_MIPS_REG_SP,
                "$sp": mips_const.UC_MIPS_REG_SP, "$ra": mips_const.UC_MIPS_REG_RA,
                "$gp": mips_const.UC_MIPS_REG_GP, "$a0": mips_const.UC_MIPS_REG_A0,
                "$a1": mips_const.UC_MIPS_REG_A1, "$a2": mips_const.UC_MIPS_REG_A2,
                "$a3": mips_const.UC_MIPS_REG_A3, "$v0": mips_const.UC_MIPS_REG_V0,
                "$v1": mips_const.UC_MIPS_REG_V1,
            },
            "mipsel": {
                "pc": mips_const.UC_MIPS_REG_PC, "sp": mips_const.UC_MIPS_REG_SP,
                "$sp": mips_const.UC_MIPS_REG_SP, "$ra": mips_const.UC_MIPS_REG_RA,
                "$gp": mips_const.UC_MIPS_REG_GP, "$a0": mips_const.UC_MIPS_REG_A0,
                "$a1": mips_const.UC_MIPS_REG_A1, "$a2": mips_const.UC_MIPS_REG_A2,
                "$a3": mips_const.UC_MIPS_REG_A3, "$v0": mips_const.UC_MIPS_REG_V0,
                "$v1": mips_const.UC_MIPS_REG_V1,
            },
        }
        
        return reg_map.get(self.arch, {}).get(name, 0)

    def get_unicorn_arch_mode(self):
        info = self._reg_info
        return info.get("unicorn_arch", unicorn.UC_ARCH_X86), info.get("unicorn_mode", unicorn.UC_MODE_64)
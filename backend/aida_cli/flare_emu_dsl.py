import logging
import struct
from .flare_emu import EmuHelper

logger = logging.getLogger(__name__)

class DSLRunner:
    def __init__(self, emu_helper):
        self.eh = emu_helper
        self.variables = {}  # Store variables for reuse across steps (e.g., allocated pointers)

    def run(self, scenario):
        """
        Run a full scenario defined by the DSL.
        scenario: dict containing 'name', 'steps', etc.
        """
        logger.info(f"Running scenario: {scenario.get('name', 'Unnamed')}")
        steps = scenario.get("steps", [])
        
        for i, step in enumerate(steps):
            step_type = step.get("type")
            logger.info(f"Executing step {i+1}: {step_type}")
            
            if step_type == "call":
                self._handle_call(step)
            elif step_type == "emulate":
                self._handle_emulate(step)
            elif step_type == "write":
                self._handle_write(step)
            elif step_type == "assert":
                self._handle_assert(step)
            elif step_type == "alloc":
                self._handle_alloc(step)
            else:
                logger.warning(f"Unknown step type: {step_type}")

    def _resolve_value(self, val):
        """
        Resolve value from variables, strings, or hex strings.
        """
        if isinstance(val, str):
            if val.startswith("$"):
                var_name = val[1:]
                if var_name in self.variables:
                    return self.variables[var_name]
                else:
                    raise ValueError(f"Undefined variable: {var_name}")
            elif val.startswith("0x") or val.startswith("-0x"):
                try:
                    return int(val, 16)
                except ValueError:
                    pass
            # Try to resolve as symbol/function name
            addr = self.eh.analysisHelper.getNameAddr(val)
            if addr is not None:
                return addr
                
        return val

    def _handle_alloc(self, step):
        """
        Alloc memory and store pointer in variable.
        Format: {type: alloc, size: 100, var: "ptr1"}
        or {type: alloc, content: "hello", var: "str1"}
        """
        size = step.get("size")
        content = step.get("content")
        var_name = step.get("var")
        
        if content is not None:
            if isinstance(content, str):
                content = content.encode("utf-8") + b"\x00"
            size = len(content)
            addr = self.eh.allocEmuMem(size)
            self.eh.writeEmuMem(addr, content)
        elif size is not None:
            addr = self.eh.allocEmuMem(size)
        else:
            raise ValueError("Alloc step requires size or content")
            
        if var_name:
            self.variables[var_name] = addr
            logger.info(f"Allocated {size} bytes at {hex(addr)} -> ${var_name}")

    def _handle_write(self, step):
        """
        Write to registers or memory.
        """
        registers = step.get("registers", {})
        for reg, val in registers.items():
            val = self._resolve_value(val)
            self.eh.uc.reg_write(self.eh.regs[reg], val)
            logger.info(f"Wrote {hex(val)} to {reg}")
            
        memory = step.get("memory", [])
        for mem_op in memory:
            addr = self._resolve_value(mem_op.get("addr"))
            data = mem_op.get("data")
            if isinstance(data, str):
                # Check for hex prefix
                if data.startswith("hex:"):
                    data = bytes.fromhex(data[4:])
                else:
                    data = data.encode("utf-8")
            self.eh.writeEmuMem(addr, data)
            logger.info(f"Wrote {len(data)} bytes to {hex(addr)}")

    def _prepare_args(self, args):
        """
        Prepare arguments for function call.
        Similar to test_runner logic but integrated.
        """
        real_args = []
        for arg in args:
            val = arg
            if isinstance(arg, dict):
                type_ = arg.get("type", "int")
                val_raw = arg.get("value")
                
                if type_ == "string":
                    if isinstance(val_raw, str):
                        val_raw = val_raw.encode("utf-8") + b"\x00"
                    mem = self.eh.allocEmuMem(len(val_raw))
                    self.eh.writeEmuMem(mem, val_raw)
                    val = mem
                elif type_ == "bytes":
                    if isinstance(val_raw, str):
                        val_raw = val_raw.encode("utf-8")
                    mem = self.eh.allocEmuMem(len(val_raw))
                    self.eh.writeEmuMem(mem, val_raw)
                    val = mem
                elif type_ == "ptr":
                    # Pointer to existing variable or address
                    val = self._resolve_value(val_raw)
                else:
                    # Default to int/value
                    val = self._resolve_value(val_raw)
            else:
                val = self._resolve_value(val)
            
            real_args.append(val)
        return real_args

    def _setup_call_context(self, args, convention=None):
        """
        Setup registers and stack for function call.
        """
        arch = self.eh.analysisHelper.getArch()
        bitness = self.eh.analysisHelper.getBitness()
        registers = {}
        stack = []
        
        # Simple ABI detection logic
        if arch == "X86":
            if bitness == 64:
                # Assuming Windows x64 or System V based on file type or explicit config
                # Defaulting to behavior in test_runner.py for now
                ftype = self.eh.analysisHelper.getFileType()
                is_pe = ftype == "PE"
                
                if convention == "ms64" or (convention is None and is_pe):
                    regs = ["rcx", "rdx", "r8", "r9"]
                    stack = [0] * 4 # Shadow space
                    for i, arg in enumerate(args):
                        if i < 4: registers[regs[i]] = arg
                        else: stack.append(arg)
                else:
                    # System V AMD64
                    regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
                    for i, arg in enumerate(args):
                        if i < 6: registers[regs[i]] = arg
                        else: stack.append(arg)
                        
                stack.insert(0, 0xDEADBEEF) # Return addr
            else:
                # x86 cdecl / stdcall
                # For now assuming cdecl (caller cleans up) or stdcall (callee cleans up)
                # But for emulation setup, we just push args.
                for arg in reversed(args):
                    stack.append(arg)
                stack.insert(0, 0xDEADBEEF)
        
        elif arch == "ARM":
            # R0-R3, stack
            regs = ["r0", "r1", "r2", "r3"]
            for i, arg in enumerate(args):
                if i < 4: registers[regs[i]] = arg
                else: stack.append(arg)
            registers["lr"] = 0xDEADBEEF

        return registers, stack

    def _setup_hooks(self, hooks_config, user_data):
        """
        Setup hooks for emulation.
        """
        # We need a way to register hooks that persist or are transient
        # For now, we'll wrap the user hook
        
        def dsl_hook(uc, address, size, user_data):
            # This is a generic hook dispatch
            # We can check address against configured hooks
            for hook in hooks_config:
                hook_addr = self._resolve_value(hook.get("addr"))
                if hook_addr == address:
                    action = hook.get("action")
                    if action == "skip":
                        self.eh.skipInstruction(user_data)
                    elif action == "write_reg":
                        reg = hook.get("register")
                        val = self._resolve_value(hook.get("value"))
                        self.eh.uc.reg_write(self.eh.regs[reg], val)
                    elif action == "read_reg":
                        reg = hook.get("register")
                        var_name = hook.get("var")
                        if var_name:
                            val = self.eh.getRegVal(reg)
                            self.variables[var_name] = val
                            logger.info(f"Hook: Read {reg} = {hex(val)} -> ${var_name}")
                    elif action == "read_mem":
                        # Support resolving address from register or variable
                        addr_val = self._resolve_value(hook.get("addr_read") or hook.get("mem_addr"))
                        # If addr_read is a register name like "esp" or "rsp", we should read that register value first
                        if isinstance(addr_val, str) and addr_val in self.eh.regs:
                            addr_val = self.eh.getRegVal(addr_val)
                            
                        size = hook.get("size")
                        var_name = hook.get("var")
                        if var_name and addr_val and size:
                            val = self.eh.getEmuBytes(addr_val, size)
                            self.variables[var_name] = val
                            logger.info(f"Hook: Read {size} bytes from {hex(addr_val)} -> ${var_name}")
                    elif action == "stop":
                        self.eh.stopEmulation(user_data)
        
        return dsl_hook

    def _handle_call(self, step):
        target = step.get("target") or step.get("function")
        addr = self._resolve_value(target)
        if addr is None:
            raise ValueError(f"Function/Target not found: {target}")
            
        args = self._prepare_args(step.get("args", []))
        convention = step.get("convention")
        
        registers, stack = self._setup_call_context(args, convention)
        
        # Handle hooks
        hooks_config = step.get("hooks", [])
        instr_hook = None
        if hooks_config:
            instr_hook = self._setup_hooks(hooks_config, {})
            
        self.eh.emulateRange(addr, registers=registers, stack=stack, instructionHook=instr_hook)
        
        # Store return value if requested
        ret_var = step.get("return_var")
        if ret_var:
            arch = self.eh.analysisHelper.getArch()
            bitness = self.eh.analysisHelper.getBitness()
            reg_name = "eax"
            if arch == "X86" and bitness == 64:
                reg_name = "rax"
            elif arch == "ARM":
                reg_name = "r0"
            
            val = self.eh.getRegVal(reg_name)
            self.variables[ret_var] = val
            logger.info(f"Return value {hex(val)} stored in ${ret_var}")

    def _handle_emulate(self, step):
        start = self._resolve_value(step.get("start"))
        end = self._resolve_value(step.get("end"))
        count = step.get("count", 0)
        
        if start is None:
             raise ValueError("Emulate step requires start address")
             
        registers = step.get("registers")
        stack = step.get("stack")
        
        hooks_config = step.get("hooks", [])
        instr_hook = None
        if hooks_config:
            instr_hook = self._setup_hooks(hooks_config, {})
            
        self.eh.emulateRange(start, endAddr=end, registers=registers, stack=stack, count=count, instructionHook=instr_hook)

    def _handle_assert(self, step):
        checks = step.get("checks", [])
        for check in checks:
            type_ = check.get("type", "register")
            
            if type_ == "register":
                reg = check.get("register") or check.get("name")
                expected = self._resolve_value(check.get("value"))
                actual = self.eh.getRegVal(reg)
                
                # Handle simple signed/unsigned assumption for x86 return values like -1
                if expected < 0:
                     # This is a bit rough, but handles common cases
                     pass 
                
                if actual != expected:
                    # Try to handle signed comparison for 64-bit negatives
                    if actual > 0x7FFFFFFFFFFFFFFF:
                         actual_signed = actual - 0x10000000000000000
                         if actual_signed == expected:
                             logger.info(f"Assert Passed (Signed): {reg} == {expected}")
                             continue

                    raise AssertionError(f"Register {reg} mismatch: expected {hex(expected)}, got {hex(actual)}")
                else:
                    logger.info(f"Assert Passed: {reg} == {hex(expected)}")
            
            elif type_ == "variable":
                var_name = check.get("name")
                if var_name not in self.variables:
                    raise ValueError(f"Variable {var_name} not found")
                
                actual = self.variables[var_name]
                expected = self._resolve_value(check.get("value"))
                
                if actual != expected:
                    raise AssertionError(f"Variable {var_name} mismatch: expected {expected}, got {actual}")
                else:
                    logger.info(f"Assert Passed: ${var_name} == {expected}")

            elif type_ == "memory":
                addr = self._resolve_value(check.get("addr"))
                content = check.get("content")
                if isinstance(content, str):
                    if content.startswith("hex:"):
                        content = bytes.fromhex(content[4:])
                    else:
                        content = content.encode("utf-8")
                
                actual = self.eh.getEmuBytes(addr, len(content))
                if actual != content:
                    raise AssertionError(f"Memory mismatch at {hex(addr)}: expected {content}, got {actual}")
                else:
                    logger.info(f"Assert Passed: Memory at {hex(addr)} matches")

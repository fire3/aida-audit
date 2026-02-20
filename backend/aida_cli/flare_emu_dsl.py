import logging
import struct
import json
import time
import re
from .flare_emu import EmuHelper

logger = logging.getLogger(__name__)

class DSLRunner:
    def __init__(self, emu_helper):
        self.eh = emu_helper
        self.variables = {}  # Store variables for reuse across steps
        # Analysis data
        self.coverage_data = set() # Set of executed addresses
        self.trace_log = [] # List of trace events
        self.crash_context = None # Context if crash occurs
        self.features = {
            "coverage": False,
            "trace": False,
            "trace_mem": False
        }

    def run(self, scenario):
        """
        Run a full scenario defined by the DSL.
        scenario: dict containing 'name', 'steps', etc.
        """
        logger.info(f"Running scenario: {scenario.get('name', 'Unnamed')}")
        
        # Configure features
        options = scenario.get("options", {})
        self.features.update(options)
        
        steps = scenario.get("steps", [])
        
        try:
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
                elif step_type == "report":
                    self._handle_report(step)
                else:
                    logger.warning(f"Unknown step type: {step_type}")
                    
        except Exception as e:
            # Capture context on crash/exception if not already captured
            if not self.crash_context:
                self._capture_crash_context(e)
            raise e

    def _capture_crash_context(self, exception):
        """Capture emulator state when an error occurs"""
        ctx = {
            "exception": str(exception),
            "registers": {},
            "stack_top": []
        }
        
        # Capture registers based on arch
        try:
            arch = self.eh.analysisHelper.getArch()
            regs_to_dump = []
            if arch == "X86":
                if self.eh.analysisHelper.getBitness() == 64:
                    regs_to_dump = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
                else:
                    regs_to_dump = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]
            elif arch == "ARM":
                regs_to_dump = [f"r{i}" for i in range(13)] + ["sp", "lr", "pc"]
                
            for reg in regs_to_dump:
                ctx["registers"][reg] = hex(self.eh.getRegVal(reg))
                
            # Capture stack top (16 words)
            sp_val = self.eh.getRegVal("rsp" if arch == "X86" and self.eh.analysisHelper.getBitness() == 64 else "esp" if arch == "X86" else "sp")
            stack_data = self.eh.getEmuBytes(sp_val, 16 * 8) # generous read
            # Just hex dump it roughly
            ctx["stack_top"] = stack_data.hex()
            
        except Exception as capture_err:
            ctx["capture_error"] = str(capture_err)
            
        self.crash_context = ctx
        logger.error(f"Crash Context Captured: {json.dumps(ctx, indent=2)}")

    def _trace_hook(self, uc, address, size, user_data):
        """Hook for code execution tracing and coverage"""
        if self.features["coverage"]:
            self.coverage_data.add(address)
            
        if self.features["trace"]:
            # Log execution trace (can be verbose!)
            # Maybe restrict to basic blocks? For now instruction level if enabled
            self.trace_log.append({
                "type": "exec",
                "addr": hex(address),
                "size": size
            })
            
    def _mem_trace_hook(self, uc, access, address, size, value, user_data):
        """Hook for memory access tracing"""
        if self.features["trace_mem"]:
            # 16 = READ, 17 = WRITE (Unicorn constants mapping)
            # Actually unicorn exposes constants, but let's just log type
            access_type = "READ" if access == 16 else "WRITE"
            self.trace_log.append({
                "type": "mem",
                "access": access_type,
                "addr": hex(address),
                "size": size,
                "val": hex(value)
            })

    def _setup_analysis_hooks(self):
        """Setup internal hooks for analysis if features enabled"""
        # We need to add these hooks to unicorn instance
        # Flare-emu manages hooks, so we should be careful not to conflict
        # But we can add our own raw unicorn hooks
        
        import unicorn
        
        if self.features["coverage"] or self.features["trace"]:
            self.eh.uc.hook_add(unicorn.UC_HOOK_CODE, self._trace_hook)
            
        if self.features["trace_mem"]:
            self.eh.uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, self._mem_trace_hook)

    def _handle_report(self, step):
        """Output analysis report"""
        report_file = step.get("file")
        report_type = step.get("format", "json")
        
        report = {
            "coverage_count": len(self.coverage_data),
            "trace_events": len(self.trace_log),
            "crash_context": self.crash_context,
            "coverage_addresses": [hex(x) for x in sorted(list(self.coverage_data))],
            # "trace_log": self.trace_log # Optional, can be huge
        }
        
        if step.get("include_trace", False):
            report["trace_log"] = self.trace_log
            
        content = ""
        if report_type == "json":
            content = json.dumps(report, indent=2)
        else:
            content = f"Coverage: {len(self.coverage_data)} instructions\n"
            if self.crash_context:
                content += f"CRASH DETECTED: {self.crash_context['exception']}\n"
                
        if report_file:
            with open(report_file, "w") as f:
                f.write(content)
            logger.info(f"Report written to {report_file}")
        else:
            logger.info(f"Analysis Report:\n{content}")

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
        
        # Setup internal analysis hooks first if needed
        self._setup_analysis_hooks()
        
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
        
        # Setup internal analysis hooks first if needed
        self._setup_analysis_hooks()
        
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

class TextDSLParser:
    def __init__(self):
        self.lines = []
        self.current_line = 0

    def parse(self, text):
        self.lines = [line.strip() for line in text.splitlines()]
        self.current_line = 0
        scenario = {"name": "TextDSL", "steps": [], "options": {}}
        
        while self.current_line < len(self.lines):
            line = self.lines[self.current_line]
            self.current_line += 1
            
            if not line or line.startswith("#"):
                continue
                
            # Parse directives
            if line.startswith("option "):
                self._parse_option(line, scenario["options"])
            elif " = alloc(" in line:
                scenario["steps"].append(self._parse_alloc(line))
            elif line.startswith("write "):
                scenario["steps"].append(self._parse_write(line))
            elif line.startswith("call ") or " = call " in line:
                scenario["steps"].append(self._parse_call(line))
            elif line.startswith("emulate "):
                scenario["steps"].append(self._parse_emulate(line))
            elif line.startswith("assert "):
                scenario["steps"].append(self._parse_assert(line))
            elif line.startswith("report "):
                scenario["steps"].append(self._parse_report(line))
            else:
                logger.warning(f"Unknown DSL line: {line}")
                
        return scenario

    def _parse_value(self, val_str):
        val_str = val_str.strip()
        if val_str.startswith('"') and val_str.endswith('"'):
            return val_str[1:-1]
        if val_str.startswith('$'):
            return val_str # Keep var syntax for runner
        if val_str.startswith('hex"'):
            return "hex:" + val_str[4:-1]
        try:
            if val_str.startswith("0x") or val_str.startswith("-0x"):
                return int(val_str, 16)
            return int(val_str)
        except ValueError:
            return val_str # Return as string (symbol name)

    def _parse_option(self, line, options):
        # option key = value
        match = re.match(r"option\s+(\w+)\s*=?\s*(.+)", line)
        if match:
            key = match.group(1)
            val = match.group(2)
            if val.lower() == "true": val = True
            elif val.lower() == "false": val = False
            options[key] = val

    def _parse_alloc(self, line):
        # $var = alloc(content)
        match = re.match(r"(\$\w+)\s*=\s*alloc\((.+)\)", line)
        if not match:
            raise ValueError(f"Invalid alloc syntax: {line}")
        var_name = match.group(1)[1:] # strip $
        arg = match.group(2)
        step = {"type": "alloc", "var": var_name}
        
        val = self._parse_value(arg)
        if isinstance(val, int):
            step["size"] = val
        else:
            step["content"] = val
        return step

    def _parse_write(self, line):
        # write reg.eax = 1
        # write mem[$p] = "val"
        step = {"type": "write"}
        if line.startswith("write reg."):
            match = re.match(r"write reg\.(\w+)\s*=\s*(.+)", line)
            if match:
                step["registers"] = {match.group(1): self._parse_value(match.group(2))}
        elif line.startswith("write mem"):
            match = re.match(r"write mem\[(.+)\]\s*=\s*(.+)", line)
            if match:
                step["memory"] = [{
                    "addr": self._parse_value(match.group(1)),
                    "data": self._parse_value(match.group(2))
                }]
        return step

    def _parse_call(self, line):
        # $res = call func(a, b) { ... }
        # call func(a, b)
        ret_var = None
        if " = call " in line:
            parts = line.split(" = call ")
            ret_var = parts[0].strip()[1:]
            call_part = parts[1]
        else:
            call_part = line[5:] # strip "call "
            
        # Check for block start
        has_block = False
        if call_part.strip().endswith("{"):
            has_block = True
            call_part = call_part.rstrip("{").strip()
            
        # Parse func and args
        match = re.match(r"([\w\.]+)\((.*)\)", call_part)
        if not match:
             # Maybe no args? call func
             match = re.match(r"([\w\.]+)", call_part)
             func_name = match.group(1)
             args_str = ""
        else:
            func_name = match.group(1)
            args_str = match.group(2)
            
        args = []
        if args_str:
            # Simple split by comma, ignoring quotes? 
            # A robust split needed for "a,b", 1
            # For simplicity assuming no commas in strings for now or simple args
            raw_args = [x.strip() for x in args_str.split(",")]
            for raw in raw_args:
                if not raw: continue
                # Detect type
                if raw.startswith("$"):
                    # Check if it's treated as ptr or value?
                    # In new DSL, variables are passed as is. 
                    # Runner resolves them.
                    # But for strings/bytes alloc logic in JSON runner...
                    # New DSL uses explicit alloc, so just pass value.
                    args.append({"type": "ptr", "value": raw}) # Default to ptr for var? Or let runner handle?
                    # Runner _prepare_args logic:
                    # if dict: ...
                    # else: resolve value
                    # If we pass "$var", runner resolves it to int/addr.
                    # If we want to support implicit string alloc: call func("str")
                    # We can detect quotes.
                elif raw.startswith('"'):
                    # Implicit string alloc
                    args.append({"type": "string", "value": raw[1:-1]})
                else:
                    args.append(self._parse_value(raw))
                    
        step = {
            "type": "call",
            "function": func_name,
            "args": args
        }
        if ret_var:
            step["return_var"] = ret_var
            
        if has_block:
            step["hooks"] = self._parse_hooks_block()
            
        return step

    def _parse_hooks_block(self):
        hooks = []
        while self.current_line < len(self.lines):
            line = self.lines[self.current_line]
            self.current_line += 1
            line = line.strip()
            
            if line == "}":
                break
            
            if line.startswith("hook "):
                # hook <addr> {
                match = re.match(r"hook\s+(.+)\s+\{", line)
                if match:
                    addr = self._parse_value(match.group(1))
                    hook_def = self._parse_single_hook_content()
                    hook_def["addr"] = addr
                    hooks.append(hook_def)
        return hooks

    def _parse_single_hook_content(self):
        hook = {}
        while self.current_line < len(self.lines):
            line = self.lines[self.current_line]
            self.current_line += 1
            line = line.strip()
            
            if line == "}":
                break
                
            if line.startswith("action:"):
                # action: type params...
                parts = line.split(":", 1)[1].strip().split(" ", 1)
                action_type = parts[0]
                rest = parts[1] if len(parts) > 1 else ""
                
                hook["action"] = action_type
                
                if action_type == "write_reg":
                    # reg.name = val
                    m = re.match(r"reg\.(\w+)\s*=\s*(.+)", rest)
                    if m:
                        hook["register"] = m.group(1)
                        hook["value"] = self._parse_value(m.group(2))
                elif action_type == "read_reg":
                    # reg.name -> $var
                    m = re.match(r"reg\.(\w+)\s*->\s*\$(\w+)", rest)
                    if m:
                        hook["register"] = m.group(1)
                        hook["var"] = m.group(2)
                elif action_type == "read_mem":
                    # mem[addr] size=N -> $var
                    # Regex is getting complex, do simple split
                    # expected: mem[...] size=... -> ...
                    m = re.match(r"mem\[(.+)\]\s+size=(\d+)\s*->\s*\$(\w+)", rest)
                    if m:
                        hook["addr_read"] = self._parse_value(m.group(1))
                        hook["size"] = int(m.group(2))
                        hook["var"] = m.group(3)
        return hook

    def _parse_assert(self, line):
        # assert $var == val
        # assert reg.x == val
        # assert mem[x] == val
        line = line[7:].strip() # strip assert
        
        check = {}
        # Split by ==
        parts = line.split("==")
        lhs = parts[0].strip()
        rhs = self._parse_value(parts[1].strip())
        
        check["value"] = rhs # or content
        
        if lhs.startswith("$"):
            check["type"] = "variable"
            check["name"] = lhs[1:]
        elif lhs.startswith("reg."):
            check["type"] = "register"
            check["name"] = lhs[4:]
        elif lhs.startswith("mem["):
            check["type"] = "memory"
            check["addr"] = self._parse_value(lhs[4:-1])
            check["content"] = rhs # Reuse value field for content? Runner expects content
            del check["value"]
            check["content"] = rhs
            
        return {"type": "assert", "checks": [check]}

    def _parse_report(self, line):
        # report "file" [include_trace=true]
        parts = line[7:].split()
        filename = self._parse_value(parts[0])
        step = {"type": "report", "file": filename}
        
        for p in parts[1:]:
            if "include_trace=true" in p:
                step["include_trace"] = True
        return step

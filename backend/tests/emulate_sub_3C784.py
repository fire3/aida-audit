#!/usr/bin/env python3
"""
Complete emulation script for sub_3C784 function from upnpd binary.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aida_cli.aida_emu import AidaEmulator


def main():
    db_path = "tests/upnpd.db"
    
    print(f"Loading database: {db_path}")
    emu = AidaEmulator.from_database(db_path)
    emu.setup_stack()
    emu.setup_heap()
    
    func = emu.db.load_function(0x3C784)
    if not func:
        print("Function sub_3C784 not found!")
        emu.close()
        return
    
    print(f"Function: {func['name']} at 0x{func['va']:x}")
    
    # Enable libc hooks (auto-handle registered libc functions)
    emu.enable_libc_hooks()

    # Print PLT/GOT map
    if hasattr(emu, '_plt_got_map'):
        print(f"\nPLT/GOT map (sample):")
        for i, (name, addr) in enumerate(list(emu._plt_got_map.items())[:10]):
            print(f"  {name}: 0x{addr:x}")

    # Print some info about external hooks
    print(f"\nExternal hooks map (sample):")
    for i, (addr, name) in enumerate(list(emu._external_hooks_map.items())[:10]):
        print(f"  0x{addr:x}: {name}")
    
    # Initialize global variables
    emu.mem.write_u32(0x908ec, 0)
    emu.mem.write_u32(0x90904, 0)
    emu.mem.write_u32(0x90b68, 0)
    emu.mem.write_u32(0x90b4c, 0)
    emu.mem.write_u32(0x90b44, 0)
    emu.mem.write_u32(0x90910, 0)
    emu.mem.write_u32(0x9f044, 0)
    
    for addr in [0xc1214, 0xc1218, 0xc121c, 0xc1220]:
        emu.mem.write_u32(addr, 0)
    
    print("Initialized global variables")
    
    # Verify literal pool
    print(f"\nVerifying literal pool:")
    for addr in [0x3f278, 0x3f27c]:
        val = emu.uc.mem_read(addr, 4)
        print(f"  0x{addr:05x}: 0x{int.from_bytes(val, 'little'):08x}")
    
    instruction_count = [0]
    
    def code_hook(emu, address, size, user_data):
        instruction_count[0] += 1

        # Only show instructions in the function and the called function
        if instruction_count[0] <= 120:
            try:
                code = emu.uc.mem_read(address, size)
                print(f"  0x{address:05x}: {code[:size].hex()}")

                # Show key registers for relevant code
                if address >= 0x3c7b0:
                    r2 = emu.regs.get_reg('r2')
                    r3 = emu.regs.get_reg('r3')
                    r12 = emu.regs.get_reg('r12')
                    lr = emu.regs.get_reg('lr')
                    pc = emu.get_pc()
                    print(f"    r2=0x{r2:08x} r3=0x{r3:08x} r12=0x{r12:08x} lr=0x{lr:08x}")

                # Check for BL instruction - high byte is 0xeb
                if size >= 4:
                    val = int.from_bytes(code[:4], 'little')
                    high_byte = (val >> 24) & 0xff
                    if high_byte == 0xeb:  # BL opcode
                        offset = val & 0x00ffffff
                        if offset & 0x00800000:
                            offset |= 0xff000000
                        target = address + 8 + offset
                        print(f"    *** BL to 0x{target:x}")
                    elif high_byte == 0xea:  # B opcode (unconditional branch)
                        offset = val & 0x00ffffff
                        if offset & 0x00800000:
                            offset |= 0xff000000
                        target = address + 8 + offset
                        print(f"    *** B to 0x{target:x}")
            except Exception as e:
                print(f"    Hook error: {e}")

        return True
    
    emu.hook_code(code_hook)
    
    def mem_hook(emu, access, address, size, value, user_data):
        pc = emu.get_pc()
        sp = emu.regs.get_reg('sp')
        lr = emu.regs.get_reg('lr')
        
        if address == 0:
            print(f"  [MEM] Read from NULL, pc=0x{pc:x}, lr=0x{lr:x}, sp=0x{sp:x}")
            
            # Check if PC is valid
            if pc == 0:
                print("    !!! PC is 0 - execution jumped to NULL address !!!")
                print("    This usually means return address was corrupted or invalid")
                print(f"    LR (return addr) = 0x{lr:x}")
                
                # Check what's at SP
                print(f"    Stack at SP=0x{sp:x}:")
                try:
                    stack_data = emu.uc.mem_read(sp, 32)
                    for i in range(0, 32, 4):
                        val = int.from_bytes(stack_data[i:i+4], 'little')
                        print(f"      SP+{i}: 0x{val:08x}")
                except Exception as e:
                    print(f"      Error reading stack: {e}")
                return True
            
            insn = emu.uc.mem_read(pc, 4)
            insn_val = int.from_bytes(insn[:4], 'little')
            print(f"    Instruction at PC: 0x{insn_val:08x}")
            
            # Decode ARM LDR instruction
            if (insn_val & 0x0c000000) == 0x04000000:
                rn = (insn_val >> 16) & 0xf
                rd = (insn_val >> 12) & 0xf
                offset = insn_val & 0xfff
                print(f"    -> ldr r{rd}, [r{rn}, #{offset}]")
            
            print(f"    Stack dump (16 bytes from SP):")
            try:
                stack_data = emu.uc.mem_read(sp, 16)
                for i in range(0, 16, 4):
                    val = int.from_bytes(stack_data[i:i+4], 'little')
                    print(f"      SP+{i}: 0x{val:08x}")
            except:
                print("      (unable to read)")
            
            r0 = emu.regs.get_reg('r0')
            r1 = emu.regs.get_reg('r1')
            r2 = emu.regs.get_reg('r2')
            r3 = emu.regs.get_reg('r3')
            print(f"    Registers: r0=0x{r0:x} r1=0x{r1:x} r2=0x{r2:x} r3=0x{r3:x}")
            
            # Show call stack (look at stack for return addresses)
            print(f"    Call stack:")
            try:
                for i in range(5):
                    ra = emu.uc.mem_read(sp + i*4, 4)
                    val = int.from_bytes(ra, 'little')
                    if val > 0x10000 and val < 0x200000:
                        print(f"      [{i}] ret_addr = 0x{val:x}")
            except:
                pass
            
            return True
        
        print(f"  [MEM] Unmapped at 0x{address:x}, pc=0x{pc:x}, sp=0x{sp:x}, lr=0x{lr:x}")
        return True
    
    emu.hook_memory(mem_hook, mem_type="unmapped")
    
    test_request = b"POST / HTTP/1.1\r\nSOAPAction: test\r\n\r\n"
    request_ptr = emu.alloc(len(test_request) + 1, test_request + b'\x00')
    
    print(f"\nCalling sub_3C784(0x{request_ptr:x}, 0, 0x7f000001, 0)...")
    
    try:
        result = emu.call(func['va'], request_ptr, 0, 0x7f000001, 0)
        print(f"\nResult: {result}")
    except Exception as e:
        print(f"\nError: {e}")
        print(f"PC: 0x{emu.get_pc():x}")
    
    print(f"\nInstructions: {instruction_count[0]}")
    
    emu.close()


if __name__ == "__main__":
    main()
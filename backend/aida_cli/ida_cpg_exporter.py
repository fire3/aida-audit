import os
import json
import hashlib
import datetime
import time

try:
    import ida_hexrays
    import ida_lines
    import ida_pro
    import ida_nalt
    import ida_segment
    import ida_funcs
    import ida_bytes
    import ida_name
    import ida_entry
    import ida_xref
    import ida_typeinf
    import idautils
    import ida_ida
    import ida_auto
    import ida_range
except ImportError:
    pass

class IDACPGExporter:
    def __init__(self, output_dir, logger):
        self.output_dir = output_dir
        self.log = logger.log
        self.meta = {}
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def _strip_tags(self, s):
        if 'ida_lines' in globals():
            return ida_lines.tag_remove(s)
        return s

    def _get_maturity(self):
        if 'ida_hexrays' in globals():
            return getattr(ida_hexrays, "MMAT_LVARS", ida_hexrays.MMAT_LOCOPT)
        return None

    def _get_maturity_name(self):
        if 'ida_hexrays' in globals() and hasattr(ida_hexrays, "MMAT_LVARS"):
            return "MMAT_LVARS"
        return "MMAT_LOCOPT"

    def _opcode_name(self, opcode):
        if 'ida_hexrays' in globals() and hasattr(ida_hexrays, "get_mcode_name"):
            try:
                return ida_hexrays.get_mcode_name(opcode)
            except Exception:
                pass
        return str(opcode)

    def _mop_embedded_insn(self, mop):
        if mop is None:
            return None
        if hasattr(mop, "t") and hasattr(ida_hexrays, "mop_d") and mop.t == ida_hexrays.mop_d:
            return mop.d
        if hasattr(mop, "insn"):
            return mop.insn
        if hasattr(mop, "f") and hasattr(mop.f, "insn"):
            return mop.f.insn
        return None

    def _insn_bits(self, insn):
        if hasattr(insn, "d") and insn.d and not insn.d.empty():
            return insn.d.size * 8
        if hasattr(insn, "l") and insn.l and not insn.l.empty():
            return insn.l.size * 8
        if hasattr(insn, "r") and insn.r and not insn.r.empty():
            return insn.r.size * 8
        return 0

    def _mop_to_expr_operand(self, mop):
        embedded = self._mop_embedded_insn(mop)
        if embedded:
            return self._insn_to_expr(embedded)
        return self._normalize_operand(mop)

    def _insn_to_expr(self, insn):
        args = []
        if hasattr(insn, "l") and insn.l and not insn.l.empty():
            op = self._mop_to_expr_operand(insn.l)
            if op:
                args.append(op)
        if hasattr(insn, "r") and insn.r and not insn.r.empty():
            op = self._mop_to_expr_operand(insn.r)
            if op:
                args.append(op)
        if hasattr(insn, "d") and insn.d and not insn.d.empty():
            op = self._mop_to_expr_operand(insn.d)
            if op:
                args.append(op)
        return {
            "kind": "expr",
            "bits": self._insn_bits(insn),
            "repr": self._strip_tags(str(insn._print())),
            "v": {
                "op": self._opcode_name(insn.opcode),
                "args": args
            }
        }

    def _collect_reads_from_mop(self, mop, reads, calls, role, index):
        if mop is None or mop.empty():
            return
        embedded = self._mop_embedded_insn(mop)
        if embedded:
            self._collect_reads_from_insn(embedded, reads, calls, False)
            return
        norm = self._normalize_operand(mop)
        if norm:
            reads.append({"role": role, "index": index, "op": norm})

    def _extract_call_args(self, insn):
        args = []
        if hasattr(insn, "r") and insn.r and not insn.r.empty():
            mop = insn.r
            if hasattr(mop, "t") and hasattr(ida_hexrays, "mop_f") and mop.t == ida_hexrays.mop_f and hasattr(mop, "f") and hasattr(mop.f, "args"):
                for a in mop.f.args:
                    op = self._mop_to_expr_operand(a)
                    if op:
                        args.append(op)
            elif hasattr(mop, "args") and isinstance(mop.args, (list, tuple)):
                for a in mop.args:
                    op = self._mop_to_expr_operand(a)
                    if op:
                        args.append(op)
            else:
                op = self._mop_to_expr_operand(mop)
                if op:
                    args.append(op)
        return args

    def _record_call(self, insn, reads, calls):
        callee_name = None
        callee_ea = None
        target = None
        callee_norm = None
        if hasattr(insn, "l") and insn.l and not insn.l.empty():
            callee_norm = self._mop_to_expr_operand(insn.l)
            if insn.l.t == ida_hexrays.mop_v:
                addr = insn.l.g
                callee_ea = f"0x{addr:x}"
                name = ida_name.get_name(addr)
                if name:
                    callee_name = name
            elif hasattr(ida_hexrays, "mop_h") and insn.l.t == ida_hexrays.mop_h:
                callee_name = insn.l.helper
            else:
                target = callee_norm
        kind = "unknown"
        if callee_ea or callee_name:
            kind = "direct"
        elif target:
            kind = "indirect"
        args = self._extract_call_args(insn)
        ret = None
        if hasattr(insn, "d") and insn.d and not insn.d.empty():
            ret = self._normalize_operand(insn.d)
        call_info = {
            "index": len(calls),
            "kind": kind,
            "callee_name": callee_name,
            "callee_ea": callee_ea,
            "target": target,
            "args": args,
            "ret": ret
        }
        calls.append(call_info)
        if callee_norm:
            reads.append({"role": "callee", "index": 0, "op": callee_norm})
        for i, arg in enumerate(args):
            reads.append({"role": "arg", "index": i, "op": arg})

    def _collect_reads_from_insn(self, insn, reads, calls, is_root):
        if 'ida_hexrays' in globals() and ida_hexrays.is_mcode_call(insn.opcode):
            self._record_call(insn, reads, calls)
        if hasattr(insn, "l"):
            self._collect_reads_from_mop(insn.l, reads, calls, "src", 0)
        if hasattr(insn, "r"):
            self._collect_reads_from_mop(insn.r, reads, calls, "src", 1)
        if not is_root and hasattr(insn, "d"):
            self._collect_reads_from_mop(insn.d, reads, calls, "src", 2)

    def export(self):
        self.log("Waiting for auto-analysis to finish...")
        if 'ida_auto' in globals():
            ida_auto.auto_wait()
            
        self.log("Starting CPG JSON export...")
        self.export_meta()
        self.export_functions()
        self.export_imports()
        self.export_exports()
        self.export_strings()
        self.log("CPG JSON export completed.")

    def export_meta(self):
        self.log("Exporting meta.json...")
        
        # Binary ID (SHA256 of input file)
        input_path = ida_nalt.get_input_file_path()
        binary_id = "sha256:unknown"
        if input_path and os.path.exists(input_path):
            sha256 = hashlib.sha256()
            try:
                with open(input_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        sha256.update(chunk)
                binary_id = f"sha256:{sha256.hexdigest()}"
            except Exception as e:
                self.log(f"Error calculating hash: {e}")

        # Arch info
        proc_name = ida_ida.inf_get_procname()
        
        # Bitness
        if ida_pro.IDA_SDK_VERSION >= 900:
             is_64 = ida_ida.inf_is_64bit()
        else:
             is_64 = ida_ida.inf_is_64bit()
             
        bitness = 64 if is_64 else 32
        
        # Endian
        is_be = ida_ida.inf_is_be()
        endian = "big" if is_be else "little"
        
        # Imagebase
        imagebase = f"0x{ida_nalt.get_imagebase():x}"
        
        # Arch mapping (simple heuristic)
        arch = proc_name.lower()
        if arch == "metapc":
            arch = "x86_64" if is_64 else "x86"
        elif "arm" in arch:
             arch = "arm64" if is_64 else "arm"
        
        meta = {
            "binary_id": binary_id,
            "input_path": input_path,
            "arch": arch,
            "endian": endian,
            "bitness": bitness,
            "imagebase": imagebase,
            "ida": {
                "version": str(ida_pro.IDA_SDK_VERSION), # Approximate
                "hexrays": ida_hexrays.init_hexrays_plugin()
            },
            "extractor": {
                "version": "v1",
                "time_utc": datetime.datetime.utcnow().isoformat() + "Z"
            }
        }
        
        with open(os.path.join(self.output_dir, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    def export_functions(self):
        self.log("Exporting functions.jsonl...")
        
        out_path = os.path.join(self.output_dir, "functions.jsonl")
        
        # Initialize Hex-Rays
        hexrays_ok = False
        if 'ida_hexrays' in globals():
            if ida_hexrays.init_hexrays_plugin():
                hexrays_ok = True
            else:
                arch = "unknown"
                if 'ida_ida' in globals():
                    arch = ida_ida.inf_get_procname()
                self.log(f"Hex-Rays available but initialization failed (Arch: {arch}). Microcode will be skipped.")
        else:
             self.log("Hex-Rays module not imported. Microcode will be skipped.")
        
        with open(out_path, "w", encoding="utf-8") as f:
            for func_ea in idautils.Functions():
                func_data = self._process_function(func_ea)
                f.write(json.dumps(func_data) + "\n")

    def _process_function(self, func_ea):
        func_name = ida_funcs.get_func_name(func_ea)
        
        # Basic info
        res = {
            "func_ea": f"0x{func_ea:x}",
            "name": func_name,
            "type_str": None,
            "status": "ok",
            "error": None,
            "microcode": None,
            "decompilation": {
                "pseudocode": None,
                "ea_to_line": None
            }
        }

        # Type string
        tinfo = ida_typeinf.tinfo_t()
        # Try multiple ways to get tinfo
        if ida_nalt.get_tinfo(tinfo, func_ea):
             res["type_str"] = str(tinfo)
        else:
            # Fallback: guess type from function flags/info
            f = ida_funcs.get_func(func_ea)
            if f:
                res["type_str"] = "unknown" # Or try to reconstruct if needed

        # Decompile / Microcode
        try:
            # 1. Generate Microcode (LVARS)
            # Use gen_microcode to get mba at specific maturity
            # Construct mba_ranges_t for the function (handles chunks)
            mbr = ida_hexrays.mba_ranges_t()
            for start, end in idautils.Chunks(func_ea):
                mbr.ranges.push_back(ida_range.range_t(start, end))

            hf = ida_hexrays.hexrays_failure_t()
            # gen_microcode(mba_ranges_t const &, hexrays_failure_t *, mlist_t const *, int, mba_maturity_t)
            mba = ida_hexrays.gen_microcode(
                mbr, 
                hf, 
                None, 
                ida_hexrays.DECOMP_WARNINGS, 
                self._get_maturity()
            )
            
            if mba:
                res["microcode"] = self._extract_microcode(mba)
            else:
                res["status"] = "failed"
                res["error"] = f"gen_microcode failed: {hf.str}"

            # 2. Get Pseudocode (Optional, best effort)
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc:
                    res["decompilation"]["pseudocode"] = str(cfunc)
                    
                    # Generate EA to line mapping
                    ea_to_line = {}
                    # cfunc.get_pseudocode() returns a list of simpleline_t
                    # We can iterate and check ea
                    # Note: str(cfunc) might not perfectly align line numbers with the list
                    # But usually line index in list corresponds to line number
                    
                    pcode = cfunc.get_pseudocode()
                    for line_idx, sline in enumerate(pcode):
                         if sline.ea != ida_ida.BADADDR:
                             ea_to_line[f"0x{sline.ea:x}"] = line_idx + 1 # 1-based line number
                    
                    res["decompilation"]["ea_to_line"] = ea_to_line
                    
            except:
                pass # Ignore pseudocode failures if microcode succeeded
                
        except Exception as e:
            res["status"] = "failed"
            res["error"] = str(e)
            
        return res

    def _extract_microcode(self, mba):
        # mba is mbl_array_t
        # It has blocks (mblock_t)
        
        blocks = []
        cfg_edges = []
        insns = []
        
        # Iterate blocks
        for i in range(mba.qty):
            block = mba.get_mblock(i)
            
            # Block info
            blk_data = {
                "block_id": i,
                "start_ea": f"0x{block.start:x}",
                "end_ea": f"0x{block.end:x}"
            }
            blocks.append(blk_data)
            
            # Edges
            # succs is a list of integers (block ids) or mblock_t objects
            for succ in block.succs():
                succ_id = succ
                if hasattr(succ, "serial"):
                    succ_id = succ.serial
                
                # Determine branch type (simplified)
                branch_type = "unknown"
                if succ_id == i + 1:
                    branch_type = "fallthrough"
                else:
                    branch_type = "true" # Simplified, need more logic for cond/switch
                
                cfg_edges.append({
                    "src_block_id": i,
                    "dst_block_id": succ_id,
                    "branch": branch_type
                })
            
            # Instructions
            # Iterate instructions in block
            # block.head is the first instruction (minsn_t)
            # block.nextb(insn) gets the next
            
            curr = block.head
            insn_idx = 0
            while curr:
                insn_data = self._process_insn(curr, i, insn_idx)
                insns.append(insn_data)
                
                curr = curr.next
                insn_idx += 1
                
        return {
            "maturity": self._get_maturity_name(),
            "blocks": blocks,
            "cfg_edges": cfg_edges,
            "insns": insns
        }

    def _process_insn(self, insn, block_id, insn_idx):
        # insn is minsn_t
        opcode = insn.opcode
        # Get opcode string name if possible, or use int
        # There isn't a direct API to get string for opcode enum in python usually, 
        # but we can try to find a mapping or just use the number for now, 
        # or manually map common ones.
        # However, the design doc example shows "m_call".
        # We might need a map.
        
        reads = []
        writes = []
        calls = []

        if hasattr(insn, "d") and insn.d and not insn.d.empty():
            norm = self._normalize_operand(insn.d)
            if norm:
                writes.append({"role": "dst", "index": 0, "op": norm})

        self._collect_reads_from_insn(insn, reads, calls, True)

        return {
            "block_id": block_id,
            "insn_idx": insn_idx,
            "ea": f"0x{insn.ea:x}",
            "opcode": self._opcode_name(opcode),
            "text": self._strip_tags(str(insn._print())), # Print representation
            "reads": reads,
            "writes": writes,
            "calls": calls
        }

    def _normalize_operand(self, mop):
        # mop is mop_t
        if mop.empty():
            return None
            
        kind = "unknown"
        bits = mop.size * 8
        repr_str = self._strip_tags(str(mop._print()))
        v = {}
        
        if mop.t == ida_hexrays.mop_r: # Register
            kind = "reg"
            # TODO: Get reg name
            reg_name = "r" + str(mop.r) # Placeholder
            v = {"reg": reg_name}
            
        elif mop.t == ida_hexrays.mop_n: # Constant
            kind = "const"
            # mop.nnn is the value object, value is .value
            val = mop.nnn.value
            v = {"value": hex(val)}
            
        elif mop.t == ida_hexrays.mop_S: # Stack
            kind = "stack"
            # mop.s is stkvar_ref_t, has off
            off = mop.s.off
            v = {"base": "fp", "off": off}
        elif hasattr(ida_hexrays, "mop_l") and mop.t == ida_hexrays.mop_l:
            kind = "stack"
            if hasattr(mop, "l") and hasattr(mop.l, "off"):
                v = {"base": "fp", "off": mop.l.off}
            else:
                v = {}
            
        elif mop.t == ida_hexrays.mop_v: # Global
            kind = "global"
            ea = mop.g
            v = {"ea": f"0x{ea:x}", "rva": f"0x{ea - ida_nalt.get_imagebase():x}"}
            
        elif mop.t == ida_hexrays.mop_str: # String
            kind = "string"
            ea = mop.cstr # or similar, depends on API
            v = {"ea": f"0x{ea:x}"} if ea else {}
            
        # ... other types
        
        return {
            "kind": kind,
            "bits": bits,
            "repr": repr_str,
            "v": v
        }

    def export_imports(self):
        self.log("Exporting imports.jsonl...")
        out_path = os.path.join(self.output_dir, "imports.jsonl")
        with open(out_path, "w", encoding="utf-8") as f:
            for i in range(ida_nalt.get_import_module_qty()):
                mod_name = ida_nalt.get_import_module_name(i)
                def cb(ea, name, ordinal):
                    rec = {
                        "name": name,
                        "ea": f"0x{ea:x}",
                        "module": mod_name
                    }
                    f.write(json.dumps(rec) + "\n")
                    return True
                ida_nalt.enum_import_names(i, cb)

    def export_exports(self):
        self.log("Exporting exports.jsonl...")
        out_path = os.path.join(self.output_dir, "exports.jsonl")
        with open(out_path, "w", encoding="utf-8") as f:
            for index, ordinal, ea, name in idautils.Entries():
                rec = {
                    "name": name,
                    "ea": f"0x{ea:x}"
                }
                f.write(json.dumps(rec) + "\n")

    def export_strings(self):
        self.log("Exporting strings.jsonl...")
        out_path = os.path.join(self.output_dir, "strings.jsonl")
        with open(out_path, "w", encoding="utf-8") as f:
            for s in idautils.Strings():
                try:
                    val = str(s)
                    rec = {
                        "ea": f"0x{s.ea:x}",
                        "value": val
                    }
                    f.write(json.dumps(rec) + "\n")
                except:
                    pass

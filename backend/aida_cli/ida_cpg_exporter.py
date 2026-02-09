import os
import json
import hashlib
import datetime
import time
import re

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
    import idaapi
except ImportError:
    pass

MopCollectorVisitor = None
if 'ida_hexrays' in globals():
    class _MopCollectorVisitor(ida_hexrays.mop_visitor_t):
        def __init__(self, exporter):
            ida_hexrays.mop_visitor_t.__init__(self)
            self.exporter = exporter
            self.sub_mops = []
            self.reads = []
            self.writes = []

        def visit_mop(self, mop, type_id, is_target):
            # type_id indicates the role of this mop in the parent instruction/structure
            # is_target is boolean
            norm = self.exporter._normalize_operand(mop)
            if norm:
                # Add role info to the normalized object for this context
                # (We don't modify the norm object itself to keep it pure, but wrap it or just use lists)
                
                self.sub_mops.append({
                    "role_id": type_id,
                    "is_target": is_target,
                    "op": norm
                })
                
                if is_target:
                    self.writes.append(norm)
                else:
                    self.reads.append(norm)
            return 0
    MopCollectorVisitor = _MopCollectorVisitor

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

    def _clean_repr(self, s):
        s = self._strip_tags(s)
        return s

    def _get_maturity_name(self):
        return "MMAT_LVARS"

    def _dump_microcode(self, mba, func_name, func_ea):
        if mba is None:
            return
        for i in range(mba.qty):
            block = mba.get_mblock(i)
            succ_ids = []
            for succ in block.succs():
                succ_id = succ
                if hasattr(succ, "serial"):
                    succ_id = succ.serial
                succ_ids.append(succ_id)
            self.log(f"BLOCK {i} {block.start:x} {block.end:x} succs={succ_ids}")
            curr = block.head
            insn_idx = 0
            while curr:
                text = curr.dstr()
                ea_str = f"{curr.ea:x}" if curr.ea != idaapi.BADADDR else "BADADDR"
                self.log(f"{i}.{insn_idx} [{ea_str}] {text}")
                curr = curr.next
                insn_idx += 1

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
        size = 0
        if hasattr(insn, "d") and insn.d and not insn.d.empty():
            size = insn.d.size
        elif hasattr(insn, "l") and insn.l and not insn.l.empty():
            size = insn.l.size
        elif hasattr(insn, "r") and insn.r and not insn.r.empty():
            size = insn.r.size
            
        if size < 0:
            size = 0
        return size * 8

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
            "repr": self._strip_tags(insn.dstr()),
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
        # 1. Try insn.args (sometimes available in specific maturity levels)
        if hasattr(insn, "args") and insn.args:
            for a in insn.args:
                op = self._mop_to_expr_operand(a)
                if op:
                    args.append(op)
            return args

        # 2. Try to find mop_f (function call info) in operands
        # m_call instructions often store call details in 'd' (destination) or 'l' (left)
        # depending on whether it's an indirect call or direct call, and maturity.
        candidates = []
        if hasattr(insn, "d"): candidates.append(insn.d)
        if hasattr(insn, "l"): candidates.append(insn.l)
        if hasattr(insn, "r"): candidates.append(insn.r)
        
        for mop in candidates:
            if not mop or mop.empty():
                continue
            
            # Check if it is a function call info operand (mop_f)
            if hasattr(mop, "t") and hasattr(ida_hexrays, "mop_f") and mop.t == ida_hexrays.mop_f:
                if hasattr(mop, "f") and hasattr(mop.f, "args"):
                    for a in mop.f.args:
                        op = self._mop_to_expr_operand(a)
                        if op:
                            args.append(op)
                    return args

        # 3. Fallback: if 'r' is present, treat it as a single argument or list
        if hasattr(insn, "r") and insn.r and not insn.r.empty():
            # Avoid duplicating if 'r' was already checked as mop_f (it would be caught above)
            # This is for cases where 'r' is a simple operand (e.g. mop_r) used as an argument
            op = self._mop_to_expr_operand(insn.r)
            if op:
                args.append(op)
        return args

    def _retloc_to_operand(self, retloc):
        if retloc is None:
            return None
        candidate = retloc
        if hasattr(retloc, "arg"):
            candidate = retloc.arg
        if isinstance(candidate, (list, tuple)):
            for item in candidate:
                if hasattr(item, "empty") and not item.empty():
                    op = self._mop_to_expr_operand(item)
                    if op:
                        return op
            return None
        if hasattr(candidate, "empty") and candidate.empty():
            return None
        try:
            return self._mop_to_expr_operand(candidate)
        except Exception:
            return None

    def _extract_call_retloc(self, insn):
        candidates = []
        if hasattr(insn, "d"): candidates.append(insn.d)
        if hasattr(insn, "l"): candidates.append(insn.l)
        if hasattr(insn, "r"): candidates.append(insn.r)
        for mop in candidates:
            if not mop or mop.empty():
                continue
            if hasattr(mop, "t") and hasattr(ida_hexrays, "mop_f") and mop.t == ida_hexrays.mop_f:
                if hasattr(mop, "f") and hasattr(mop.f, "retloc"):
                    op = self._retloc_to_operand(mop.f.retloc)
                    if op:
                        return op
        return None

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
        retloc = self._extract_call_retloc(insn)
        call_info = {
            "index": len(calls),
            "kind": kind,
            "callee_name": callee_name,
            "callee_ea": callee_ea,
            "target": target,
            "args": args,
            "ret": ret,
            "retloc": retloc
        }
        calls.append(call_info)

    def _collect_reads_from_insn(self, insn, reads, calls, is_root):
        is_call = False
        if 'ida_hexrays' in globals() and ida_hexrays.is_mcode_call(insn.opcode):
            is_call = True
            self._record_call(insn, reads, calls)
            
            # Recursively collect reads from arguments
            # 1. Try insn.args
            if hasattr(insn, "args") and insn.args:
                for i, arg in enumerate(insn.args):
                    self._collect_reads_from_mop(arg, reads, calls, "arg", i)
            else:
                # 2. Try mop_f candidates in d, l, r
                candidates = []
                if hasattr(insn, "d"): candidates.append(insn.d)
                if hasattr(insn, "l"): candidates.append(insn.l)
                if hasattr(insn, "r"): candidates.append(insn.r)
                
                found_args = False
                for mop in candidates:
                    if not mop or mop.empty(): continue
                    if hasattr(mop, "t") and hasattr(ida_hexrays, "mop_f") and mop.t == ida_hexrays.mop_f:
                        if hasattr(mop, "f") and hasattr(mop.f, "args"):
                            for i, arg in enumerate(mop.f.args):
                                self._collect_reads_from_mop(arg, reads, calls, "arg", i)
                            found_args = True
                            break
                
                # 3. Fallback to 'r' if not found
                if not found_args and hasattr(insn, "r") and insn.r and not insn.r.empty():
                     # Only if we didn't process it as mop_f above
                     self._collect_reads_from_mop(insn.r, reads, calls, "arg", 0)

        if hasattr(insn, "l"):
            role = "callee" if is_call else "src"
            self._collect_reads_from_mop(insn.l, reads, calls, role, 0)

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
        self.export_globals()
        self.export_strings()
        self.log("CPG JSON export completed.")

    def export_globals(self):
        self.log("Exporting globals.jsonl...")
        out_path = os.path.join(self.output_dir, "globals.jsonl")
        
        globals_list = []
        
        # Iterate over all segments
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg: continue
            
            # Determine if segment is read-only (const)
            is_const = (seg.perm & ida_segment.SEGPERM_WRITE) == 0
            
            # Iterate over heads in segment
            for head_ea in idautils.Heads(seg.start_ea, seg.end_ea):
                # Only process data items
                flags = ida_bytes.get_flags(head_ea)
                if not ida_bytes.is_data(flags):
                    continue
                
                # Get name
                name = ida_name.get_name(head_ea)
                if not name: 
                    continue
                
                # Get type info
                tinfo = ida_typeinf.tinfo_t()
                type_str = "unknown"
                if ida_nalt.get_tinfo(tinfo, head_ea):
                    type_str = str(tinfo)
                
                # Size
                size = ida_bytes.get_item_size(head_ea)
                
                # Content extraction
                content = {}
                str_type = ida_nalt.get_str_type(head_ea)
                
                if str_type >= 0: # It's a string
                    content_bytes = None
                    try:
                        # Try standard call
                        content_bytes = ida_bytes.get_strlit_contents(head_ea, -1, int(str_type))
                    except Exception:
                        try:
                            # Fallback: try without type or with default type if API differs
                            content_bytes = ida_bytes.get_strlit_contents(head_ea, -1, 0)
                        except Exception:
                             pass
                             
                    if content_bytes:
                        try:
                            content = {
                                "type": "string",
                                "value": content_bytes.decode("utf-8"),
                                "encoding": "utf-8"
                            }
                        except:
                            content = {
                                "type": "bytes",
                                "value": content_bytes.hex(),
                                "encoding": "hex"
                            }
                else:
                    # Check if pointer
                    is_ptr = False
                    ptr_val = 0
                    is_64 = ida_ida.inf_is_64bit()
                    ptr_size = 8 if is_64 else 4
                    
                    if size == ptr_size:
                         if is_64:
                             ptr_val = ida_bytes.get_qword(head_ea)
                         else:
                             ptr_val = ida_bytes.get_dword(head_ea)
                         
                         # Check if points to valid memory
                         if ida_bytes.is_loaded(ptr_val):
                             is_ptr = True
                    
                    if is_ptr:
                        content = {
                            "type": "ptr",
                            "value": f"0x{ptr_val:x}"
                        }
                    elif size <= 8:
                        # Scalar
                        val = 0
                        if size == 1: val = ida_bytes.get_byte(head_ea)
                        elif size == 2: val = ida_bytes.get_word(head_ea)
                        elif size == 4: val = ida_bytes.get_dword(head_ea)
                        elif size == 8: val = ida_bytes.get_qword(head_ea)
                        content = {
                            "type": "int",
                            "value": hex(val)
                        }
                    else:
                         content = {
                            "type": "blob",
                            "size": size
                        }

                # Xrefs
                refs = []
                for xref in idautils.XrefsTo(head_ea):
                     refs.append(f"0x{xref.frm:x}")
                
                demangled = None
                try:
                    if hasattr(ida_name, "demangle_name"):
                        demangled = ida_name.demangle_name(name, 0)
                    elif hasattr(ida_name, "get_demangled_name"):
                         # Fallback for some versions, though arguments vary
                         pass
                except:
                    pass
                
                record = {
                    "ea": f"0x{head_ea:x}",
                    "name": name,
                    "demangled_name": demangled,
                    "type": type_str,
                    "size": size,
                    "storage": "static" if is_const else "public", # Simplified
                    "is_const": is_const,
                    "content": content,
                    "refs": refs
                }
                globals_list.append(record)
                
        with open(out_path, "w", encoding="utf-8") as f:
            for g in globals_list:
                f.write(json.dumps(g) + "\n")

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
            cfunc = None
            try:
                cfunc = ida_hexrays.decompile(func_ea)
            except:
                cfunc = None

            pfn = idaapi.get_func(cfunc.entry_ea)
            hf = ida_hexrays.hexrays_failure_t()
            mbr = ida_hexrays.mba_ranges_t(pfn)

            mba = ida_hexrays.gen_microcode(
                mbr, 
                hf, 
                None, 
                ida_hexrays.DECOMP_WARNINGS, 
                ida_hexrays.MMAT_LVARS
            )
            
            if not mba:
                res["status"] = "failed"
                res["error"] = f"gen_microcode failed: {hf.str}"

            if mba:
                res["microcode"] = self._extract_microcode(mba)
                #self._dump_microcode(mba, func_name, res["func_ea"])

            if cfunc:
                res["decompilation"]["pseudocode"] = str(cfunc)
                
                ea_to_line = {}
                pcode = cfunc.get_pseudocode()
                for line_idx, sline in enumerate(pcode):
                     if hasattr(sline, "ea") and sline.ea != ida_ida.BADADDR:
                         ea_to_line[f"0x{sline.ea:x}"] = line_idx + 1
                
                res["decompilation"]["ea_to_line"] = ea_to_line
                
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

        is_call = False
        if 'ida_hexrays' in globals() and ida_hexrays.is_mcode_call(insn.opcode):
             is_call = True

        if hasattr(insn, "d") and insn.d and not insn.d.empty():
            norm = self._normalize_operand(insn.d)
            if norm:
                skip = False
                if is_call:
                     if norm['bits'] == 0: skip = True
                     if norm['repr'] == "void": skip = True
                     if "void" in str(norm.get("v", {}).get("full_repr", "")): skip = True
                
                if not skip:
                    writes.append({"role": "dst", "index": 0, "op": norm})

        self._collect_reads_from_insn(insn, reads, calls, True)

        if is_call:
            retloc = self._extract_call_retloc(insn)
            if retloc:
                exists = False
                for w in writes:
                    if w.get("op", {}).get("repr") == retloc.get("repr"):
                        exists = True
                        break
                if not exists:
                    writes.append({"role": "dst", "index": len(writes), "op": retloc})

        return {
            "block_id": block_id,
            "insn_idx": insn_idx,
            "ea": f"0x{insn.ea:x}",
            "opcode": self._opcode_name(opcode),
            "text": self._strip_tags(insn.dstr()), # Print representation
            "reads": reads,
            "writes": writes,
            "calls": calls
        }

    def _get_mop_type_name(self, t):
        if not hasattr(self, "_mop_tnames_map"):
            m = {}
            if 'ida_hexrays' in globals():
                for k, v in vars(ida_hexrays).items():
                    if k.startswith("mop_") and isinstance(v, int):
                        m[v] = k
            self._mop_tnames_map = m
        return self._mop_tnames_map.get(t, str(t))

    def _normalize_operand(self, mop):
        # mop is mop_t
        if mop.empty():
            return None
            
        t = mop.t
        repr_str = self._clean_repr(mop.dstr())
        
        # 1. Basic Info & Stable Identifier
        # User requested simple v as identifier, using dstr
        res = {
            "t": t,
            "t_name": self._get_mop_type_name(t),
            "dstr": repr_str, # Use dstr as the primary identifier
        }

        # 2. Visitor for sub-mops (Complex Types)
        # Use visitor for complex types that contain other mops
        if MopCollectorVisitor and t in (ida_hexrays.mop_d, ida_hexrays.mop_f, ida_hexrays.mop_a, ida_hexrays.mop_c, ida_hexrays.mop_p):
             visitor = MopCollectorVisitor(self)
             mop.for_all_ops(visitor)
             if visitor.sub_mops:
                 res["sub_mops"] = visitor.sub_mops
                 
             if visitor.reads:
                 res["reads"] = visitor.reads
             if visitor.writes:
                 res["writes"] = visitor.writes
                 
             # 3. Semantic Sugar / Aliases
             
             # Function Call Info
             if t == ida_hexrays.mop_f:
                 res["args"] = visitor.reads
             
             # Embedded Instruction (might be a call)
             elif t == ida_hexrays.mop_d:
                 if hasattr(ida_hexrays, "is_mcode_call") and hasattr(mop, "d") and ida_hexrays.is_mcode_call(mop.d.opcode):
                     res["is_call"] = True
                     res["args"] = visitor.reads
                     res["ret"] = visitor.writes
                     
             # Address Of / Pointer
             elif t == ida_hexrays.mop_a:
                 if visitor.reads:
                     res["pointed_to"] = visitor.reads[0]
                     
        return res

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

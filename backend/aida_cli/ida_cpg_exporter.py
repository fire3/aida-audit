import os
import json
import hashlib
import datetime
import sys

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
    import idaapi
except ImportError:
    pass

# Helper to map mop types to strings
def get_mop_type_name(t):
    if 'ida_hexrays' not in globals():
        return str(t)
    for k, v in vars(ida_hexrays).items():
        if k.startswith("mop_") and isinstance(v, int) and v == t:
            return k
    return str(t)

class MopCollector(ida_hexrays.mop_visitor_t):
    def __init__(self):
        ida_hexrays.mop_visitor_t.__init__(self)
        self.mops = []
        self.error = None

    def visit_mop(self, mop, type_id, is_target):
        try:
            # We capture the mop information here.
            # We do NOT call for_all_ops recursively to avoid re-entrancy issues 
            # and because for_all_ops should be traversing the tree already.
            
            # type_id corresponds to the 'type' argument in C++ visit_mop(op, type, is_target)
            # It is a tinfo_t object, not JSON serializable.
            type_str = str(type_id) if type_id else None

            mop_data = {
                "t": mop.t,
                "t_name": get_mop_type_name(mop.t),
                "v": self._get_simple_v(mop),
                "dstr": ida_lines.tag_remove(mop.dstr()),
                "is_target": bool(is_target),
                "type_str": type_str, 
                # We can try to capture more info if needed
            }
            self.mops.append(mop_data)
        except Exception as e:
            self.error = str(e)
            # We don't stop traversal, just log? Or return 1 to stop?
            # Let's try to continue
        return 0

    def _get_simple_v(self, mop):
        # User wants a simple identifier
        # We can use the string representation
        return ida_lines.tag_remove(mop.dstr())

class IDACPGExporter:
    def __init__(self, output_dir, logger):
        self.output_dir = output_dir
        self.log = logger.log
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def export(self):
        self.log("Waiting for auto-analysis to finish...")
        if 'ida_auto' in globals():
            ida_auto.auto_wait()
            
        self.log("Starting CPG JSON export (Redesigned)...")
        self.export_meta()
        self.export_functions()
        self.export_globals()
        self.log("CPG JSON export completed.")

    def export_meta(self):
        self.log("Exporting meta.json...")
        input_path = ida_nalt.get_input_file_path()
        binary_id = "sha256:unknown"
        if input_path and os.path.exists(input_path):
            sha256 = hashlib.sha256()
            try:
                with open(input_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        sha256.update(chunk)
                binary_id = f"sha256:{sha256.hexdigest()}"
            except Exception:
                pass

        proc_name = ida_ida.inf_get_procname() if 'ida_ida' in globals() else "unknown"
        is_64 = ida_ida.inf_is_64bit() if 'ida_ida' in globals() else False
        bitness = 64 if is_64 else 32
        is_be = ida_ida.inf_is_be() if 'ida_ida' in globals() else False
        endian = "big" if is_be else "little"
        imagebase = f"0x{ida_nalt.get_imagebase():x}" if 'ida_nalt' in globals() else "0x0"
        
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
            "exporter": "v2-redesign"
        }
        
        with open(os.path.join(self.output_dir, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    def export_functions(self):
        self.log("Exporting functions.jsonl...")
        out_path = os.path.join(self.output_dir, "functions.jsonl")
        
        # Check Hex-Rays
        if 'ida_hexrays' not in globals() or not ida_hexrays.init_hexrays_plugin():
            self.log("Hex-Rays not available.")
            return

        with open(out_path, "w", encoding="utf-8") as f:
            for func_ea in idautils.Functions():
                func_data = self._process_function(func_ea)
                f.write(json.dumps(func_data) + "\n")

    def _process_function(self, func_ea):
        func_name = ida_funcs.get_func_name(func_ea)
        res = {
            "func_ea": f"0x{func_ea:x}",
            "name": func_name,
            "status": "ok",
            "blocks": [],
            "instructions": [] # Flat list of instructions
        }

        try:
            # Decompile to get microcode
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                res["status"] = "failed_decompile"
                return res
            
            # Generate microcode
            pfn = idaapi.get_func(cfunc.entry_ea)
            hf = ida_hexrays.hexrays_failure_t()
            mbr = ida_hexrays.mba_ranges_t(pfn)
            mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_WARNINGS, ida_hexrays.MMAT_LVARS)
            
            if not mba:
                res["status"] = "failed_microcode"
                res["error"] = hf.str
                return res

            # Traverse blocks and instructions
            self._extract_microcode(mba, res)

        except Exception as e:
            res["status"] = "failed"
            res["error"] = str(e)

        return res

    def _extract_microcode(self, mba, res):
        # mba is mbl_array_t
        for i in range(mba.qty):
            block = mba.get_mblock(i)
            
            # Block info
            block_info = {
                "id": i,
                "start_ea": f"0x{block.start:x}",
                "end_ea": f"0x{block.end:x}",
                "type": "block", # node type
                "succs": []
            }
            
            for succ in block.succs():
                succ_id = succ.serial if hasattr(succ, "serial") else succ
                block_info["succs"].append(succ_id)
            
            res["blocks"].append(block_info)
            
            # Instructions
            curr = block.head
            insn_idx = 0
            while curr:
                insn_data = self._process_insn(curr, i, insn_idx)
                res["instructions"].append(insn_data)
                curr = curr.next
                insn_idx += 1

    def _process_insn(self, insn, block_id, insn_idx):
        # insn is minsn_t
        
        insn_data = {
            "block_id": block_id,
            "idx": insn_idx,
            "ea": f"0x{insn.ea:x}",
            "opcode": self._get_opcode_name(insn.opcode),
            "txt": ida_lines.tag_remove(insn.dstr()),
            "mops": []
        }

        # Use MopCollector to traverse operands
        # We process 'l' (left), 'r' (right), 'd' (destination)
        
        # 1. Destination (Write)
        if insn.d and not insn.d.empty():
            self._collect_mops(insn.d, insn_data["mops"], is_target=True, role="d")

        # 2. Left (Read)
        if insn.l and not insn.l.empty():
            self._collect_mops(insn.l, insn_data["mops"], is_target=False, role="l")

        # 3. Right (Read)
        if insn.r and not insn.r.empty():
            self._collect_mops(insn.r, insn_data["mops"], is_target=False, role="r")

        # 4. Call Arguments (if present in this version of Hex-Rays)
        if hasattr(insn, "args") and insn.args:
            for i, arg in enumerate(insn.args):
                # arg might be a mop_t or mcallarg_t (which has .type, .name, but usually wraps mop)
                # In Python hexrays, it's often presented as mop-compatible or has a mop field?
                # Previous code treated it as mop.
                self._collect_mops(arg, insn_data["mops"], is_target=False, role=f"arg_{i}")

        return insn_data

    def _collect_mops(self, root_mop, result_list, is_target, role):
        # 1. Add the root mop itself
        root_data = {
            "t": root_mop.t,
            "t_name": get_mop_type_name(root_mop.t),
            "v": ida_lines.tag_remove(root_mop.dstr()),
            "dstr": ida_lines.tag_remove(root_mop.dstr()),
            "is_target": is_target,
            "root_role": role,
            "is_root": True
        }
        result_list.append(root_data)
        
        # 2. Visit sub-mops
        visitor = MopCollector()
        root_mop.for_all_ops(visitor)
        
        if visitor.mops:
            # Append collected sub-mops
            # Note: visitor.mops contains flat list of descendants
            for m in visitor.mops:
                # Inherit target status if not specified? 
                # Actually visit_mop passes is_target. MopCollector captures it.
                # But 'role' is only for the root.
                m["root_role"] = role
                m["is_root"] = False
                result_list.append(m)

    def _get_opcode_name(self, opcode):
        if 'ida_hexrays' in globals() and hasattr(ida_hexrays, "get_mcode_name"):
            return ida_hexrays.get_mcode_name(opcode)
        return str(opcode)

    def export_globals(self):
        # Simplified export globals
        self.log("Exporting globals.jsonl...")
        out_path = os.path.join(self.output_dir, "globals.jsonl")
        
        with open(out_path, "w", encoding="utf-8") as f:
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if not seg: continue
                # Only data segments usually
                if (seg.perm & ida_segment.SEGPERM_EXEC) != 0:
                    continue
                    
                for head_ea in idautils.Heads(seg.start_ea, seg.end_ea):
                     if not ida_bytes.is_data(ida_bytes.get_flags(head_ea)):
                         continue
                     name = ida_name.get_name(head_ea)
                     if not name: continue
                     
                     rec = {
                         "ea": f"0x{head_ea:x}",
                         "name": name,
                         "size": ida_bytes.get_item_size(head_ea)
                     }
                     f.write(json.dumps(rec) + "\n")


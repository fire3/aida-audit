import sys
import os
import hashlib
import zlib
import json
import time
import datetime

# IDA Imports
try:
    import idapro
    import ida_kernwin
    import ida_auto
    import ida_loader
    import ida_pro
    import ida_nalt
    import ida_segment
    import ida_funcs
    import ida_bytes
    import ida_name
    import ida_entry
    import ida_xref
    import ida_typeinf
    import ida_hexrays
    import ida_lines
    import ida_gdl
    import ida_strlist
    import idautils
    import idc
    import ida_ida
    import ida_ua
except ImportError:
    pass # Expecting to run inside IDA

from ida_utils import ProgressTracker, calculate_entropy

class IDAExporter:
    def __init__(self, db, logger, timer, input_file=None):
        self.db = db
        self.log = logger.log
        self.timer = timer
        self.input_file = input_file

    def get_binary_info_dict(self):
        """Extract all metadata about the loaded binary in IDA and return as a complete dictionary matching frontend requirements.
        
        Returns:
            dict: A dictionary containing the final metadata structure.
        """
        # Get binary path and name
        binary_path = self.input_file or ida_nalt.get_input_file_path()
        binary_name = os.path.basename(binary_path) if binary_path else "unknown"
        file_exists = binary_path and os.path.exists(binary_path)
        
        # Calculate Hashes & Size
        hashes = {"md5": "", "sha256": "", "crc32": ""}
        file_size = 0
        
        if file_exists:
            try:
                with open(binary_path, 'rb') as f:
                    content = f.read()
                    hashes['sha256'] = hashlib.sha256(content).hexdigest()
                    hashes['md5'] = hashlib.md5(content).hexdigest()
                    hashes['crc32'] = str(zlib.crc32(content))
                file_size = os.path.getsize(binary_path)
            except Exception as e:
                self.log(f"Error calculating hashes: {e}")

        # Architecture & Processor
        processor = ida_ida.inf_get_procname()
        if ida_pro.IDA_SDK_VERSION == 910:
            is_64 = ida_ida.idainfo_is_64bit()
            is_32 = ida_ida.idainfo_is_32bit()
        else:
            is_64 = ida_ida.inf_is_64bit()
            is_32 = ida_ida.inf_is_32bit_exactly()
            
        bitness = "64-bit" if is_64 else "32-bit" if is_32 else "16-bit"
        address_width = "64" if is_64 else "32" if is_32 else "16"
        endian = "Big endian" if ida_ida.inf_is_be() else "Little endian"

        # Compiler Info
        compiler_id = ida_ida.inf_get_cc_id()
        compiler_name = ida_typeinf.get_compiler_name(compiler_id)
        compiler_abbr = ida_typeinf.get_compiler_abbr(compiler_id)

        # Segments Stats
        segment_count = 0
        for seg_ea in idautils.Segments():
            segment_count += 1
        
        # Functions Stats
        function_count = 0
        lib_functions = 0
        user_functions = 0
        
        for func_ea in idautils.Functions():
            function_count += 1
            func_name = ida_funcs.get_func_name(func_ea)
            # Simple heuristic for user vs lib functions
            if func_name and (func_name.startswith('sub_') or not any(c in func_name for c in ['@', '.', '_imp_'])):
                user_functions += 1
            else:
                lib_functions += 1
        
        # Strings Stats
        string_count = 0
        for _ in idautils.Strings():
            string_count += 1
        
        # Imports & Exports Stats
        import_count = 0
        for i in range(ida_nalt.get_import_module_qty()):
            def cb(ea, name, ordinal):
                nonlocal import_count
                import_count += 1
                return True
            ida_nalt.enum_import_names(i, cb)
        
        export_count = 0
        try:
            for _ in idautils.Entries():
                export_count += 1
        except:
            try:
                export_count = ida_nalt.get_entry_qty()
            except:
                export_count = 0

        # Libraries List
        libraries = []
        for i in range(ida_nalt.get_import_module_qty()):
            name = ida_nalt.get_import_module_name(i)
            if name:
                libraries.append(name)

        # Construct Final JSON Structure
        final_meta = {
            "binary_name": binary_name,
            "arch": bitness,
            "processor": processor,
            "format": ida_loader.get_file_type_name(),
            "size": file_size,
            "image_base": hex(ida_nalt.get_imagebase()),
            "endian": endian,
            "address_width": address_width,
            "created_at": datetime.datetime.now().isoformat(),
            "counts": {
                "functions": function_count,
                "user_functions": user_functions,
                "library_functions": lib_functions,
                "imports": import_count,
                "exports": export_count,
                "strings": string_count,
                "segments": segment_count,
                "symbols": ida_name.get_nlist_size()
            },
            "hashes": hashes,
            "compiler": {
                "compiler_name": compiler_name,
                "compiler_abbr": compiler_abbr
            },
            "libraries": libraries
        }
        
        return final_meta

    def safe_int(self, val):
        if val is None: return None
        if val >= (1 << 63):
            val -= (1 << 64)
        return val

    def export_all(self):
        try:
            self.export_metadata()
            self.export_segments()
            self.export_sections()
            self.export_imports()
            self.export_exports()
            self.export_symbols()
            self.export_functions()
            self.export_pseudocode()
            self.export_disasm_chunks()
            self.export_data_items()
            self.export_strings()
            self.export_xrefs()
            self.export_call_edges()
            self.export_local_types()
            self.export_segment_content()
            self.export_cfg()
            self.export_instructions()
        except Exception as e:
            self.log(f"Error during export: {e}")
            import traceback
            traceback.print_exc()
            raise e

    def export_all_but_pseudocode(self):
        self.export_metadata()
        self.export_segments()
        self.export_sections()
        self.export_imports()
        self.export_exports()
        self.export_symbols()
        self.export_functions()
        #self.export_pseudocode()
        self.export_disasm_chunks()
        self.export_data_items()
        self.export_strings()
        self.export_xrefs()
        self.export_call_edges()
        self.export_local_types()
        self.export_segment_content()
        self.export_cfg()
        self.export_instructions()

    def export_metadata(self):
        self.timer.start_step("Metadata")
        self.log("Exporting metadata...")
        
        # Get the complete metadata dictionary
        final_meta = self.get_binary_info_dict()

        # Save as single JSON blob
        self.db.insert_metadata_json(json.dumps(final_meta))
        self.timer.end_step("Metadata")

    def export_symbols(self):
        self.timer.start_step("Symbols")
        self.log("Exporting symbols...")
        total_names = ida_name.get_nlist_size()
        tracker = ProgressTracker(total_names, self.log, "Symbols")
        
        data = []
        for i, (ea, name) in enumerate(idautils.Names()):
            tracker.update(i + 1)
            flags = ida_bytes.get_flags(ea)
            kind = "unknown"
            if ida_bytes.is_func(flags):
                kind = "function"
            elif ida_bytes.is_data(flags):
                kind = "data"
            elif ida_bytes.is_code(flags):
                kind = "label" # Code but not function start
            
            demangled = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM)
            
            # Size estimation
            size = 0
            if kind == "function":
                func = ida_funcs.get_func(ea)
                if func: size = func.size()
            elif kind == "data":
                size = ida_bytes.get_item_size(ea)
            
            data.append((name, demangled, kind, ea, size))
            
            if len(data) >= 1000:
                self.db.insert_symbols(data)
                data = []

        if data:
            self.db.insert_symbols(data)
        self.timer.end_step("Symbols")

    def export_functions(self):
        self.timer.start_step("Functions")
        self.log("Exporting functions...")
        total_funcs = ida_funcs.get_func_qty()
        tracker = ProgressTracker(total_funcs, self.log, "Functions")
        
        data = []
        rtree_data = []
        
        for i, ea in enumerate(idautils.Functions()):
            tracker.update(i + 1)
            func = ida_funcs.get_func(ea)
            name = ida_funcs.get_func_name(ea)
            demangled = None
            if name:
                demangled = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM)
            
            is_thunk = 1 if (func.flags & ida_funcs.FUNC_THUNK) else 0
            is_library = 1 if (func.flags & ida_funcs.FUNC_LIB) else 0
            
            data.append((ea, name, demangled, func.start_ea, func.end_ea, func.size(), is_thunk, is_library))
            rtree_data.append((ea, func.start_ea, func.end_ea))
            
            if len(data) >= 1000:
                self.db.insert_functions(data, rtree_data)
                data = []
                rtree_data = []

        if data:
            self.db.insert_functions(data, rtree_data)
        self.timer.end_step("Functions")

    def export_segments(self):
        self.timer.start_step("Segments")
        self.log("Exporting segments...")
        data = []
        for ea in idautils.Segments():
            seg = ida_segment.getseg(ea)
            name = ida_segment.get_segm_name(seg)
            perm = seg.perm
            perm_r = 1 if (perm & ida_segment.SEGPERM_READ) else 0
            perm_w = 1 if (perm & ida_segment.SEGPERM_WRITE) else 0
            perm_x = 1 if (perm & ida_segment.SEGPERM_EXEC) else 0
            
            seg_type = "UNKNOWN"
            if seg.type == ida_segment.SEG_CODE: seg_type = "CODE"
            elif seg.type == ida_segment.SEG_DATA: seg_type = "DATA"
            elif seg.type == ida_segment.SEG_BSS: seg_type = "BSS"
            elif seg.type == ida_segment.SEG_XTRN: seg_type = "EXTERN"
            
            file_offset = None 
            offset = ida_loader.get_fileregion_offset(ea)
            if offset != -1:
                file_offset = offset

            data.append((name, seg.start_ea, seg.end_ea, perm_r, perm_w, perm_x, file_offset, seg_type))
            
        self.db.insert_segments(data)
        self.timer.end_step("Segments")

    def export_sections(self):
        self.timer.start_step("Sections")
        self.log("Exporting sections...")
        data = []
        for ea in idautils.Segments():
            seg = ida_segment.getseg(ea)
            name = ida_segment.get_segm_name(seg)
            start_va = seg.start_ea
            end_va = seg.end_ea
            
            file_offset = None
            offset = ida_loader.get_fileregion_offset(ea)
            if offset != -1:
                file_offset = offset
            
            entropy = 0.0
            try:
                size = end_va - start_va
                if size > 0:
                    if size < 10 * 1024 * 1024:
                        content = ida_bytes.get_bytes(start_va, size)
                        entropy = calculate_entropy(content)
                    else:
                        content = ida_bytes.get_bytes(start_va, 1024*1024) # First 1MB
                        entropy = calculate_entropy(content)
            except Exception as e:
                self.log(f"Error calculating entropy for {name}: {e}")
                
            seg_type = "UNKNOWN"
            if seg.type == ida_segment.SEG_CODE: seg_type = "CODE"
            elif seg.type == ida_segment.SEG_DATA: seg_type = "DATA"
            elif seg.type == ida_segment.SEG_BSS: seg_type = "BSS"
            
            data.append((name, start_va, end_va, file_offset, entropy, seg_type))
            
        self.db.insert_sections(data)
        self.timer.end_step("Sections")

    def export_imports(self):
        self.timer.start_step("Imports")
        self.log("Exporting imports...")
        data = []
        
        import_modules = []
        for i in range(ida_nalt.get_import_module_qty()):
            name = ida_nalt.get_import_module_name(i)
            import_modules.append((i, name))
            
        for i, lib_name in import_modules:
            def callback(ea, name, ordinal):
                data.append((lib_name, name, ordinal, ea, None))
                return True
            ida_nalt.enum_import_names(i, callback)
            
        self.db.insert_imports(data)
        self.timer.end_step("Imports")

    def export_exports(self):
        self.timer.start_step("Exports")
        self.log("Exporting exports...")
        data = []
        for index, ordinal, ea, name in idautils.Entries():
            forwarder = None
            try:
                forwarder = ida_entry.get_entry_forwarder(ordinal)
            except Exception:
                pass
            data.append((name, ordinal, ea, forwarder))
            
        self.db.insert_exports(data)
        self.timer.end_step("Exports")

    def export_strings(self):
        self.timer.start_step("Strings")
        self.log("Exporting strings...")
        data = []
        s = idautils.Strings()
        for i in s:
            content = str(i)
            encoding = "ascii" 
            seg = ida_segment.getseg(i.ea)
            section_name = ida_segment.get_segm_name(seg) if seg else None
            
            data.append((i.ea, encoding, i.length, content, section_name))
            
            if len(data) >= 1000:
                self.db.insert_strings(data)
                data = []
                
        if data:
            self.db.insert_strings(data)
        self.timer.end_step("Strings")

    def export_pseudocode(self, function_list=None):
        self.timer.start_step("Pseudocode")
        if not ida_hexrays.init_hexrays_plugin():
            self.log("Hex-Rays decompiler not available, skipping pseudocode export.")
            self.timer.end_step("Pseudocode")
            return {
                "attempted": 0,
                "decompiled": 0,
                "failed": 0,
                "thunks": 0,
                "library": 0,
                "nofunc": 0,
                "none": 0,
                "min_ea": None,
                "max_ea": None,
                "top_errors": [],
                "hexrays_available": False,
            }

        self.log("Exporting pseudocode...")
        
        funcs_to_process = []
        if function_list:
            funcs_to_process = function_list
        else:
            # Get all functions
            funcs_to_process = [ea for ea in idautils.Functions()]
            
        total_funcs = len(funcs_to_process)
        min_ea = None
        max_ea = None
        if funcs_to_process:
            try:
                min_ea = int(min(funcs_to_process))
                max_ea = int(max(funcs_to_process))
            except Exception:
                min_ea = None
                max_ea = None

        start_time = time.time()
        next_log_time = start_time
        decompiled = 0
        failed = 0
        thunks = 0
        library = 0
        nofunc = 0
        none_results = 0
        error_counts = {}
        error_order = []
        last_name = ""
        last_ea = None

        data = []
        for i, ea in enumerate(funcs_to_process):
            func = None
            try:
                func = ida_funcs.get_func(ea)
            except Exception:
                func = None

            if not func:
                nofunc += 1
                failed += 1
                key = "no_func"
                error_counts[key] = error_counts.get(key, 0) + 1
                if key not in error_order:
                    error_order.append(key)
                continue

            try:
                if func.flags & ida_funcs.FUNC_THUNK:
                    thunks += 1
                if func.flags & ida_funcs.FUNC_LIB:
                    library += 1
            except Exception:
                pass

            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    content = str(cfunc)
                    data.append((ea, content))
                    decompiled += 1
                else:
                    failed += 1
                    none_results += 1
                    key = "decompile_returned_none"
                    error_counts[key] = error_counts.get(key, 0) + 1
                    if key not in error_order:
                        error_order.append(key)
            except Exception as e:
                failed += 1
                key = f"{type(e).__name__}: {str(e)}"
                error_counts[key] = error_counts.get(key, 0) + 1
                if key not in error_order:
                    error_order.append(key)

            last_ea = ea
            try:
                last_name = ida_funcs.get_func_name(ea) or ""
            except Exception:
                last_name = ""

            now = time.time()
            if now >= next_log_time or (i + 1) >= total_funcs:
                elapsed = now - start_time
                if elapsed < 0.001:
                    elapsed = 0.001
                rate = (i + 1) / elapsed
                remaining = total_funcs - (i + 1)
                eta_seconds = remaining / rate if rate > 0 else 0
                percent = ((i + 1) / total_funcs * 100.0) if total_funcs else 100.0
                where = f"{last_name}@{hex(last_ea)}" if last_ea is not None else ""
                self.log(
                    f"Pseudocode: {percent:5.1f}% ({i+1}/{total_funcs}) ok={decompiled} fail={failed} rate={rate:.2f}/s eta={int(eta_seconds)}s {where}".rstrip()
                )
                next_log_time = now + 2.0
            
            if len(data) >= 100:
                self.db.insert_pseudocode(data)
                data = []
        
        if data:
            self.db.insert_pseudocode(data)
        self.timer.end_step("Pseudocode")

        top_errors = []
        for key in error_order:
            if key in error_counts:
                top_errors.append({"error": key, "count": int(error_counts[key])})
            if len(top_errors) >= 5:
                break
        return {
            "attempted": total_funcs,
            "decompiled": decompiled,
            "failed": failed,
            "thunks": thunks,
            "library": library,
            "nofunc": nofunc,
            "none": none_results,
            "min_ea": min_ea,
            "max_ea": max_ea,
            "top_errors": top_errors,
            "hexrays_available": True,
        }

    def dump_function_list(self, output_path):
        self.log(f"Dumping function list to {output_path}...")
        funcs = [ea for ea in idautils.Functions()]
        with open(output_path, 'w') as f:
            json.dump(funcs, f)
        self.log(f"Dumped {len(funcs)} functions.")

    def export_disasm_chunks(self):
        self.timer.start_step("DisasmChunks")
        self.log("Exporting disasm chunks...")
        
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        total_range = max_ea - min_ea
        if total_range <= 0: total_range = 1
        tracker = ProgressTracker(total_range, self.log, "Disasm Chunks")

        CHUNK_SIZE_LINES = 100
        data = []
        
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg: continue
            
            current_chunk_lines = []
            current_chunk_start = None
            current_chunk_end = None
            
            for head in idautils.Heads(seg.start_ea, seg.end_ea):
                tracker.update(head - min_ea)
                if current_chunk_start is None:
                    current_chunk_start = head
                
                disasm_text = idc.generate_disasm_line(head, 0)
                if disasm_text:
                    current_chunk_lines.append(f"{hex(head)}: {disasm_text}")
                
                current_chunk_end = head + ida_bytes.get_item_size(head)
                
                if len(current_chunk_lines) >= CHUNK_SIZE_LINES:
                    content = "\n".join(current_chunk_lines)
                    data.append((current_chunk_start, current_chunk_end, content))
                    current_chunk_lines = []
                    current_chunk_start = None
            
            if current_chunk_lines:
                content = "\n".join(current_chunk_lines)
                data.append((current_chunk_start, current_chunk_end, content))

            if len(data) >= 100:
                 self.db.insert_disasm_chunks(data)
                 data = []

        if data:
            self.db.insert_disasm_chunks(data)
        self.timer.end_step("DisasmChunks")

    def export_data_items(self):
        self.timer.start_step("DataItems")
        self.log("Exporting data items...")
        
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        total_range = max_ea - min_ea
        if total_range <= 0: total_range = 1
        tracker = ProgressTracker(total_range, self.log, "Data Items")
        
        data = []
        for ea in idautils.Heads():
            tracker.update(ea - min_ea)
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_data(flags):
                size = ida_bytes.get_item_size(ea)
                
                kind = "byte"
                type_name = "unknown"
                repr_str = ""
                target_va = None
                
                if ida_bytes.is_strlit(flags):
                    kind = "string"
                    repr_str = str(ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C))
                elif ida_bytes.is_off0(flags) or ida_bytes.is_off1(flags):
                     kind = "offset"
                     xrefs = idautils.DataRefsFrom(ea)
                     for x in xrefs:
                         target_va = x
                         break
                else:
                    width = ida_bytes.get_item_size(ea)
                    if width == 1: kind = "byte"
                    elif width == 2: kind = "word"
                    elif width == 4: kind = "dword"
                    elif width == 8: kind = "qword"
                    else: kind = "array/struct"
                
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, ea):
                    type_name = str(tif)
                
                if not repr_str:
                    repr_str = idc.generate_disasm_line(ea, 0)

                data.append((ea, size, kind, type_name, repr_str, target_va))

            if len(data) >= 1000:
                self.db.insert_data_items(data)
                data = []

        if data:
            self.db.insert_data_items(data)
        self.timer.end_step("DataItems")

    def export_xrefs(self):
        self.timer.start_step("Xrefs")
        self.log("Exporting xrefs...")
        
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        total_range = max_ea - min_ea
        if total_range <= 0: total_range = 1
        tracker = ProgressTracker(total_range, self.log, "Xrefs")
        
        data = []
        for ea in idautils.Heads():
            tracker.update(ea - min_ea)
            for xref in idautils.XrefsFrom(ea, 0):
                if not ida_segment.getseg(xref.to):
                    continue

                xref_type_str = "unknown"
                t = xref.type
                if t == ida_xref.fl_CF or t == ida_xref.fl_CN: xref_type_str = "call"
                elif t == ida_xref.fl_JF or t == ida_xref.fl_JN: xref_type_str = "jmp"
                elif t == ida_xref.dr_R: xref_type_str = "data_read"
                elif t == ida_xref.dr_W: xref_type_str = "data_write"
                elif t == ida_xref.dr_O: xref_type_str = "offset"
                
                from_func = ida_funcs.get_func(xref.frm)
                to_func = ida_funcs.get_func(xref.to)
                
                from_func_va = from_func.start_ea if from_func else None
                to_func_va = to_func.start_ea if to_func else None
                
                data.append((self.safe_int(xref.frm), self.safe_int(xref.to), self.safe_int(from_func_va), self.safe_int(to_func_va), xref_type_str, 0))
                
            if len(data) >= 1000:
                self.db.insert_xrefs(data)
                data = []

        if data:
            self.db.insert_xrefs(data)
        self.timer.end_step("Xrefs")
    
    def export_call_edges(self):
        self.timer.start_step("CallEdges")
        self.log("Exporting call edges...")
        data = []
        
        total_funcs = ida_funcs.get_func_qty()
        tracker = ProgressTracker(total_funcs, self.log, "Call Edges")

        for i, ea in enumerate(idautils.Functions()):
            tracker.update(i + 1)
            func = ida_funcs.get_func(ea)
            if not func: continue

            for head in idautils.FuncItems(ea):
                for xref in idautils.XrefsFrom(head, 0):
                    if xref.iscode: 
                        t = xref.type
                        if t in [ida_xref.fl_CF, ida_xref.fl_CN, ida_xref.fl_JF, ida_xref.fl_JN]:
                             callee_func = ida_funcs.get_func(xref.to)
                             if callee_func:
                                 # Skip intra-function jumps (not call edges)
                                 if t in [ida_xref.fl_JF, ida_xref.fl_JN] and callee_func.start_ea == func.start_ea:
                                     continue

                                 data.append((self.safe_int(func.start_ea), self.safe_int(callee_func.start_ea), self.safe_int(head), "direct"))
            
            if len(data) >= 1000:
                 self.db.insert_call_edges(data)
                 data = []
        
        if data:
             self.db.insert_call_edges(data)
        self.timer.end_step("CallEdges")

    def export_local_types(self):
        self.timer.start_step("LocalTypes")
        self.log("Exporting local types...")
        
        content_lines = []
        try:
            til = ida_typeinf.get_idati()
            if til:
                qty = 0
                if hasattr(ida_typeinf, 'get_ordinal_count'):
                    qty = ida_typeinf.get_ordinal_count(til)
                elif hasattr(ida_typeinf, 'get_ordinal_qty'):
                    qty = ida_typeinf.get_ordinal_qty(til)
                
                flags = 41
                
                for i in range(1, qty):
                    name = ida_typeinf.get_numbered_type_name(til, i)
                    if not name:
                        continue
                    
                    tinfo = ida_typeinf.tinfo_t()
                    if tinfo.get_numbered_type(til, i):
                        defn = tinfo._print(name, flags)
                        if defn:
                            content_lines.append(f"// {name}")
                            content_lines.append(defn)
                            content_lines.append("") 

        except Exception as e:
            self.log(f"Error iterating local types: {e}")

        full_content = "\n".join(content_lines)
        
        if full_content:
            self.db.insert_local_types("default", full_content)
        else:
             self.log("No local types found.")
        self.timer.end_step("LocalTypes")

    def export_segment_content(self):
        self.timer.start_step("SegmentContent")
        self.log("Exporting segment content...")
        
        # We need seg_id from the database to link content.
        # So we query segments table first.
        self.db.cursor.execute("SELECT seg_id, start_va, end_va, name FROM segments")
        segments = self.db.cursor.fetchall()
        
        for seg_id, start_va, end_va, name in segments:
            try:
                size = end_va - start_va
                if size > 0:
                    # Limit size if needed? flare_emu might need huge segments.
                    # SQLite limit is usually 1GB per row. 
                    # If segment is huge (e.g. 100MB), it's fine.
                    content = ida_bytes.get_bytes(start_va, size)
                    if content:
                        self.db.insert_segment_content(seg_id, content)
                    else:
                        self.log(f"Warning: get_bytes returned None for segment {name} ({hex(start_va)}-{hex(end_va)}). Trying byte-by-byte check...")
                        if not ida_bytes.is_loaded(start_va):
                             self.log(f"  Start VA {hex(start_va)} is not loaded.")
                        else:
                             b = ida_bytes.get_bytes(start_va, 1)
                             self.log(f"  First byte at {hex(start_va)}: {b}")
                             
                        # Try to read partially?
                        # If a segment has uninitialized tail, get_bytes fails for whole range?
                        # Let's try to read byte by byte until failure or end
                        loaded_bytes = []
                        for i in range(size):
                            b = ida_bytes.get_bytes(start_va + i, 1)
                            if b:
                                loaded_bytes.append(b)
                            else:
                                # Stop at first failure? Or assume 00?
                                # Usually uninitialized data is 00 or ??
                                # We'll pad with 00 for now if we found SOME bytes
                                loaded_bytes.append(b"\x00")
                        
                        if loaded_bytes:
                            full_content = b"".join(loaded_bytes)
                            self.db.insert_segment_content(seg_id, full_content)
                            self.log(f"  Recovered {len(full_content)} bytes using byte-by-byte read (padded with 00).")

            except Exception as e:
                self.log(f"Error exporting content for segment {name}: {e}")
                
        self.timer.end_step("SegmentContent")

    def export_cfg(self):
        self.timer.start_step("CFG")
        self.log("Exporting CFG...")
        
        total_funcs = ida_funcs.get_func_qty()
        tracker = ProgressTracker(total_funcs, self.log, "CFG")
        
        all_blocks = []
        block_successors_map = {} # start_va -> [succ_start_va]
        
        for i, func_ea in enumerate(idautils.Functions()):
            tracker.update(i + 1)
            func = ida_funcs.get_func(func_ea)
            if not func: continue
            
            flowchart = idaapi.FlowChart(func)
            for block in flowchart:
                start = block.start_ea
                end = block.end_ea
                btype = block.type
                all_blocks.append((func_ea, start, end, btype))
                
                succs = []
                for succ in block.succs():
                    succs.append(succ.start_ea)
                if succs:
                    block_successors_map[start] = succs
                    
            if len(all_blocks) >= 1000:
                 self.db.insert_basic_blocks(all_blocks)
                 all_blocks = []

        if all_blocks:
            self.db.insert_basic_blocks(all_blocks)
            
        # Resolve successors
        self.log("Resolving CFG successors...")
        # Get mapping of start_va -> block_id
        # Note: If multiple blocks have same start_va (overlays?), this might be ambiguous.
        # But usually start_va is unique for basic blocks.
        self.db.cursor.execute("SELECT start_va, block_id FROM basic_blocks")
        va_to_id = dict(self.db.cursor.fetchall())
        
        succ_data = []
        for src_va, succ_vas in block_successors_map.items():
            src_id = va_to_id.get(src_va)
            if not src_id: continue
            for dst_va in succ_vas:
                dst_id = va_to_id.get(dst_va)
                if dst_id:
                    succ_data.append((src_id, dst_id))
                    
            if len(succ_data) >= 1000:
                self.db.insert_basic_block_successors(succ_data)
                succ_data = []
                
        if succ_data:
            self.db.insert_basic_block_successors(succ_data)
            
        self.timer.end_step("CFG")

    def export_instructions(self):
        self.timer.start_step("Instructions")
        self.log("Exporting instructions...")
        
        # Iterate all heads that are code
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        tracker = ProgressTracker(max_ea - min_ea, self.log, "Instructions")
        
        insn_data = []
        op_data = []
        BATCH_SIZE = 1000
        
        for head in idautils.Heads(min_ea, max_ea):
            tracker.update(head - min_ea)
            flags = ida_bytes.get_flags(head)
            if not ida_bytes.is_code(flags):
                continue
            
            mnem = idc.print_insn_mnem(head)
            if not mnem: continue
            
            size = ida_bytes.get_item_size(head)
            func = ida_funcs.get_func(head)
            sp_delta = 0
            if func:
                sp_delta = idaapi.get_sp_delta(func, head)
            
            insn_data.append((head, mnem, size, sp_delta))
            
            # Operands (0 to 8 usually)
            for i in range(8):
                op_type = idc.get_operand_type(head, i)
                if op_type == 0: # o_void
                    break
                
                op_val = idc.get_operand_value(head, i)
                op_text = idc.print_operand(head, i)
                
                op_data.append((head, i, op_type, op_val, op_text))
            
            if len(insn_data) >= BATCH_SIZE:
                self.db.insert_instructions(insn_data)
                self.db.insert_instruction_operands(op_data)
                insn_data = []
                op_data = []
        
        if insn_data:
            self.db.insert_instructions(insn_data)
            self.db.insert_instruction_operands(op_data)
            
        self.timer.end_step("Instructions")

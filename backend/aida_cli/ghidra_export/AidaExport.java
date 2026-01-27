import java.io.BufferedWriter;
import java.io.File;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Typedef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

public class AidaExport extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1) {
            return;
        }
        List<String> positional = parsePositionalArgs(args);
        if (positional.isEmpty()) {
            return;
        }
        File outDir = new File(positional.get(0));
        outDir.mkdirs();
        String mode = positional.size() > 1 ? positional.get(1) : "full";
        int threads = parseIntArg(args, "--threads", 1);
        int chunkSize = parseIntArg(args, "--chunk", 0);
        String exportCPath = parseStringArg(args, "--export-c", null);
        println("AidaExport start");
        println("Output: " + outDir.getAbsolutePath());
        println("Mode: " + mode);
        println("Threads: " + threads + " Chunk: " + chunkSize);
        if (exportCPath != null) {
            println("Export C: " + exportCPath);
        }
        if ("pseudocode".equalsIgnoreCase(mode)) {
            String listPath = positional.size() > 2 ? positional.get(2) : null;
            String outPath = positional.size() > 3 ? positional.get(3) : null;
            List<Long> targets = listPath != null && !listPath.isEmpty() ? readFunctionList(listPath) : null;
            File outFile = outPath != null && !outPath.isEmpty() ? new File(outPath) : null;
            println("Pseudocode mode list: " + (listPath == null ? "" : listPath));
            println("Pseudocode mode out: " + (outFile == null ? "" : outFile.getAbsolutePath()));
            writePseudocode(outDir, targets, outFile);
            return;
        }
        println("Export metadata");
        writeMetadata(outDir);
        println("Export segments");
        writeSegments(outDir);
        println("Export sections");
        writeSections(outDir);
        println("Export imports");
        writeImports(outDir);
        println("Export exports");
        writeExports(outDir);
        println("Export symbols");
        writeSymbols(outDir);
        println("Export functions");
        writeFunctions(outDir);
        println("Export disassembly");
        writeDisasmChunks(outDir);
        println("Export strings");
        writeStrings(outDir);
        if (!"nopseudocode".equalsIgnoreCase(mode)) {
            println("Export pseudocode");
            if (threads > 1) {
                writePseudocodeParallel(outDir, threads, chunkSize);
            } else {
                writePseudocode(outDir, null, null);
            }
        }
        println("Export xrefs");
        writeXrefs(outDir);
        println("Export call edges");
        writeCallEdges(outDir);
        if (exportCPath != null) {
            println("Exporting C file...");
            writeCFile(new File(exportCPath));
        }
        println("AidaExport done");
    }

    private void writeCFile(File outFile) throws Exception {
        DecompInterface ifc = new DecompInterface();
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(currentProgram)) {
            println("Decompiler failed to open program");
            return;
        }
        
        try (BufferedWriter w = writer(outFile)) {
             writeCTypeDefinitions(w);
             writeCGlobals(w);
             writeCPrototypes(w);
             FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
             int count = 0;
             while (it.hasNext()) {
                 Function f = it.next();
                 DecompileResults res = ifc.decompileFunction(f, 30, monitor);
                 if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                     String c = res.getDecompiledFunction().getC();
                     if (c != null && !c.isEmpty()) {
                         w.write("// Function: " + f.getName() + " @ " + f.getEntryPoint() + "\n");
                         w.write(c);
                         w.write("\n\n");
                         count++;
                     }
                 }
                 if (count % 100 == 0) {
                     // monitor.setMessage("Exporting C: " + count);
                 }
             }
             println("Exported " + count + " functions to C file");
        } finally {
            ifc.dispose();
        }
    }

    private void writeCTypeDefinitions(BufferedWriter w) throws Exception {
        List<DataType> types = new ArrayList<>();
        for (DataType dt : currentProgram.getDataTypeManager().getAllDataTypes()) {
            if (dt == null) {
                continue;
            }
            String name = dt.getName();
            if (name == null || name.isEmpty()) {
                continue;
            }
            String path = dt.getCategoryPath() != null ? dt.getCategoryPath().toString() : "";
            if (path.startsWith("/builtin") || path.startsWith("/undefined")) {
                continue;
            }
            if (dt instanceof Structure || dt instanceof Union || dt instanceof Enum || dt instanceof Typedef) {
                types.add(dt);
            }
        }
        for (DataType dt : types) {
            String def = formatTypeDefinition(dt);
            if (def == null || def.isEmpty()) {
                continue;
            }
            w.write(def);
            w.newLine();
            w.newLine();
        }
    }

    private void writeCGlobals(BufferedWriter w) throws Exception {
        SymbolTable table = currentProgram.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);
        Set<String> emitted = new LinkedHashSet<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s == null || isExternalSymbol(s)) {
                continue;
            }
            SymbolType st = s.getSymbolType();
            if (st != null && (st == SymbolType.FUNCTION || st == SymbolType.LABEL)) {
                continue;
            }
            Address addr = s.getAddress();
            if (addr == null) {
                continue;
            }
            Data data = currentProgram.getListing().getDataAt(addr);
            if (data == null) {
                continue;
            }
            DataType dt = data.getDataType();
            String name = s.getName();
            if (dt == null || name == null || name.isEmpty()) {
                continue;
            }
            String decl = formatDeclaration(dt, name);
            if (decl == null || decl.isEmpty()) {
                continue;
            }
            if (emitted.add(decl)) {
                w.write(decl);
                w.write(";");
                w.newLine();
            }
        }
        if (!emitted.isEmpty()) {
            w.newLine();
        }
    }

    private void writeCPrototypes(BufferedWriter w) throws Exception {
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            String proto = functionPrototype(f);
            if (proto == null || proto.isEmpty()) {
                continue;
            }
            w.write(proto);
            if (!proto.trim().endsWith(";")) {
                w.write(";");
            }
            w.newLine();
        }
        w.newLine();
    }

    private String functionPrototype(Function f) {
        try {
            Method m = f.getClass().getMethod("getPrototypeString", boolean.class, boolean.class);
            Object v = m.invoke(f, true, true);
            if (v != null) {
                return String.valueOf(v);
            }
        } catch (Exception e) {
        }
        try {
            Object sig = f.getSignature();
            if (sig != null) {
                Method m = sig.getClass().getMethod("getPrototypeString");
                Object v = m.invoke(sig);
                if (v != null) {
                    return String.valueOf(v);
                }
            }
        } catch (Exception e) {
        }
        String name = f.getName();
        if (name == null || name.isEmpty()) {
            return null;
        }
        return "void " + name + "()";
    }

    private String formatTypeDefinition(DataType dt) {
        if (dt instanceof Typedef) {
            Typedef td = (Typedef) dt;
            DataType base = td.getDataType();
            String baseType = toCType(base);
            String name = td.getName();
            if (baseType == null || baseType.isEmpty() || name == null || name.isEmpty()) {
                return null;
            }
            return "typedef " + baseType + " " + name + ";";
        }
        if (dt instanceof Enum) {
            Enum en = (Enum) dt;
            String name = en.getName();
            if (name == null || name.isEmpty()) {
                return null;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("typedef enum ").append(name).append(" {").append("\n");
            String[] names = en.getNames();
            for (int i = 0; i < names.length; i++) {
                String n = names[i];
                if (n == null || n.isEmpty()) {
                    continue;
                }
                sb.append("    ").append(n).append(" = ").append(en.getValue(n));
                if (i < names.length - 1) {
                    sb.append(",");
                }
                sb.append("\n");
            }
            sb.append("} ").append(name).append(";");
            return sb.toString();
        }
        if (dt instanceof Structure) {
            Structure st = (Structure) dt;
            return formatCompositeDefinition("struct", st.getName(), st.getComponents());
        }
        if (dt instanceof Union) {
            Union un = (Union) dt;
            return formatCompositeDefinition("union", un.getName(), un.getComponents());
        }
        return null;
    }

    private String formatCompositeDefinition(String kind, String name, DataTypeComponent[] components) {
        if (name == null || name.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("typedef ").append(kind).append(" ").append(name).append(" {").append("\n");
        if (components != null) {
            for (DataTypeComponent c : components) {
                if (c == null || c.getDataType() == null) {
                    continue;
                }
                String fieldName = c.getFieldName();
                if (fieldName == null || fieldName.isEmpty()) {
                    fieldName = "field_" + c.getOffset();
                }
                String decl = formatDeclaration(c.getDataType(), fieldName);
                if (decl == null || decl.isEmpty()) {
                    continue;
                }
                sb.append("    ").append(decl).append(";").append("\n");
            }
        }
        sb.append("} ").append(name).append(";");
        return sb.toString();
    }

    private String formatDeclaration(DataType dt, String name) {
        if (dt instanceof Array) {
            Array arr = (Array) dt;
            String inner = formatDeclaration(arr.getDataType(), name);
            if (inner == null || inner.isEmpty()) {
                return null;
            }
            return inner + "[" + arr.getNumElements() + "]";
        }
        if (dt instanceof Pointer) {
            Pointer ptr = (Pointer) dt;
            String base = toCType(ptr.getDataType());
            if (base == null || base.isEmpty()) {
                base = "void";
            }
            return base + " *" + name;
        }
        String type = toCType(dt);
        if (type == null || type.isEmpty()) {
            return null;
        }
        return type + " " + name;
    }

    private String toCType(DataType dt) {
        if (dt == null) {
            return null;
        }
        if (dt instanceof FunctionDefinition) {
            String name = dt.getName();
            if (name != null && !name.isEmpty()) {
                return name;
            }
        }
        if (dt instanceof Typedef || dt instanceof Structure || dt instanceof Union || dt instanceof Enum) {
            return dt.getName();
        }
        String name = dt.getName();
        if (name == null || name.isEmpty()) {
            return null;
        }
        return name;
    }

    private void writeMetadata(File outDir) throws Exception {
        Map<String, Object> meta = new LinkedHashMap<>();
        String path = null;
        try {
            path = currentProgram.getExecutablePath();
        } catch (Exception e) {
            path = null;
        }
        String binaryName = path != null ? new File(path).getName() : currentProgram.getName();
        meta.put("binary_name", binaryName);
        int pointerSize = currentProgram.getDefaultPointerSize();
        String arch = pointerSize == 8 ? "64-bit" : pointerSize == 4 ? "32-bit" : pointerSize == 2 ? "16-bit" : String.valueOf(pointerSize * 8);
        meta.put("arch", arch);
        meta.put("processor", currentProgram.getLanguage().getProcessor().toString());
        String format = "";
        try {
            Method m = currentProgram.getClass().getMethod("getExecutableFormat");
            Object v = m.invoke(currentProgram);
            format = v == null ? "" : String.valueOf(v);
        } catch (Exception e) {
            format = "";
        }
        meta.put("format", format);
        meta.put("size", path != null && new File(path).isFile() ? new File(path).length() : 0);
        meta.put("image_base", "0x" + Long.toHexString(currentProgram.getImageBase().getOffset()));
        meta.put("endian", currentProgram.getLanguage().isBigEndian() ? "Big endian" : "Little endian");
        meta.put("address_width", String.valueOf(pointerSize * 8));
        meta.put("created_at", OffsetDateTime.now().toString());
        Map<String, Object> counts = new LinkedHashMap<>();
        FunctionManager fm = currentProgram.getFunctionManager();
        int functionCount = 0;
        int libFunctions = 0;
        FunctionIterator fit = fm.getFunctions(true);
        while (fit.hasNext()) {
            Function f = fit.next();
            functionCount += 1;
            if (isLibraryFunction(f)) {
                libFunctions += 1;
            }
        }
        counts.put("functions", functionCount);
        counts.put("user_functions", functionCount - libFunctions);
        counts.put("library_functions", libFunctions);
        counts.put("imports", countImports());
        counts.put("exports", countExports());
        counts.put("strings", countStrings());
        counts.put("segments", currentProgram.getMemory().getBlocks().length);
        counts.put("symbols", currentProgram.getSymbolTable().getNumSymbols());
        meta.put("counts", counts);
        Map<String, Object> hashes = new LinkedHashMap<>();
        String sha256 = "";
        String md5 = "";
        String crc32 = "";
        if (path != null && new File(path).isFile()) {
            sha256 = hashFile(path, "SHA-256");
            md5 = hashFile(path, "MD5");
            crc32 = crc32File(path);
        }
        hashes.put("sha256", sha256);
        hashes.put("md5", md5);
        hashes.put("crc32", crc32);
        meta.put("hashes", hashes);
        Map<String, Object> compiler = new LinkedHashMap<>();
        compiler.put("compiler_name", "");
        compiler.put("compiler_abbr", "");
        meta.put("compiler", compiler);
        meta.put("libraries", new ArrayList<>(collectLibraries()));
        writeJsonObject(new File(outDir, "metadata.json"), meta);
    }

    private void writeSegments(File outDir) throws Exception {
        Memory memory = currentProgram.getMemory();
        File outFile = new File(outDir, "segments.jsonl");
        try (BufferedWriter w = writer(outFile)) {
            for (MemoryBlock block : memory.getBlocks()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", block.getName());
                row.put("start_va", block.getStart().getOffset());
                row.put("end_va", block.getEnd().getOffset() + 1);
                row.put("perm_r", block.isRead() ? 1 : 0);
                row.put("perm_w", block.isWrite() ? 1 : 0);
                row.put("perm_x", block.isExecute() ? 1 : 0);
                row.put("file_offset", null);
                row.put("type", block.getType().toString());
                writeJsonLine(w, row);
            }
        }
    }

    private void writeSections(File outDir) throws Exception {
        Memory memory = currentProgram.getMemory();
        File outFile = new File(outDir, "sections.jsonl");
        try (BufferedWriter w = writer(outFile)) {
            for (MemoryBlock block : memory.getBlocks()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", block.getName());
                row.put("start_va", block.getStart().getOffset());
                row.put("end_va", block.getEnd().getOffset() + 1);
                row.put("file_offset", null);
                row.put("entropy", computeEntropy(block));
                row.put("type", block.getType().toString());
                writeJsonLine(w, row);
            }
        }
    }

    private void writeImports(File outDir) throws Exception {
        SymbolTable table = currentProgram.getSymbolTable();
        File outFile = new File(outDir, "imports.jsonl");
        try (BufferedWriter w = writer(outFile)) {
            SymbolIterator it = table.getAllSymbols(true);
            while (it.hasNext()) {
                Symbol s = it.next();
                if (!isExternalSymbol(s)) {
                    continue;
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("library", s.getParentNamespace() != null ? s.getParentNamespace().getName() : null);
                row.put("name", s.getName());
                row.put("ordinal", null);
                row.put("address", s.getAddress() != null ? s.getAddress().getOffset() : null);
                row.put("thunk_address", null);
                writeJsonLine(w, row);
            }
        }
    }

    private void writeExports(File outDir) throws Exception {
        SymbolTable table = currentProgram.getSymbolTable();
        File outFile = new File(outDir, "exports.jsonl");
        try (BufferedWriter w = writer(outFile)) {
            SymbolIterator it = table.getAllSymbols(true);
            while (it.hasNext()) {
                Symbol s = it.next();
                if (!isExportSymbol(s)) {
                    continue;
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", s.getName());
                row.put("ordinal", null);
                row.put("address", s.getAddress() != null ? s.getAddress().getOffset() : null);
                row.put("forwarder", null);
                writeJsonLine(w, row);
            }
        }
    }

    private void writeSymbols(File outDir) throws Exception {
        SymbolTable table = currentProgram.getSymbolTable();
        File outFile = new File(outDir, "symbols.jsonl");
        try (BufferedWriter w = writer(outFile)) {
            SymbolIterator it = table.getAllSymbols(true);
            while (it.hasNext()) {
                Symbol s = it.next();
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", s.getName());
                row.put("demangled_name", s.getName(true));
                row.put("kind", symbolKind(s));
                row.put("address", s.getAddress() != null ? s.getAddress().getOffset() : null);
                row.put("size", 0);
                writeJsonLine(w, row);
            }
        }
    }

    private void writeFunctions(File outDir) throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        File outFile = new File(outDir, "functions.jsonl");
        try (BufferedWriter w = writer(outFile)) {
            FunctionIterator it = fm.getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                AddressSetView body = f.getBody();
                Address min = body.getMinAddress();
                Address max = body.getMaxAddress();
                long start = min != null ? min.getOffset() : f.getEntryPoint().getOffset();
                long end = max != null ? max.getOffset() + 1 : start;
                long size = body != null ? body.getNumAddresses() : 0;
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("function_va", f.getEntryPoint().getOffset());
                row.put("name", f.getName());
                row.put("demangled_name", f.getName(true));
                row.put("start_va", start);
                row.put("end_va", end);
                row.put("size", size);
                row.put("is_thunk", f.isThunk() ? 1 : 0);
                row.put("is_library", isLibraryFunction(f) ? 1 : 0);
                writeJsonLine(w, row);
            }
        }
    }

    private void writeStrings(File outDir) throws Exception {
        Listing listing = currentProgram.getListing();
        File outFile = new File(outDir, "strings.jsonl");
        try (BufferedWriter w = writer(outFile)) {
            for (Data data : listing.getDefinedData(true)) {
                if (!data.hasStringValue()) {
                    continue;
                }
                Object val = data.getValue();
                String text = val == null ? "" : String.valueOf(val);
                DataType dt = data.getDataType();
                String encoding = dt != null ? dt.getName() : "";
                String sectionName = null;
                MemoryBlock block = currentProgram.getMemory().getBlock(data.getAddress());
                if (block != null) {
                    sectionName = block.getName();
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("address", data.getAddress().getOffset());
                row.put("encoding", encoding);
                row.put("length", data.getLength());
                row.put("string", text);
                row.put("section_name", sectionName);
                writeJsonLine(w, row);
            }
        }
    }

    private void writePseudocode(File outDir, List<Long> onlyFunctions, File outputOverride) throws Exception {
        File outFile = outputOverride != null ? outputOverride : new File(outDir, "pseudocode.jsonl");
        DecompInterface ifc = new DecompInterface();
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(currentProgram)) {
            return;
        }
        int total = 0;
        if (onlyFunctions != null && !onlyFunctions.isEmpty()) {
            total = onlyFunctions.size();
        } else {
            total = currentProgram.getFunctionManager().getFunctionCount();
        }
        int logEvery = Math.max(1, total / 20);
        int processed = 0;
        try (BufferedWriter w = writer(outFile)) {
            if (onlyFunctions != null && !onlyFunctions.isEmpty()) {
                Collections.sort(onlyFunctions);
                FunctionManager fm = currentProgram.getFunctionManager();
                for (Long addrVal : onlyFunctions) {
                    if (addrVal == null) {
                        continue;
                    }
                    Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrVal);
                    Function f = fm.getFunctionAt(addr);
                    if (f == null) {
                        continue;
                    }
                    writePseudocodeForFunction(ifc, w, f);
                    processed += 1;
                    if (processed % logEvery == 0) {
                        println("Pseudocode progress " + processed + "/" + total);
                    }
                }
            } else {
                FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
                while (it.hasNext()) {
                    Function f = it.next();
                    writePseudocodeForFunction(ifc, w, f);
                    processed += 1;
                    if (processed % logEvery == 0) {
                        println("Pseudocode progress " + processed + "/" + total);
                    }
                }
            }
        } finally {
            ifc.dispose();
        }
    }

    private void writePseudocodeParallel(File outDir, int threads, int chunkSize) throws Exception {
        File outFile = new File(outDir, "pseudocode.jsonl");
        List<Function> all = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            all.add(it.next());
        }
        if (all.isEmpty()) {
            try (BufferedWriter w = writer(outFile)) {
            }
            return;
        }
        List<List<Function>> batches = buildBatches(all, threads, chunkSize);
        println("Pseudocode parallel total " + all.size() + " batches " + batches.size());
        AtomicInteger processed = new AtomicInteger(0);
        int total = all.size();
        int logEvery = Math.max(1, total / 20);
        ExecutorService executor = Executors.newFixedThreadPool(Math.max(1, threads));
        try (BufferedWriter w = writer(outFile)) {
            for (List<Function> batch : batches) {
                executor.submit(() -> {
                    DecompInterface local = new DecompInterface();
                    local.setSimplificationStyle("decompile");
                    try {
                        if (!local.openProgram(currentProgram)) {
                            return;
                        }
                        for (Function f : batch) {
                            DecompileResults res = local.decompileFunction(f, 30, monitor);
                            if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) {
                                continue;
                            }
                            String content = res.getDecompiledFunction().getC();
                            if (content == null) {
                                continue;
                            }
                            Map<String, Object> row = new LinkedHashMap<>();
                            row.put("function_va", f.getEntryPoint().getOffset());
                            row.put("content", content);
                            synchronized (w) {
                                writeJsonLine(w, row);
                            }
                            int done = processed.incrementAndGet();
                            if (done % logEvery == 0) {
                                println("Pseudocode progress " + done + "/" + total);
                            }
                        }
                    } catch (Exception e) {
                    } finally {
                        try {
                            local.dispose();
                        } catch (Exception ignore) {
                        }
                    }
                });
            }
            executor.shutdown();
            executor.awaitTermination(12, TimeUnit.HOURS);
        }
    }

    private void writePseudocodeForFunction(DecompInterface ifc, BufferedWriter w, Function f) throws Exception {
        DecompileResults res = ifc.decompileFunction(f, 30, monitor);
        if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) {
            return;
        }
        String content = res.getDecompiledFunction().getC();
        if (content == null) {
            return;
        }
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("function_va", f.getEntryPoint().getOffset());
        row.put("content", content);
        writeJsonLine(w, row);
    }

    private List<Long> readFunctionList(String path) {
        File file = new File(path);
        if (!file.isFile()) {
            return null;
        }
        List<Long> out = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                try {
                    if (line.startsWith("0x") || line.startsWith("0X")) {
                        out.add(Long.parseLong(line.substring(2), 16));
                    } else {
                        out.add(Long.parseLong(line));
                    }
                } catch (Exception e) {
                    continue;
                }
            }
        } catch (Exception e) {
            return null;
        }
        return out;
    }

    private void writeDisasmChunks(File outDir) throws Exception {
        Listing listing = currentProgram.getListing();
        File outFile = new File(outDir, "disasm_chunks.jsonl");
        int chunkSize = 100;
        int lineCount = 0;
        long chunkStart = 0;
        long chunkEnd = 0;
        StringBuilder buf = new StringBuilder();
        InstructionIterator it = listing.getInstructions(true);
        try (BufferedWriter w = writer(outFile)) {
            while (it.hasNext()) {
                Instruction insn = it.next();
                String text = insn.toString();
                if (text == null || text.isEmpty()) {
                    continue;
                }
                long addr = insn.getAddress().getOffset();
                if (lineCount == 0) {
                    chunkStart = addr;
                }
                buf.append("0x").append(Long.toHexString(addr)).append(": ").append(text).append("\n");
                chunkEnd = addr + insn.getLength();
                lineCount += 1;
                if (lineCount >= chunkSize) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("start_va", chunkStart);
                    row.put("end_va", chunkEnd);
                    row.put("content", buf.toString().trim());
                    writeJsonLine(w, row);
                    buf.setLength(0);
                    lineCount = 0;
                }
            }
            if (lineCount > 0) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("start_va", chunkStart);
                row.put("end_va", chunkEnd);
                row.put("content", buf.toString().trim());
                writeJsonLine(w, row);
            }
        }
    }

    private void writeXrefs(File outDir) throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        File outFile = new File(outDir, "xrefs.jsonl");
        try (BufferedWriter w = writer(outFile)) {
            for (CodeUnit cu : listing.getCodeUnits(true)) {
                Address from = cu.getAddress();
                Reference[] refs = cu.getReferencesFrom();
                if (refs == null || refs.length == 0) {
                    continue;
                }
                Function fromFunc = fm.getFunctionContaining(from);
                Long fromFuncVa = fromFunc != null ? fromFunc.getEntryPoint().getOffset() : null;
                for (Reference ref : refs) {
                    Address to = ref.getToAddress();
                    if (to == null) {
                        continue;
                    }
                    Function toFunc = fm.getFunctionContaining(to);
                    Long toFuncVa = toFunc != null ? toFunc.getEntryPoint().getOffset() : null;
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("from_va", from.getOffset());
                    row.put("to_va", to.getOffset());
                    row.put("from_function_va", fromFuncVa);
                    row.put("to_function_va", toFuncVa);
                    row.put("xref_type", xrefType(ref));
                    row.put("operand_index", ref.getOperandIndex());
                    writeJsonLine(w, row);
                }
            }
        }
    }

    private void writeCallEdges(File outDir) throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        File outFile = new File(outDir, "call_edges.jsonl");
        try (BufferedWriter w = writer(outFile)) {
            FunctionIterator fit = fm.getFunctions(true);
            while (fit.hasNext()) {
                Function func = fit.next();
                InstructionIterator it = listing.getInstructions(func.getBody(), true);
                while (it.hasNext()) {
                    Instruction insn = it.next();
                    Reference[] refs = insn.getReferencesFrom();
                    if (refs == null || refs.length == 0) {
                        continue;
                    }
                    for (Reference ref : refs) {
                        RefType rt = ref.getReferenceType();
                        if (rt == null || (!rt.isCall() && !rt.isJump())) {
                            continue;
                        }
                        Address to = ref.getToAddress();
                        if (to == null) {
                            continue;
                        }
                        Function callee = fm.getFunctionContaining(to);
                        if (callee == null) {
                            continue;
                        }
                        if (rt.isJump() && callee.getEntryPoint().equals(func.getEntryPoint())) {
                            continue;
                        }
                        Map<String, Object> row = new LinkedHashMap<>();
                        row.put("caller_function_va", func.getEntryPoint().getOffset());
                        row.put("callee_function_va", callee.getEntryPoint().getOffset());
                        row.put("call_site_va", insn.getAddress().getOffset());
                        row.put("call_type", "direct");
                        writeJsonLine(w, row);
                    }
                }
            }
        }
    }

    private BufferedWriter writer(File file) throws Exception {
        return new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8));
    }

    private void writeJsonObject(File file, Map<String, Object> obj) throws Exception {
        try (BufferedWriter w = writer(file)) {
            w.write(toJson(obj));
        }
    }

    private void writeJsonLine(BufferedWriter w, Map<String, Object> obj) throws Exception {
        w.write(toJson(obj));
        w.newLine();
    }

    private int parseIntArg(String[] args, String flag, int def) {
        if (args == null || args.length == 0) {
            return def;
        }
        for (int i = 0; i < args.length - 1; i++) {
            if (flag.equalsIgnoreCase(args[i])) {
                try {
                    return Integer.parseInt(args[i + 1]);
                } catch (Exception e) {
                    return def;
                }
            }
        }
        return def;
    }

    private String parseStringArg(String[] args, String flag, String def) {
        if (args == null || args.length == 0) {
            return def;
        }
        for (int i = 0; i < args.length - 1; i++) {
            if (flag.equalsIgnoreCase(args[i])) {
                return args[i + 1];
            }
        }
        return def;
    }

    private List<String> parsePositionalArgs(String[] args) {
        List<String> out = new ArrayList<>();
        if (args == null || args.length == 0) {
            return out;
        }
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--threads".equalsIgnoreCase(arg) || "--chunk".equalsIgnoreCase(arg) || "--export-c".equalsIgnoreCase(arg)) {
                i += 1;
                continue;
            }
            out.add(arg);
        }
        return out;
    }

    private List<List<Function>> buildBatches(List<Function> functions, int threads, int chunkSize) {
        List<List<Function>> batches = new ArrayList<>();
        if (chunkSize != 0) {
            int size = Math.max(1, chunkSize);
            for (int i = 0; i < functions.size(); i += size) {
                int end = Math.min(functions.size(), i + size);
                batches.add(new ArrayList<>(functions.subList(i, end)));
            }
            return batches;
        }
        int t = Math.max(1, threads);
        int base = functions.size() / t;
        int rem = functions.size() % t;
        int start = 0;
        for (int i = 0; i < t; i++) {
            int size = base + (i < rem ? 1 : 0);
            if (size <= 0) {
                continue;
            }
            batches.add(new ArrayList<>(functions.subList(start, start + size)));
            start += size;
        }
        return batches;
    }

    private String toJson(Object v) {
        if (v == null) {
            return "null";
        }
        if (v instanceof String) {
            return "\"" + escape((String) v) + "\"";
        }
        if (v instanceof Number || v instanceof Boolean) {
            return String.valueOf(v);
        }
        if (v instanceof Map) {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            boolean first = true;
            for (Object entryObj : ((Map<?, ?>) v).entrySet()) {
                Map.Entry<?, ?> entry = (Map.Entry<?, ?>) entryObj;
                if (!first) {
                    sb.append(",");
                }
                first = false;
                sb.append("\"").append(escape(String.valueOf(entry.getKey()))).append("\":");
                sb.append(toJson(entry.getValue()));
            }
            sb.append("}");
            return sb.toString();
        }
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            boolean first = true;
            for (Object item : (List<?>) v) {
                if (!first) {
                    sb.append(",");
                }
                first = false;
                sb.append(toJson(item));
            }
            sb.append("]");
            return sb.toString();
        }
        return "\"" + escape(String.valueOf(v)) + "\"";
    }

    private String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private double computeEntropy(MemoryBlock block) throws Exception {
        if (!block.isInitialized()) {
            return 0.0;
        }
        long size = block.getSize();
        if (size <= 0) {
            return 0.0;
        }
        int[] counts = new int[256];
        Memory mem = currentProgram.getMemory();
        Address start = block.getStart();
        int chunk = 4096;
        byte[] buf = new byte[chunk];
        long pos = 0;
        while (pos < size) {
            int len = (int) Math.min(chunk, size - pos);
            mem.getBytes(start.add(pos), buf, 0, len);
            for (int i = 0; i < len; i++) {
                counts[buf[i] & 0xff] += 1;
            }
            pos += len;
        }
        double entropy = 0.0;
        double total = (double) size;
        for (int i = 0; i < counts.length; i++) {
            int c = counts[i];
            if (c == 0) {
                continue;
            }
            double p = c / total;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private String hashFile(String path, String algo) {
        try {
            MessageDigest md = MessageDigest.getInstance(algo);
            try (FileInputStream in = new FileInputStream(path)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    if (n > 0) {
                        md.update(buf, 0, n);
                    }
                }
            }
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private String crc32File(String path) {
        try {
            CRC32 crc = new CRC32();
            try (FileInputStream in = new FileInputStream(path)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    if (n > 0) {
                        crc.update(buf, 0, n);
                    }
                }
            }
            return String.valueOf(crc.getValue());
        } catch (Exception e) {
            return "";
        }
    }

    private boolean isLibraryFunction(Function f) {
        try {
            return f.isExternal();
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isExternalSymbol(Symbol s) {
        try {
            Method m = s.getClass().getMethod("isExternal");
            Object v = m.invoke(s);
            return v instanceof Boolean && (Boolean) v;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isExportSymbol(Symbol s) {
        try {
            Method m = s.getClass().getMethod("isExternalEntryPoint");
            Object v = m.invoke(s);
            if (v instanceof Boolean && (Boolean) v) {
                return true;
            }
        } catch (Exception e) {
        }
        try {
            Method m = s.getClass().getMethod("isEntryPoint");
            Object v = m.invoke(s);
            if (v instanceof Boolean && (Boolean) v) {
                return true;
            }
        } catch (Exception e) {
        }
        return false;
    }

    private String symbolKind(Symbol s) {
        SymbolType t = s.getSymbolType();
        String name = t != null ? t.toString().toLowerCase() : "unknown";
        if (name.contains("function")) {
            return "function";
        }
        if (name.contains("label")) {
            return "label";
        }
        if (name.contains("data")) {
            return "data";
        }
        return "unknown";
    }

    private int countImports() {
        int count = 0;
        SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (isExternalSymbol(s)) {
                count += 1;
            }
        }
        return count;
    }

    private String xrefType(Reference ref) {
        RefType rt = ref.getReferenceType();
        if (rt != null) {
            if (rt.isCall()) {
                return "call";
            }
            if (rt.isJump()) {
                return "jmp";
            }
            if (rt.isRead()) {
                return "data_read";
            }
            if (rt.isWrite()) {
                return "data_write";
            }
        }
        String name = rt != null ? rt.getName() : null;
        if (name != null && name.toLowerCase().contains("offset")) {
            return "offset";
        }
        return "unknown";
    }

    private int countExports() {
        int count = 0;
        SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (isExportSymbol(s)) {
                count += 1;
            }
        }
        return count;
    }

    private int countStrings() {
        int count = 0;
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            if (data.hasStringValue()) {
                count += 1;
            }
        }
        return count;
    }

    private Set<String> collectLibraries() {
        Set<String> libs = new LinkedHashSet<>();
        SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (isExternalSymbol(s)) {
                if (s.getParentNamespace() != null) {
                    libs.add(s.getParentNamespace().getName());
                }
            }
        }
        return libs;
    }
}

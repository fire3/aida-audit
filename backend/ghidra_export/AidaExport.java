import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.CRC32;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceType;
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
        File outDir = new File(args[0]);
        outDir.mkdirs();
        writeMetadata(outDir);
        writeSegments(outDir);
        writeSections(outDir);
        writeImports(outDir);
        writeExports(outDir);
        writeSymbols(outDir);
        writeFunctions(outDir);
        writeStrings(outDir);
        writePseudocode(outDir);
        writeXrefs(outDir);
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

    private void writePseudocode(File outDir) throws Exception {
        File outFile = new File(outDir, "pseudocode.jsonl");
        DecompInterface ifc = new DecompInterface();
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(currentProgram)) {
            return;
        }
        try (BufferedWriter w = writer(outFile)) {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                DecompileResults res = ifc.decompileFunction(f, 30, monitor);
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
                writeJsonLine(w, row);
            }
        } finally {
            ifc.dispose();
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
        ReferenceType rt = ref.getReferenceType();
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

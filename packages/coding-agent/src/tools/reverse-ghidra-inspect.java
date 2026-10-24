// Reverse Ghidra Inspect bundled script for headless decompilation & export
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.data.*;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.util.exception.CancelledException;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
public class ReverseGhidraInspect extends GhidraScript {

    private static final String START_TOKEN = "<<<REVERSE_GHIDRA_OUTPUT_START>>>";
    private static final String END_TOKEN = "<<<REVERSE_GHIDRA_OUTPUT_END>>>";

    private int maxSerializedBytes = 262144;

    @Override
    public void run() throws Exception {
        try {
            String[] args = getScriptArgs();
            String action = args != null && args.length > 0 ? args[0] : "decompile";
            String target = args != null && args.length > 1 ? args[1] : "";
            int timeoutSec = 60;
            if (args != null && args.length > 2) {
                try {
                    timeoutSec = Math.max(5, Integer.parseInt(args[2]));
                } catch (Exception ignored) {
                }
            }
            if (args != null && args.length > 3) {
                try {
                    maxSerializedBytes = Math.max(1024, Integer.parseInt(args[3]));
                } catch (Exception ignored) {
                }
            }

            if ("jni_enrich".equalsIgnoreCase(action)) {
                handleJniEnrich(args, target, timeoutSec);
            } else if ("findcrypt".equalsIgnoreCase(action)) {
                handleFindCrypt(target, timeoutSec);
            } else if ("export".equalsIgnoreCase(action)) {
                if (target != null && !target.trim().isEmpty()) {
                    decompileFunctionTarget(target, timeoutSec, true);
                } else {
                    handleInventoryExport();
                }
            } else {
                decompileFunctionTarget(target, timeoutSec, false);
            }
        } catch (CancelledException ce) {
            // 捕获取消异常，避免中断导致非结构化崩溃
            emitError("CANCELLED", "Script execution was cancelled.");
        } catch (Exception e) {
            emitError("SCRIPT_EXCEPTION", e.getClass().getSimpleName() + ": " + (e.getMessage() != null ? e.getMessage() : e.toString()));
        }
    }

    // 支持带或不带 0x 前缀的十六进制虚拟地址解析
    private Address parseAddressString(String addrStr) {
        if (addrStr == null || addrStr.trim().isEmpty()) return null;
        String clean = addrStr.trim();
        try {
            return toAddr(clean);
        } catch (Exception e1) {
            if (!clean.startsWith("0x") && !clean.startsWith("0X")) {
                try {
                    return toAddr("0x" + clean);
                } catch (Exception e2) {
                    return null;
                }
            }
            return null;
        }
    }

    // 支持纯函数名与带命名空间/作用域全名（如 ns::func）的双向匹配
    private boolean matchesName(Function f, String query) {
        return f.getName().equals(query) || f.getName(true).equals(query);
    }

    // 优先精确虚拟地址匹配，未命中再检索全局符号表与函数管理器
    private List<Function> resolveTarget(String target) throws Exception {
        List<Function> results = new ArrayList<Function>();
        if (target == null || target.trim().isEmpty()) {
            return results;
        }
        String query = target.trim();

        // 1. 优先检查是否为显式十六进制虚拟地址
        boolean explicitHex = query.startsWith("0x") || query.startsWith("0X");
        if (explicitHex) {
            Address addr = parseAddressString(query);
            if (addr != null) {
                Function func = getFunctionAt(addr);
                // 地址可能位于函数体内而非入口点，支持包含查找
                if (func == null) {
                    func = getFunctionContaining(addr);
                }
                if (func != null) {
                    results.add(func);
                    return results;
                }
            }
            return results;
        }

        // 2. 通过全局符号与函数表检索
        List<Function> globalFuncs = getGlobalFunctions(query);
        if (globalFuncs != null) {
            for (Function f : globalFuncs) {
                if (!results.contains(f)) {
                    results.add(f);
                }
            }
        }

        // 3. 全局未命中时遍历函数管理器，匹配带作用域的全限定名
        if (results.isEmpty()) {
            FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
            while (iter.hasNext()) {
                monitor.checkCancelled();
                Function f = iter.next();
                if (matchesName(f, query)) {
                    if (!results.contains(f)) {
                        results.add(f);
                    }
                }
            }
        }

        // 4. 尝试不带 0x 前缀的十六进制地址后备查找
        if (results.isEmpty() && query.matches("^[0-9a-fA-F]{1,16}$")) {
            Address addr = parseAddressString(query);
            if (addr != null) {
                Function func = getFunctionAt(addr);
                if (func == null) {
                    func = getFunctionContaining(addr);
                }
                if (func != null) {
                    results.add(func);
                }
            }
        }

        return results;
    }

    // 未指定目标时，按常见入口优先级（main/_start 等）寻找默认反编译函数
    private Function findDefaultFunction() throws Exception {
        String[] candidates = new String[] { "main", "_main", "_start", "entry", "start" };
        for (String candidate : candidates) {
            monitor.checkCancelled();
            List<Function> funcs = getGlobalFunctions(candidate);
            if (funcs != null) {
                for (Function f : funcs) {
                    if (!f.isExternal()) return f;
                }
            }
            FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
            while (iter.hasNext()) {
                monitor.checkCancelled();
                Function f = iter.next();
                if (f.getName().equalsIgnoreCase(candidate) && !f.isExternal()) {
                    return f;
                }
            }
        }

        // 无标准入口名时，取首个非外部非 thunk 的实际定义函数
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        Function firstAny = null;
        while (iter.hasNext()) {
            monitor.checkCancelled();
            Function f = iter.next();
            if (firstAny == null) firstAny = f;
            if (!f.isExternal() && !f.isThunk()) {
                return f;
            }
        }
        return firstAny;
    }

    // 调用 Ghidra 反编译器内核执行目标函数反编译，export 模式附加元数据头
    private void decompileFunctionTarget(String target, int timeoutSec, boolean isExport) throws Exception {
        Function func = null;
        if (target != null && !target.trim().isEmpty()) {
            List<Function> matches = resolveTarget(target);
            if (matches.isEmpty()) {
                emitError("TARGET_NOT_FOUND", "Function target '" + target + "' was not found in binary '" + currentProgram.getName() + "'.");
                return;
            }
            if (matches.size() > 1) {
                StringBuilder sb = new StringBuilder();
                sb.append("Ambiguous function target '").append(target).append("' matched ").append(matches.size()).append(" functions: [");
                for (int i = 0; i < matches.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(matches.get(i).getEntryPoint().toString());
                }
                sb.append("]. Please specify a virtual address.");
                emitError("AMBIGUOUS_TARGET", sb.toString());
                return;
            }
            func = matches.get(0);
        } else {
            func = findDefaultFunction();
            if (func == null) {
                emitError("NO_FUNCTIONS", "No functions found in binary '" + currentProgram.getName() + "' to decompile.");
                return;
            }
        }

        DecompInterface decomp = new DecompInterface();
        try {
            if (!decomp.openProgram(currentProgram)) {
                emitError("DECOMPILE_INIT_FAILED", "Failed to open program in Ghidra decompiler: " + currentProgram.getName());
                return;
            }
            DecompileResults results = decomp.decompileFunction(func, timeoutSec, monitor);
            if (results == null) {
                emitError("DECOMPILE_FAILED", "Decompiler returned null results for function: " + func.getName());
                return;
            }
            if (!results.decompileCompleted()) {
                emitError("DECOMPILE_FAILED", "Decompilation failed for function '" + func.getName() + "' at " + func.getEntryPoint() + ": " + results.getErrorMessage());
                return;
            }
            DecompiledFunction decompFunc = results.getDecompiledFunction();
            String cCode = decompFunc != null ? decompFunc.getC() : null;
            if (cCode == null || cCode.trim().isEmpty()) {
                emitError("EMPTY_DECOMPILATION", "Decompiler produced empty pseudocode for function: " + func.getName());
                return;
            }

            String sig = (decompFunc != null && decompFunc.getSignature() != null)
                ? decompFunc.getSignature()
                : func.getSignature().getPrototypeString();

            String outputText;
            if (isExport) {
                StringBuilder out = new StringBuilder();
                out.append("// Exported function: ").append(func.getName()).append("\n");
                out.append("// Entry: ").append(func.getEntryPoint().toString()).append("\n");
                out.append("// Program: ").append(currentProgram.getName()).append("\n");
                out.append("// Size: ").append(func.getBody().getNumAddresses()).append(" bytes\n\n");
                out.append(cCode);
                outputText = out.toString();
            } else {
                outputText = cCode;
            }

            emitSuccess(isExport ? "export" : "decompile", func.getName(), func.getEntryPoint().toString(), sig, outputText);
        } finally {
            decomp.dispose();
        }
    }

    // 导出二进制函数与符号清单，严格限制数量防止大文件耗尽内存
    private void handleInventoryExport() throws Exception {
        StringBuilder out = new StringBuilder();
        out.append("# Ghidra Analysis Export: ").append(currentProgram.getName()).append("\n");
        out.append("# Executable Format: ").append(currentProgram.getExecutableFormat()).append("\n");
        out.append("# Language: ").append(currentProgram.getLanguageID().toString()).append("\n");
        out.append("# Compiler: ").append(currentProgram.getCompilerSpec().getCompilerSpecID().toString()).append("\n");
        out.append("# Base Address: ").append(currentProgram.getImageBase().toString()).append("\n\n");

        out.append("## Functions\n");
        out.append(String.format("%-18s %-8s %-10s %s\n", "Address", "Size", "Type", "Name / Signature"));
        out.append("--------------------------------------------------------------------------------\n");
        int funcCount = 0;
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            monitor.checkCancelled();
            Function f = iter.next();
            funcCount++;
            String type = f.isThunk() ? "Thunk" : (f.isExternal() ? "External" : "Function");
            long size = f.getBody().getNumAddresses();
            String sig = f.getSignature().getPrototypeString();
            out.append(String.format("%-18s %-8d %-10s %s\n", f.getEntryPoint().toString(), size, type, sig));
            if (funcCount >= 500) {
                out.append(String.format("... [truncated at %d functions]\n", funcCount));
                break;
            }
        }
        out.append(String.format("\nTotal functions enumerated: %d\n\n", funcCount));

        out.append("## Symbols\n");
        out.append(String.format("%-18s %-12s %s\n", "Address", "Type", "Name"));
        out.append("--------------------------------------------------------------------------------\n");
        int symCount = 0;
        SymbolIterator symIter = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symIter.hasNext()) {
            monitor.checkCancelled();
            Symbol s = symIter.next();
            if (s.isExternal() || s.getSymbolType() == SymbolType.FUNCTION || s.getSymbolType() == SymbolType.LABEL) {
                symCount++;
                out.append(String.format("%-18s %-12s %s\n", s.getAddress().toString(), s.getSymbolType().toString(), s.getName()));
                if (symCount >= 500) {
                    out.append(String.format("... [truncated at %d symbols]\n", symCount));
                    break;
                }
            }
        }
        out.append(String.format("\nTotal symbols enumerated: %d\n", symCount));

        emitSuccess("export", "summary", currentProgram.getImageBase().toString(), "inventory", out.toString());
    }
    private static class EnrichItem {
        String address;
        String name;
        String signature;
        String prototype;
        Boolean isStatic;
        boolean isThumb;
    }

    private List<EnrichItem> parseEnrichItems(String jsonOrPath, String defaultTarget) {
        List<EnrichItem> items = new ArrayList<EnrichItem>();
        if (jsonOrPath != null && !jsonOrPath.trim().isEmpty()) {
            String content = jsonOrPath.trim();
            File f = new File(content);
            if (f.exists() && f.isFile()) {
                try {
                    content = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
                } catch (Exception ignored) {}
            }

            Pattern objPattern = Pattern.compile("\\{[^{}]*\\}");
            Matcher m = objPattern.matcher(content);
            while (m.find()) {
                String objStr = m.group();
                EnrichItem item = new EnrichItem();
                Matcher mAddr = Pattern.compile("\"(?:address|staticAddress)\"\\s*:\\s*\"([^\"]+)\"").matcher(objStr);
                if (mAddr.find()) item.address = mAddr.group(1);
                Matcher mName = Pattern.compile("\"(?:name|targetFunctionName)\"\\s*:\\s*\"([^\"]+)\"").matcher(objStr);
                if (mName.find()) item.name = mName.group(1);
                Matcher mSig = Pattern.compile("\"signature\"\\s*:\\s*\"([^\"]+)\"").matcher(objStr);
                if (mSig.find()) item.signature = mSig.group(1);
                Matcher mProto = Pattern.compile("\"(?:prototype|cPrototype)\"\\s*:\\s*\"([^\"]+)\"").matcher(objStr);
                if (mProto.find()) item.prototype = mProto.group(1);
                Matcher mStatic = Pattern.compile("\"isStatic\"\\s*:\\s*(true|false)").matcher(objStr);
                if (mStatic.find()) item.isStatic = Boolean.parseBoolean(mStatic.group(1));
                Matcher mThumb = Pattern.compile("\"isThumb\"\\s*:\\s*(true|false)").matcher(objStr);
                if (mThumb.find()) item.isThumb = Boolean.parseBoolean(mThumb.group(1));

                if (item.address != null && !item.address.isEmpty() && item.name != null && !item.name.isEmpty()) {
                    items.add(item);
                }
            }
        }

        if (items.isEmpty() && defaultTarget != null && !defaultTarget.trim().isEmpty() && !defaultTarget.startsWith("[")) {
            EnrichItem single = new EnrichItem();
            single.address = defaultTarget.trim();
            single.name = "JNI_Function_" + defaultTarget.trim().replace("0x", "");
            items.add(single);
        }
        return items;
    }

    private DataType resolveOrGet(DataType dt, DataTypeManager dtm) {
        DataType existing = dtm.getDataType(dt.getCategoryPath(), dt.getName());
        if (existing != null) return existing;
        return dtm.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private void initJniDataTypes(DataTypeManager dtm) throws Exception {
        CategoryPath jniCat = new CategoryPath("/jni");
        int ptrSize = currentProgram.getDefaultPointerSize();

        // Primitive JNI typedefs
        resolveOrGet(new TypedefDataType(jniCat, "jboolean", ByteDataType.dataType), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jbyte", SignedByteDataType.dataType), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jchar", WordDataType.dataType), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jshort", ShortDataType.dataType), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jint", IntegerDataType.dataType), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jlong", LongLongDataType.dataType), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jfloat", FloatDataType.dataType), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jdouble", DoubleDataType.dataType), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jsize", IntegerDataType.dataType), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jobjectRefType", IntegerDataType.dataType), dtm);

        // Object and class types
        StructureDataType jobjectStruct = new StructureDataType(jniCat, "_jobject", 0, dtm);
        DataType resolvedJobjectStruct = resolveOrGet(jobjectStruct, dtm);
        PointerDataType jobjectPtr = new PointerDataType(resolvedJobjectStruct, ptrSize, dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jobject", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jclass", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jstring", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jthrowable", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jarray", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jbyteArray", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jintArray", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jbooleanArray", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jcharArray", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jshortArray", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jlongArray", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jfloatArray", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jdoubleArray", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jobjectArray", jobjectPtr), dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jweak", jobjectPtr), dtm);

        // Opaque handle types and JNI auxiliary structs
        StructureDataType jfieldIDStruct = new StructureDataType(jniCat, "_jfieldID", 0, dtm);
        DataType resolvedJfieldIDStruct = resolveOrGet(jfieldIDStruct, dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jfieldID", new PointerDataType(resolvedJfieldIDStruct, ptrSize, dtm)), dtm);

        StructureDataType jmethodIDStruct = new StructureDataType(jniCat, "_jmethodID", 0, dtm);
        DataType resolvedJmethodIDStruct = resolveOrGet(jmethodIDStruct, dtm);
        resolveOrGet(new TypedefDataType(jniCat, "jmethodID", new PointerDataType(resolvedJmethodIDStruct, ptrSize, dtm)), dtm);

        UnionDataType jvalueUnion = new UnionDataType(jniCat, "jvalue");
        jvalueUnion.add(dtm.getDataType(jniCat, "jboolean"), "z", "");
        jvalueUnion.add(dtm.getDataType(jniCat, "jbyte"), "b", "");
        jvalueUnion.add(dtm.getDataType(jniCat, "jchar"), "c", "");
        jvalueUnion.add(dtm.getDataType(jniCat, "jshort"), "s", "");
        jvalueUnion.add(dtm.getDataType(jniCat, "jint"), "i", "");
        jvalueUnion.add(dtm.getDataType(jniCat, "jlong"), "j", "");
        jvalueUnion.add(dtm.getDataType(jniCat, "jfloat"), "f", "");
        jvalueUnion.add(dtm.getDataType(jniCat, "jdouble"), "d", "");
        jvalueUnion.add(dtm.getDataType(jniCat, "jobject"), "l", "");
        resolveOrGet(jvalueUnion, dtm);

        StructureDataType javaVMTable = new StructureDataType(jniCat, "JNIInvokeInterface_", 0, dtm);
        DataType resolvedJavaVMTable = resolveOrGet(javaVMTable, dtm);
        resolveOrGet(new TypedefDataType(jniCat, "JavaVM", new PointerDataType(resolvedJavaVMTable, ptrSize, dtm)), dtm);

        StructureDataType jniNativeMethod = new StructureDataType(jniCat, "JNINativeMethod", 0, dtm);
        jniNativeMethod.add(new PointerDataType(CharDataType.dataType, ptrSize, dtm), "name", "char*");
        jniNativeMethod.add(new PointerDataType(CharDataType.dataType, ptrSize, dtm), "signature", "char*");
        jniNativeMethod.add(new PointerDataType(DataType.DEFAULT, ptrSize, dtm), "fnPtr", "void*");
        resolveOrGet(jniNativeMethod, dtm);

        StructureDataType jniNativeInterface = new StructureDataType(jniCat, "JNINativeInterface_", 0, dtm);
        PointerDataType pJniTable = new PointerDataType(jniNativeInterface, ptrSize, dtm);
        resolveOrGet(new TypedefDataType(jniCat, "JNIEnv", pJniTable), dtm);

        File jsonFile = null;
        if (getSourceFile() != null) {
            try {
                java.io.File sf = getSourceFile().getFile(false);
                if (sf != null && sf.getParentFile() != null) {
                    jsonFile = new File(sf.getParentFile(), "jni_env.json");
                }
            } catch (Exception ignored) {}
        }
        if (jsonFile == null || !jsonFile.exists()) {
            jsonFile = new File("jni_env.json");
        }
        if (!jsonFile.exists()) {
            throw new Exception("Required JNI metadata asset 'jni_env.json' not found in script directory: " + (jsonFile != null ? jsonFile.getAbsolutePath() : "null"));
        }

        String jsonStr = new String(Files.readAllBytes(jsonFile.toPath()), StandardCharsets.UTF_8);
        JsonArray arr = new Gson().fromJson(jsonStr, JsonArray.class);
        // 固定元数据包含 reserved0..3 与截至 GetObjectRefType 的全部 233 个槽位。
        if (arr == null || arr.size() != 233) {
            throw new Exception("Corrupt or incomplete JNI metadata in jni_env.json: expected 233 entries, got " + (arr != null ? arr.size() : 0));
        }

        for (int i = 0; i < arr.size(); i++) {
            JsonObject obj = arr.get(i).getAsJsonObject();
            String name = obj.get("name").getAsString();
            if (name.startsWith("reserved")) {
                jniNativeInterface.add(new PointerDataType(DataType.DEFAULT, ptrSize, dtm), name, "reserved");
                continue;
            }

            String retType = obj.has("ret") ? obj.get("ret").getAsString() : "void";
            JsonArray argsArr = obj.has("args") ? obj.getAsJsonArray("args") : new JsonArray();

            FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(jniCat, name + "_type");
            funcDef.setReturnType(resolveJniDataType(retType, dtm));

            boolean hasVarArgs = false;
            List<ParameterDefinition> pDefs = new ArrayList<ParameterDefinition>();
            for (int a = 0; a < argsArr.size(); a++) {
                String argT = argsArr.get(a).getAsString();
                if ("...".equals(argT)) {
                    hasVarArgs = true;
                    continue;
                }
                pDefs.add(new ParameterDefinitionImpl("p" + a, resolveJniDataType(argT, dtm), null));
            }
            funcDef.setArguments(pDefs.toArray(new ParameterDefinition[0]));
            if (hasVarArgs) {
                funcDef.setVarArgs(true);
            }
            DataType resolvedDef = dtm.resolve(funcDef, DataTypeConflictHandler.DEFAULT_HANDLER);
            jniNativeInterface.add(new PointerDataType(resolvedDef, ptrSize, dtm), name, name);
        }

        // Re-resolve populated structure with REPLACE_HANDLER so forward typedef points to complete table
        DataType resolvedTable = dtm.resolve(jniNativeInterface, DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(new TypedefDataType(jniCat, "JNIEnv", new PointerDataType(resolvedTable, ptrSize, dtm)), DataTypeConflictHandler.REPLACE_HANDLER);

        int numComps = ((Structure) resolvedTable).getNumComponents();
        if (numComps != arr.size()) {
            throw new Exception("JNINativeInterface_ structure components count mismatch: " + numComps + ", expected " + arr.size());
        }
        int totalSize = resolvedTable.getLength();
        if (totalSize != arr.size() * ptrSize) {
            throw new Exception("JNINativeInterface_ byte size mismatch: " + totalSize + ", expected " + (arr.size() * ptrSize));
        }
    }

    private DataType resolveJniDataType(String rawType, DataTypeManager dtm) {
        if (rawType == null || rawType.isEmpty() || "V".equals(rawType) || "void".equalsIgnoreCase(rawType)) {
            return VoidDataType.dataType;
        }

        CategoryPath jniCat = new CategoryPath("/jni");
        String trimmed = rawType.trim();

        if (trimmed.endsWith("*")) {
            int ptrSize = currentProgram.getDefaultPointerSize();
            String base = trimmed.substring(0, trimmed.length() - 1).trim();
            if (base.startsWith("const ")) {
                base = base.substring(6).trim();
            }
            if ("void".equals(base)) return new PointerDataType(DataType.DEFAULT, ptrSize, dtm);
            if ("char".equals(base)) return new PointerDataType(CharDataType.dataType, ptrSize, dtm);
            if ("JNIEnv".equals(base)) {
                DataType dt = dtm.getDataType(jniCat, "JNIEnv");
                return dt != null ? new PointerDataType(dt, ptrSize, dtm) : new PointerDataType(DataType.DEFAULT, ptrSize, dtm);
            }
            if ("JavaVM".equals(base)) {
                DataType dt = dtm.getDataType(jniCat, "JavaVM");
                return dt != null ? new PointerDataType(dt, ptrSize, dtm) : new PointerDataType(DataType.DEFAULT, ptrSize, dtm);
            }
            if ("jvalue".equals(base)) {
                DataType dt = dtm.getDataType(jniCat, "jvalue");
                return dt != null ? new PointerDataType(dt, ptrSize, dtm) : new PointerDataType(DataType.DEFAULT, ptrSize, dtm);
            }
            if ("JNINativeMethod".equals(base)) {
                DataType dt = dtm.getDataType(jniCat, "JNINativeMethod");
                return dt != null ? new PointerDataType(dt, ptrSize, dtm) : new PointerDataType(DataType.DEFAULT, ptrSize, dtm);
            }
            DataType baseDt = resolveJniDataType(base, dtm);
            return new PointerDataType(baseDt, ptrSize, dtm);
        }

        if (trimmed.startsWith("const ")) {
            return resolveJniDataType(trimmed.substring(6).trim(), dtm);
        }

        if ("Z".equals(trimmed) || "jboolean".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jboolean");
            return dt != null ? dt : ByteDataType.dataType;
        }
        if ("B".equals(trimmed) || "jbyte".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jbyte");
            return dt != null ? dt : SignedByteDataType.dataType;
        }
        if ("C".equals(trimmed) || "jchar".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jchar");
            return dt != null ? dt : WordDataType.dataType;
        }
        if ("S".equals(trimmed) || "jshort".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jshort");
            return dt != null ? dt : ShortDataType.dataType;
        }
        if ("I".equals(trimmed) || "jint".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jint");
            return dt != null ? dt : IntegerDataType.dataType;
        }
        if ("J".equals(trimmed) || "jlong".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jlong");
            return dt != null ? dt : LongLongDataType.dataType;
        }
        if ("F".equals(trimmed) || "jfloat".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jfloat");
            return dt != null ? dt : FloatDataType.dataType;
        }
        if ("D".equals(trimmed) || "jdouble".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jdouble");
            return dt != null ? dt : DoubleDataType.dataType;
        }
        if ("jsize".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jsize");
            return dt != null ? dt : IntegerDataType.dataType;
        }
        if ("char".equals(trimmed)) {
            return CharDataType.dataType;
        }
        if ("int".equals(trimmed)) {
            return IntegerDataType.dataType;
        }
        if ("va_list".equals(trimmed)) {
            return PointerDataType.dataType;
        }
        if ("jobjectRefType".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jobjectRefType");
            return dt != null ? dt : IntegerDataType.dataType;
        }

        if ("jmethodID".equals(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jmethodID");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if ("jfieldID".equals(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jfieldID");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if ("Ljava/lang/String;".equals(trimmed) || "jstring".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jstring");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if ("Ljava/lang/Class;".equals(trimmed) || "jclass".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jclass");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if ("Ljava/lang/Throwable;".equals(trimmed) || "jthrowable".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jthrowable");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if (trimmed.startsWith("[B") || "jbyteArray".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jbyteArray");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if (trimmed.startsWith("[I") || "jintArray".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jintArray");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if (trimmed.startsWith("[Z") || "jbooleanArray".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jbooleanArray");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if (trimmed.startsWith("[C") || "jcharArray".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jcharArray");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if (trimmed.startsWith("[S") || "jshortArray".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jshortArray");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if (trimmed.startsWith("[J") || "jlongArray".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jlongArray");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if (trimmed.startsWith("[F") || "jfloatArray".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jfloatArray");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if (trimmed.startsWith("[D") || "jdoubleArray".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jdoubleArray");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if (trimmed.startsWith("[L") || trimmed.startsWith("[[") || "jobjectArray".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jobjectArray");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if (trimmed.startsWith("[") || "jarray".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jarray");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if ("jweak".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jweak");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if (trimmed.startsWith("L") && trimmed.endsWith(";")) {
            DataType dt = dtm.getDataType(jniCat, "jobject");
            return dt != null ? dt : PointerDataType.dataType;
        }
        if ("jobject".equalsIgnoreCase(trimmed)) {
            DataType dt = dtm.getDataType(jniCat, "jobject");
            return dt != null ? dt : PointerDataType.dataType;
        }

        throw new IllegalArgumentException("Unknown or unmapped JNI type descriptor: " + trimmed);
    }

    private List<Parameter> buildParameters(EnrichItem item, DataTypeManager dtm) throws Exception {
        List<Parameter> params = new ArrayList<Parameter>();
        int ptrSize = currentProgram.getDefaultPointerSize();
        DataType jniEnvTypeDef = dtm.getDataType(new CategoryPath("/jni"), "JNIEnv");
        params.add(new ParameterImpl("env", new PointerDataType(jniEnvTypeDef, ptrSize, dtm), currentProgram));

        if (item.isStatic != null && item.isStatic.booleanValue()) {
            DataType jclassType = resolveJniDataType("jclass", dtm);
            params.add(new ParameterImpl("clazz", jclassType, currentProgram));
        } else {
            DataType jobjectType = resolveJniDataType("jobject", dtm);
            params.add(new ParameterImpl("thiz", jobjectType, currentProgram));
        }

        if (item.signature != null && item.signature.startsWith("(") && item.signature.contains(")")) {
            String paramSec = item.signature.substring(1, item.signature.indexOf(")"));
            int i = 0;
            int argIdx = 0;
            while (i < paramSec.length()) {
                int start = i;
                while (i < paramSec.length() && paramSec.charAt(i) == '[') i++;
                if (i >= paramSec.length()) break;
                if (paramSec.charAt(i) == 'L') {
                    int semi = paramSec.indexOf(';', i);
                    if (semi != -1) {
                        String desc = paramSec.substring(start, semi + 1);
                        DataType dt = resolveJniDataType(desc, dtm);
                        params.add(new ParameterImpl("arg" + argIdx, dt, currentProgram));
                        argIdx++;
                        i = semi + 1;
                        continue;
                    }
                }
                String desc = paramSec.substring(start, i + 1);
                DataType dt = resolveJniDataType(desc, dtm);
                params.add(new ParameterImpl("arg" + argIdx, dt, currentProgram));
                argIdx++;
                i++;
            }
        }
        return params;
    }

    private DataType getReturnTypeFromSignature(String signature, DataTypeManager dtm) {
        if (signature != null && signature.contains(")")) {
            String retSec = signature.substring(signature.indexOf(")") + 1);
            return resolveJniDataType(retSec, dtm);
        }
        return VoidDataType.dataType;
    }

    private void handleJniEnrich(String[] args, String target, int timeoutSec) throws Exception {
        String enrichData = args != null && args.length > 4 ? args[4] : target;
        List<EnrichItem> items = parseEnrichItems(enrichData, target);
        if (items.isEmpty()) {
            emitError("NO_ENRICH_ITEMS", "No valid JNI enrichment items provided to apply.");
            return;
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int jniInitTx = currentProgram.startTransaction("Initialize JNI Data Types");
        try {
            initJniDataTypes(dtm);
            currentProgram.endTransaction(jniInitTx, true);
        } catch (Exception e) {
            currentProgram.endTransaction(jniInitTx, false);
            emitError("JNI_TYPE_INIT_FAILED", "Failed to initialize JNI types: " + e.getMessage());
            return;
        }

        StringBuilder outArray = new StringBuilder();
        outArray.append("[");
        int applied = 0;
        List<String> failedErrors = new ArrayList<String>();

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(currentProgram);
            for (int i = 0; i < items.size(); i++) {
                monitor.checkCancelled();
                EnrichItem item = items.get(i);
                Address addr = parseAddressString(item.address);
                if (addr == null) {
                    failedErrors.add("Invalid address for " + item.name + ": " + item.address);
                    continue;
                }

                // If address has lowest bit set (ARM32 Thumb), clear it for entry point
                if ((addr.getOffset() & 1L) == 1L) {
                    try {
                        addr = addr.subtract(1L);
                    } catch (Exception ignored) {}
                }

                // If relative offset is outside loaded memory, rebase against imageBase
                if (!currentProgram.getMemory().contains(addr)) {
                    try {
                        Address rebased = currentProgram.getImageBase().add(addr.getOffset());
                        if (currentProgram.getMemory().contains(rebased)) {
                            addr = rebased;
                        }
                    } catch (Exception ignored) {}
                }

                int itemTx = currentProgram.startTransaction("Apply JNI Symbol & Prototype: " + item.name);
                boolean itemCommitted = false;
                try {
                    Function func = getFunctionAt(addr);
                    if (func == null) func = getFunctionContaining(addr);
                    if (func == null) {
                        func = createFunction(addr, item.name);
                    }
                    if (func == null) {
                        throw new Exception("Could not find or create function at address: " + addr);
                    }

                    // 1. Rename function with USER_DEFINED source
                    func.setName(item.name, SourceType.USER_DEFINED);

                    // 2. Build parameters and return type
                    List<Parameter> parameters = buildParameters(item, dtm);
                    DataType returnType = getReturnTypeFromSignature(item.signature, dtm);

                    // 3. Set return type
                    func.setReturnType(returnType, SourceType.USER_DEFINED);

                    // 4. Update function parameters with dynamic ABI storage
                    func.updateFunction(
                        null,
                        null,
                        FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true,
                        SourceType.USER_DEFINED,
                        parameters.toArray(new Parameter[0])
                    );

                    // 5. Inspect post-apply signature: ensure changes took effect
                    String postApplySig = func.getSignature().getPrototypeString();
                    if (postApplySig == null || !postApplySig.contains(item.name)) {
                        throw new Exception("Post-apply verification failed: function prototype did not update.");
                    }

                    // Set plate comment
                    try {
                        currentProgram.getListing().setComment(addr, CodeUnit.PLATE_COMMENT, "JNI Dynamic Registration: " + postApplySig);
                    } catch (Exception ignored) {}

                    // 6. Decompile with DecompInterface
                    DecompileResults dRes = decomp.decompileFunction(func, timeoutSec, monitor);
                    if (dRes == null || !dRes.decompileCompleted() || dRes.getDecompiledFunction() == null) {
                        throw new Exception("Post-enrich decompilation failed for " + item.name + ": " + (dRes != null ? dRes.getErrorMessage() : "null"));
                    }
                    String code = dRes.getDecompiledFunction().getC();

                    // Success for this item!
                    itemCommitted = true;

                    if (applied > 0) outArray.append(",");
                    outArray.append("{")
                        .append("\"address\":").append(escapeJson(addr.toString())).append(",")
                        .append("\"name\":").append(escapeJson(item.name)).append(",")
                        .append("\"prototype\":").append(escapeJson(postApplySig)).append(",")
                        .append("\"code\":").append(escapeJson(code))
                        .append("}");
                    applied++;
                } catch (Exception itemErr) {
                    failedErrors.add("Error enriching " + item.name + " at " + item.address + ": " + itemErr.getMessage());
                } finally {
                    currentProgram.endTransaction(itemTx, itemCommitted);
                }
            }
        } finally {
            decomp.dispose();
        }
        outArray.append("]");

        if (applied == 0 && !failedErrors.isEmpty()) {
            emitError("JNI_ENRICH_FAILED", "Failed to apply any JNI prototypes:\n" + String.join("\n", failedErrors));
            return;
        }

        emitSuccess("jni_enrich", target, currentProgram.getImageBase().toString(), "jni_enrichment", outArray.toString());
    }

    private boolean isCryptoKeyword(String text) {
        if (text == null || text.trim().isEmpty()) return false;
        String lower = text.toLowerCase();
        return lower.contains("aes") || lower.contains("des") || lower.contains("sha") ||
               lower.contains("md5") || lower.contains("rc4") || lower.contains("blowfish") ||
               lower.contains("chacha") || lower.contains("curve25519") || lower.contains("crc32") ||
               lower.contains("rsa") || lower.contains("keccak") || lower.contains("sbox") ||
               lower.contains("findcrypt");
    }

    private void handleFindCrypt(String target, int timeoutSec) throws Exception {
        // 1. Attempt to invoke findcrypt.FindCryptAnalyzer via reflection if present in Ghidra classloader
        try {
            Class<?> analyzerCls = Class.forName("findcrypt.FindCryptAnalyzer");
            Object analyzerInst = analyzerCls.getDeclaredConstructor().newInstance();
            Class<?> msgLogCls = Class.forName("ghidra.app.util.importer.MessageLog");
            Object msgLogInst = msgLogCls.getDeclaredConstructor().newInstance();
            java.lang.reflect.Method addedMethod = analyzerCls.getMethod(
                "added",
                ghidra.program.model.listing.Program.class,
                ghidra.program.model.address.AddressSetView.class,
                ghidra.util.task.TaskMonitor.class,
                msgLogCls
            );
            addedMethod.invoke(analyzerInst, currentProgram, currentProgram.getMemory(), monitor, msgLogInst);
            try {
                java.lang.reflect.Method endMethod = analyzerCls.getMethod("analysisEnded", ghidra.program.model.listing.Program.class);
                endMethod.invoke(analyzerInst, currentProgram);
            } catch (Exception ignored) {}
        } catch (Exception ignored) {
            // Analyzer not loaded in JVM or database.json missing; will inspect any existing bookmarks/symbols
        }

        List<String> candidates = new ArrayList<String>();
        BookmarkManager bm = currentProgram.getBookmarkManager();
        if (bm != null) {
            java.util.Iterator<Bookmark> bIter = bm.getBookmarksIterator();
            while (bIter.hasNext()) {
                monitor.checkCancelled();
                Bookmark b = bIter.next();
                String cat = b.getCategory() != null ? b.getCategory() : "";
                String comment = b.getComment() != null ? b.getComment() : "";
                String typeName = b.getTypeString() != null ? b.getTypeString() : "";

                boolean isCrypto = cat.toLowerCase().contains("crypto") ||
                                   cat.toLowerCase().contains("findcrypt") ||
                                   typeName.toLowerCase().contains("crypto") ||
                                   isCryptoKeyword(comment);

                if (isCrypto) {
                    String entry = "{\"address\":" + escapeJson(b.getAddress().toString()) +
                        ",\"algorithm\":" + escapeJson(!comment.isEmpty() ? comment : cat) +
                        ",\"matchType\":\"bookmark\"" +
                        ",\"category\":" + escapeJson(cat) + "}";
                    if (!candidates.contains(entry) && candidates.size() < 300) {
                        candidates.add(entry);
                    }
                }
            }
        }

        SymbolIterator sIter = currentProgram.getSymbolTable().getAllSymbols(true);
        while (sIter.hasNext()) {
            monitor.checkCancelled();
            Symbol s = sIter.next();
            String sName = s.getName();
            if (sName.startsWith("CRYPT_") || sName.toLowerCase().startsWith("crypto_") || sName.toLowerCase().contains("findcrypt") || isCryptoKeyword(sName)) {
                String alg = sName.startsWith("CRYPT_") ? sName.substring(6) : sName;
                String entry = "{\"address\":" + escapeJson(s.getAddress().toString()) +
                    ",\"algorithm\":" + escapeJson(alg) +
                    ",\"matchType\":\"symbol\"" +
                    ",\"category\":\"CRYPT_LABEL\"}";
                if (!candidates.contains(entry) && candidates.size() < 300) {
                    candidates.add(entry);
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < candidates.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(candidates.get(i));
        }
        sb.append("]");

        emitSuccess("findcrypt", target != null ? target : "all", currentProgram.getImageBase().toString(), "FindCryptAnalyzer", sb.toString());
    }


    // 一次性编码为标准 UTF-8 字节流并经由 System.out.write 输出，避免 Windows 平台 JVM 默认字符集转码不一致并保证精准换行
    private void emitResult(String json) {
        byte[] frameBytes = (START_TOKEN + json + END_TOKEN + "\n").getBytes(StandardCharsets.UTF_8);
        if (frameBytes.length > maxSerializedBytes) {
            String errJson = "{\"status\":\"error\"," +
                "\"code\":\"RESULT_TOO_LARGE\"," +
                "\"error\":\"Result frame size (" + frameBytes.length + " bytes) exceeds max_bytes limit (" + maxSerializedBytes + " bytes)\"}";
            frameBytes = (START_TOKEN + errJson + END_TOKEN + "\n").getBytes(StandardCharsets.UTF_8);
        }
        System.out.write(frameBytes, 0, frameBytes.length);
        System.out.flush();
    }

    private void emitSuccess(String action, String target, String address, String signature, String output) {
        String json = "{\"status\":\"ok\"," +
            "\"action\":" + escapeJson(action) + "," +
            "\"target\":" + escapeJson(target) + "," +
            "\"address\":" + escapeJson(address) + "," +
            "\"signature\":" + escapeJson(signature) + "," +
            "\"output\":" + escapeJson(output) + "}";
        emitResult(json);
    }

    private void emitError(String code, String message) {
        String json = "{\"status\":\"error\"," +
            "\"code\":" + escapeJson(code) + "," +
            "\"error\":" + escapeJson(message) + "}";
        emitResult(json);
    }

    private String escapeJson(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder();
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                // 转义尖括号，防止伪代码字符串中包含协议定界符导致外层帧过早截断
                case '<': sb.append("\\u003c"); break;
                case '>': sb.append("\\u003e"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}

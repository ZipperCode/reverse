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
import ghidra.util.exception.CancelledException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

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

            if ("export".equalsIgnoreCase(action)) {
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

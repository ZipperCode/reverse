/**
 * DexSearchBridge - Java Bridge for DexKit Structured Code Search Engine.
 *
 * Upstream: LuckyPray/DexKit (pinned v2.3.0, Core LGPL-3.0, wrapper Apache-2.0).
 * This bridge is an Apache-2.0 thin runner that dynamically interfaces with the
 * external DexKit runtime (JAR + JNI native library). No LGPL-3.0 Core source is vendored.
 *
 * Input: JSON via --input-file <path>, --input <json>, or stdin.
 * Output: JSON response delimited by <<<DEX_SEARCH_OUTPUT_START>>> and <<<DEX_SEARCH_OUTPUT_END>>>.
 */
package org.reverse.dexsearch;

import java.io.*;
import java.lang.reflect.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class DexSearchBridge {

    public static final String START_TOKEN = "<<<DEX_SEARCH_OUTPUT_START>>>";
    public static final String END_TOKEN = "<<<DEX_SEARCH_OUTPUT_END>>>";
    public static final String BRIDGE_VERSION = "2.3.0";

    public static void main(String[] args) {
        String inputJson = null;
        for (int i = 0; i < args.length; i++) {
            if ("--input-file".equals(args[i]) && i + 1 < args.length) {
                try {
                    byte[] bytes = Files.readAllBytes(Paths.get(args[i + 1]));
                    inputJson = new String(bytes, StandardCharsets.UTF_8);
                } catch (Exception e) {
                    emitError("Failed to read input file: " + e.getMessage());
                    return;
                }
                i++;
            } else if ("--input".equals(args[i]) && i + 1 < args.length) {
                inputJson = args[i + 1];
                i++;
            } else if ("--version".equals(args[i])) {
                System.out.println("DexSearchBridge v" + BRIDGE_VERSION);
                return;
            }
        }

        if (inputJson == null || inputJson.trim().isEmpty()) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int read;
                while ((read = System.in.read(buf)) != -1) {
                    baos.write(buf, 0, read);
                }
                inputJson = new String(baos.toByteArray(), StandardCharsets.UTF_8);
            } catch (Exception e) {
                emitError("Failed to read JSON from stdin: " + e.getMessage());
                return;
            }
        }

        if (inputJson.trim().isEmpty()) {
            emitError("No JSON request supplied via --input, --input-file, or stdin");
            return;
        }

        Map<String, Object> request;
        try {
            Object parsed = SimpleJson.parse(inputJson);
            if (!(parsed instanceof Map)) {
                emitError("Invalid JSON request: expected JSON object root");
                return;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> reqMap = (Map<String, Object>) parsed;
            request = reqMap;
        } catch (Exception e) {
            emitError("Failed to parse JSON request: " + e.getMessage());
            return;
        }

        runSearch(request);
    }

    private static void runSearch(Map<String, Object> request) {
        String action = optString(request, "action", optString(request, "type", "class"));
        String target = optString(request, "target", null);
        if (target == null || target.trim().isEmpty()) {
            emitError("Missing required parameter: target (path to .apk or .dex file)");
            return;
        }

        File targetFile = new File(target);
        if (!targetFile.exists() || !targetFile.isFile()) {
            emitError("Target file does not exist: " + target);
            return;
        }

        long rawLimit = optLong(request, "limit", 50L);
        long rawOffset = optLong(request, "offset", 0L);
        int limit = (int) Math.min(500L, Math.max(1L, rawLimit));
        int offset = (int) Math.min((long) Integer.MAX_VALUE, Math.max(0L, rawOffset));

        @SuppressWarnings("unchecked")
        Map<String, Object> query = (Map<String, Object>) request.get("query");
        if (query == null) {
            query = request;
        }

        String customNativeLibPath = optString(request, "nativeLibPath", optString(query, "nativeLibPath", null));

        try {
            // Load JNI native library before invoking DexKitBridge
            loadDexKitNative(customNativeLibPath);

            ClassLoader loader = resolveDexKitClassLoader();
            Class<?> bridgeClass = loader.loadClass("org.luckypray.dexkit.DexKitBridge");
            boolean isRawDex = targetFile.getName().toLowerCase().endsWith(".dex");
            if (!isRawDex && targetFile.length() >= 4) {
                try (InputStream is = new FileInputStream(targetFile)) {
                    byte[] magic = new byte[4];
                    if (is.read(magic) == 4) {
                        isRawDex = (magic[0] == 0x64 && magic[1] == 0x65 && magic[2] == 0x78 && magic[3] == 0x0a);
                    }
                } catch (Exception ignored) {}
            }

            Object bridge;
            if (isRawDex) {
                byte[] dexBytes = Files.readAllBytes(targetFile.toPath());
                Method createMethod = bridgeClass.getMethod("create", byte[][].class);
                bridge = createMethod.invoke(null, (Object) new byte[][] { dexBytes });
            } else {
                Method createMethod = bridgeClass.getMethod("create", String.class);
                bridge = createMethod.invoke(null, targetFile.getAbsolutePath());
            }
            if (bridge == null) {
                emitError("DexKitBridge.create returned null for target: " + target);
                return;
            }

            try {
                Map<String, Object> response = new LinkedHashMap<>();
                response.put("success", true);
                response.put("action", action);
                response.put("target", targetFile.getAbsolutePath());
                response.put("engine", "DexKit " + BRIDGE_VERSION);

                try {
                    Method getDexNumMethod = bridgeClass.getMethod("getDexNum");
                    Object dexNum = getDexNumMethod.invoke(bridge);
                    response.put("dexNum", dexNum);
                } catch (Exception ignored) {
                }

                if ("info".equalsIgnoreCase(action)) {
                    response.put("total", 0);
                    response.put("offset", 0);
                    response.put("limit", limit);
                    response.put("has_more", false);
                    response.put("items", Collections.emptyList());
                    emitOutput(response);
                    return;
                }

                switch (action.toLowerCase()) {
                    case "class":
                    case "find_class":
                        executeFindClass(loader, bridge, query, offset, limit, response);
                        break;
                    case "method":
                    case "find_method":
                        executeFindMethod(loader, bridge, query, offset, limit, response);
                        break;
                    case "field":
                    case "find_field":
                        executeFindField(loader, bridge, query, offset, limit, response);
                        break;
                    case "callers":
                        executeCallers(loader, bridge, query, offset, limit, response);
                        break;
                    case "callees":
                    case "invokes":
                        executeCallees(loader, bridge, query, offset, limit, response);
                        break;
                    case "field_uses":
                    case "field_refs":
                        executeFieldUses(loader, bridge, query, offset, limit, response);
                        break;
                    case "batch_strings":
                        executeBatchStrings(loader, bridge, query, offset, limit, response);
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported action: " + action + ". Supported actions: class, method, field, callers, callees, field_uses, batch_strings, info");
                }
                emitOutput(response);

            } finally {
                try {
                    Method closeMethod = bridgeClass.getMethod("close");
                    closeMethod.invoke(bridge);
                } catch (Exception ignored) {
                }
            }
        } catch (IllegalArgumentException e) {
            emitError(e.getMessage());
        } catch (ClassNotFoundException e) {
            emitError("DexKit runtime classes not found. Ensure dexkit.jar is installed in managed directory: " + e.getMessage());
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            emitError("DexKit execution error: " + cause.getMessage());
        } catch (UnsatisfiedLinkError e) {
            emitError("Failed to link DexKit native library (libdexkit). Verify native library in java.library.path: " + e.getMessage());
        } catch (Exception e) {
            emitError("Failed to execute DexKit search: " + e.getMessage());
        }
    }

    private static void loadDexKitNative(String customNativeLibPath) {
        if (customNativeLibPath != null && !customNativeLibPath.trim().isEmpty()) {
            File f = new File(customNativeLibPath.trim());
            if (f.exists() && f.isFile()) {
                try {
                    System.load(f.getAbsolutePath());
                    return;
                } catch (Throwable ignored) {
                }
            }
        }
        String os = System.getProperty("os.name", "").toLowerCase();
        String libName = os.contains("mac") || os.contains("darwin") ? "libdexkit.dylib" : (os.contains("win") ? "dexkit.dll" : "libdexkit.so");

        File codeLocation = null;
        try {
            codeLocation = new File(DexSearchBridge.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (Exception ignored) {
        }

        List<File> searchDirs = new ArrayList<>();
        if (codeLocation != null) {
            if (codeLocation.isDirectory()) searchDirs.add(codeLocation);
            else if (codeLocation.getParentFile() != null) searchDirs.add(codeLocation.getParentFile());
        }
        searchDirs.add(new File("."));

        String userHome = System.getProperty("user.home");
        if (userHome != null) {
            searchDirs.add(new File(userHome, ".reverse/tools/dexkit"));
        }

        String javaLibPath = System.getProperty("java.library.path");
        if (javaLibPath != null) {
            for (String p : javaLibPath.split(File.pathSeparator)) {
                if (!p.trim().isEmpty()) searchDirs.add(new File(p.trim()));
            }
        }

        for (File dir : searchDirs) {
            File cand = new File(dir, libName);
            if (cand.exists() && cand.isFile()) {
                try {
                    System.load(cand.getAbsolutePath());
                    return;
                } catch (Throwable ignored) {
                }
            }
        }

        try {
            System.loadLibrary("dexkit");
        } catch (Throwable ignored) {
        }
    }

    private static void executeFindClass(ClassLoader loader, Object bridge, Map<String, Object> query, int offset, int limit, Map<String, Object> response) throws Exception {
        Class<?> findClassClz = loader.loadClass("org.luckypray.dexkit.query.FindClass");
        Class<?> classMatcherClz = loader.loadClass("org.luckypray.dexkit.query.matchers.ClassMatcher");
        Class<?> stringMatchTypeClz = loader.loadClass("org.luckypray.dexkit.query.enums.StringMatchType");

        Object finder = findClassClz.getDeclaredConstructor().newInstance();
        Object matcher = classMatcherClz.getDeclaredConstructor().newInstance();

        applyPackageFilters(findClassClz, finder, query);

        String className = optString(query, "className", optString(query, "class", null));
        String stringMatchTypeStr = optString(query, "stringMatchType", optString(query, "string_match_type", "Contains"));
        boolean ignoreCase = optBool(query, "ignoreCase", optBool(query, "ignore_case", false));
        Object matchTypeEnum = resolveEnum(stringMatchTypeClz, stringMatchTypeStr);

        applyClassName(classMatcherClz, matcher, className, matchTypeEnum, ignoreCase, stringMatchTypeClz);

        String superClass = optString(query, "superClass", optString(query, "super_class", null));
        if (superClass != null && !superClass.trim().isEmpty()) {
            Object superMatcher = classMatcherClz.getDeclaredConstructor().newInstance();
            applyClassName(classMatcherClz, superMatcher, superClass.trim(), resolveEnum(stringMatchTypeClz, "Equals"), false, stringMatchTypeClz);
            try {
                Method setSuperClassMethod = classMatcherClz.getMethod("superClass", classMatcherClz);
                setSuperClassMethod.invoke(matcher, superMatcher);
            } catch (NoSuchMethodException e) {
                try {
                    Method setSuperClassMethod = classMatcherClz.getMethod("superClass", String.class);
                    setSuperClassMethod.invoke(matcher, superClass.trim());
                } catch (Exception ignored) {}
            } catch (Exception ignored) {}
        }

        List<String> usingStrings = optStringList(query, "usingStrings", optStringList(query, "using_strings", null));
        applyUsingStrings(classMatcherClz, matcher, usingStrings, matchTypeEnum, ignoreCase, stringMatchTypeClz);

        Object modifiersObj = query.get("modifiers");
        applyModifiers(classMatcherClz, matcher, modifiersObj, loader);

        Method matcherSetter = findClassClz.getMethod("matcher", classMatcherClz);
        matcherSetter.invoke(finder, matcher);

        Method findClassMethod = bridge.getClass().getMethod("findClass", findClassClz);
        Object resultsObj = findClassMethod.invoke(bridge, finder);

        List<?> results = toList(resultsObj);
        int total = results.size();
        response.put("total", total);
        response.put("offset", offset);
        response.put("limit", limit);
        response.put("has_more", ((long) offset + limit) < total);

        List<Map<String, Object>> items = new ArrayList<>();
        int end = (int) Math.min((long) offset + limit, (long) total);
        for (int i = offset; i < end; i++) {
            Object classData = results.get(i);
            items.add(formatClassData(classData));
        }
        response.put("items", items);
    }

    private static void executeFindMethod(ClassLoader loader, Object bridge, Map<String, Object> query, int offset, int limit, Map<String, Object> response) throws Exception {
        Class<?> findMethodClz = loader.loadClass("org.luckypray.dexkit.query.FindMethod");
        Class<?> methodMatcherClz = loader.loadClass("org.luckypray.dexkit.query.matchers.MethodMatcher");
        Class<?> stringMatchTypeClz = loader.loadClass("org.luckypray.dexkit.query.enums.StringMatchType");

        Object finder = findMethodClz.getDeclaredConstructor().newInstance();
        Object matcher = methodMatcherClz.getDeclaredConstructor().newInstance();

        applyPackageFilters(findMethodClz, finder, query);

        String declaredClass = optString(query, "className", optString(query, "class", null));
        String stringMatchTypeStr = optString(query, "stringMatchType", optString(query, "string_match_type", "Contains"));
        boolean ignoreCase = optBool(query, "ignoreCase", optBool(query, "ignore_case", false));
        Object matchTypeEnum = resolveEnum(stringMatchTypeClz, stringMatchTypeStr);

        applyDeclaredClass(methodMatcherClz, matcher, declaredClass, matchTypeEnum, ignoreCase, stringMatchTypeClz);

        String name = optString(query, "name", optString(query, "methodName", optString(query, "method_name", null)));
        applyName(methodMatcherClz, matcher, name, matchTypeEnum, ignoreCase, stringMatchTypeClz);

        String returnType = optString(query, "returnType", optString(query, "return_type", null));
        applyReturnType(methodMatcherClz, matcher, returnType, matchTypeEnum, ignoreCase, stringMatchTypeClz);

        List<String> paramTypes = optStringList(query, "paramTypes", optStringList(query, "param_types", null));
        applyParamTypes(methodMatcherClz, matcher, paramTypes);

        List<String> usingStrings = optStringList(query, "usingStrings", optStringList(query, "using_strings", null));
        applyUsingStrings(methodMatcherClz, matcher, usingStrings, matchTypeEnum, ignoreCase, stringMatchTypeClz);

        List<Number> usingNumbers = optNumberList(query, "usingNumbers", optNumberList(query, "using_numbers", null));
        applyUsingNumbers(methodMatcherClz, matcher, usingNumbers);

        Object modifiersObj = query.get("modifiers");
        applyModifiers(methodMatcherClz, matcher, modifiersObj, loader);

        Method matcherSetter = findMethodClz.getMethod("matcher", methodMatcherClz);
        matcherSetter.invoke(finder, matcher);

        Method findMethodMethod = bridge.getClass().getMethod("findMethod", findMethodClz);
        Object resultsObj = findMethodMethod.invoke(bridge, finder);

        List<?> results = toList(resultsObj);
        int total = results.size();
        response.put("total", total);
        response.put("offset", offset);
        response.put("limit", limit);
        response.put("has_more", ((long) offset + limit) < total);

        List<Map<String, Object>> items = new ArrayList<>();
        int end = (int) Math.min((long) offset + limit, (long) total);
        for (int i = offset; i < end; i++) {
            Object methodData = results.get(i);
            items.add(formatMethodData(methodData));
        }
        response.put("items", items);
    }

    private static void executeFindField(ClassLoader loader, Object bridge, Map<String, Object> query, int offset, int limit, Map<String, Object> response) throws Exception {
        Class<?> findFieldClz = loader.loadClass("org.luckypray.dexkit.query.FindField");
        Class<?> fieldMatcherClz = loader.loadClass("org.luckypray.dexkit.query.matchers.FieldMatcher");
        Class<?> stringMatchTypeClz = loader.loadClass("org.luckypray.dexkit.query.enums.StringMatchType");

        Object finder = findFieldClz.getDeclaredConstructor().newInstance();
        Object matcher = fieldMatcherClz.getDeclaredConstructor().newInstance();

        applyPackageFilters(findFieldClz, finder, query);

        String declaredClass = optString(query, "className", optString(query, "class", null));
        String stringMatchTypeStr = optString(query, "stringMatchType", optString(query, "string_match_type", "Contains"));
        boolean ignoreCase = optBool(query, "ignoreCase", optBool(query, "ignore_case", false));
        Object matchTypeEnum = resolveEnum(stringMatchTypeClz, stringMatchTypeStr);

        applyDeclaredClass(fieldMatcherClz, matcher, declaredClass, matchTypeEnum, ignoreCase, stringMatchTypeClz);

        String name = optString(query, "name", optString(query, "fieldName", optString(query, "field_name", null)));
        applyName(fieldMatcherClz, matcher, name, matchTypeEnum, ignoreCase, stringMatchTypeClz);

        String fieldType = optString(query, "fieldType", optString(query, "type", optString(query, "type_name", null)));
        applyFieldType(fieldMatcherClz, matcher, fieldType, matchTypeEnum, ignoreCase, stringMatchTypeClz);

        Object modifiersObj = query.get("modifiers");
        applyModifiers(fieldMatcherClz, matcher, modifiersObj, loader);

        Method matcherSetter = findFieldClz.getMethod("matcher", fieldMatcherClz);
        matcherSetter.invoke(finder, matcher);

        Method findFieldMethod = bridge.getClass().getMethod("findField", findFieldClz);
        Object resultsObj = findFieldMethod.invoke(bridge, finder);

        List<?> results = toList(resultsObj);
        int total = results.size();
        response.put("total", total);
        response.put("offset", offset);
        response.put("limit", limit);
        response.put("has_more", ((long) offset + limit) < total);

        List<Map<String, Object>> items = new ArrayList<>();
        int end = (int) Math.min((long) offset + limit, (long) total);
        for (int i = offset; i < end; i++) {
            Object fieldData = results.get(i);
            items.add(formatFieldData(fieldData));
        }
        response.put("items", items);
    }

    private static final String[] RELATION_DISALLOWED_KEYS = new String[] {
        "className", "class", "name", "methodName", "method_name", "fieldName", "field_name",
        "returnType", "return_type", "paramTypes", "param_types", "fieldType", "field_type",
        "superClass", "super_class", "usingStrings", "using_strings", "usingNumbers", "using_numbers"
    };

    private static void validateRelationQuery(String action, Map<String, Object> query) {
        for (String key : RELATION_DISALLOWED_KEYS) {
            Object val = query.get(key);
            if (val != null) {
                if (key.equals("paramTypes") || key.equals("param_types")) {
                    throw new IllegalArgumentException("Action '" + action + "' does not support parameter '" + key + "'. Relation queries support target method/field, searchPackages, excludePackages, and modifiers.");
                }
                if (val instanceof String && !((String) val).trim().isEmpty()) {
                    throw new IllegalArgumentException("Action '" + action + "' does not support parameter '" + key + "'. Relation queries support target method/field, searchPackages, excludePackages, and modifiers.");
                }
                if (val instanceof Collection && !((Collection<?>) val).isEmpty()) {
                    throw new IllegalArgumentException("Action '" + action + "' does not support parameter '" + key + "'. Relation queries support target method/field, searchPackages, excludePackages, and modifiers.");
                }
            }
        }
    }

    private static void executeCallers(ClassLoader loader, Object bridge, Map<String, Object> query, int offset, int limit, Map<String, Object> response) throws Exception {
        validateRelationQuery("callers", query);
        String targetMethod = optString(query, "method", optString(query, "target_method", null));
        if (targetMethod == null || targetMethod.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing target_method descriptor for callers query (e.g. Lcom/example/MyClass;->myMethod()V)");
        }
        Method getMethodDataMethod = bridge.getClass().getMethod("getMethodData", String.class);
        Object methodData = getMethodDataMethod.invoke(bridge, targetMethod.trim());
        if (methodData == null) {
            response.put("total", 0);
            response.put("offset", 0);
            response.put("limit", limit);
            response.put("has_more", false);
            response.put("items", Collections.emptyList());
            response.put("note", "Method not found: " + targetMethod);
            return;
        }

        Method getCallersMethod = methodData.getClass().getMethod("getCallers");
        Object callersObj = getCallersMethod.invoke(methodData);
        List<?> callers = filterMethodList(toList(callersObj), query);

        int total = callers.size();
        response.put("total", total);
        response.put("offset", offset);
        response.put("limit", limit);
        response.put("has_more", ((long) offset + limit) < total);

        List<Map<String, Object>> items = new ArrayList<>();
        int end = (int) Math.min((long) offset + limit, (long) total);
        for (int i = offset; i < end; i++) {
            items.add(formatMethodData(callers.get(i)));
        }
        response.put("items", items);
    }

    private static void executeCallees(ClassLoader loader, Object bridge, Map<String, Object> query, int offset, int limit, Map<String, Object> response) throws Exception {
        validateRelationQuery("callees", query);
        String targetMethod = optString(query, "method", optString(query, "target_method", null));
        if (targetMethod == null || targetMethod.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing target_method descriptor for callees query (e.g. Lcom/example/MyClass;->myMethod()V)");
        }
        Method getMethodDataMethod = bridge.getClass().getMethod("getMethodData", String.class);
        Object methodData = getMethodDataMethod.invoke(bridge, targetMethod.trim());
        if (methodData == null) {
            response.put("offset", 0);
            response.put("limit", limit);
            response.put("has_more", false);
            response.put("items", Collections.emptyList());
            response.put("note", "Method not found: " + targetMethod);
            return;
        }

        Method getInvokesMethod = methodData.getClass().getMethod("getInvokes");
        Object invokesObj = getInvokesMethod.invoke(methodData);
        List<?> invokes = filterMethodList(toList(invokesObj), query);

        int total = invokes.size();
        response.put("total", total);
        response.put("offset", offset);
        response.put("limit", limit);
        response.put("has_more", ((long) offset + limit) < total);

        List<Map<String, Object>> items = new ArrayList<>();
        int end = (int) Math.min((long) offset + limit, (long) total);
        for (int i = offset; i < end; i++) {
            items.add(formatMethodData(invokes.get(i)));
        }
        response.put("items", items);
    }

    private static void executeFieldUses(ClassLoader loader, Object bridge, Map<String, Object> query, int offset, int limit, Map<String, Object> response) throws Exception {
        validateRelationQuery("field_uses", query);
        String targetField = optString(query, "field", optString(query, "target_field", null));
        if (targetField == null || targetField.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing target_field descriptor for field_uses query (e.g. Lcom/example/MyClass;->myField:I)");
        }
        Method getFieldDataMethod = bridge.getClass().getMethod("getFieldData", String.class);
        Object fieldData = getFieldDataMethod.invoke(bridge, targetField.trim());
        if (fieldData == null) {
            response.put("offset", 0);
            response.put("limit", limit);
            response.put("has_more", false);
            response.put("readers", Collections.emptyList());
            response.put("writers", Collections.emptyList());
            response.put("note", "Field not found: " + targetField);
            return;
        }

        Method getReadersMethod = fieldData.getClass().getMethod("getReaders");
        Method getWritersMethod = fieldData.getClass().getMethod("getWriters");
        List<?> allReaders = filterMethodList(toList(getReadersMethod.invoke(fieldData)), query);
        List<?> allWriters = filterMethodList(toList(getWritersMethod.invoke(fieldData)), query);

        int totalReaders = allReaders.size();
        int totalWriters = allWriters.size();
        int total = totalReaders + totalWriters;
        response.put("total", total);
        response.put("totalReaders", totalReaders);
        response.put("totalWriters", totalWriters);
        response.put("offset", offset);
        response.put("limit", limit);
        response.put("has_more", ((long) offset + limit) < total);

        List<Map<String, Object>> readerItems = new ArrayList<>();
        List<Map<String, Object>> writerItems = new ArrayList<>();

        for (int i = 0; i < totalReaders; i++) {
            if (i >= offset && readerItems.size() + writerItems.size() < limit) {
                readerItems.add(formatMethodData(allReaders.get(i)));
            }
        }
        int writerOffset = Math.max(0, offset - totalReaders);
        for (int i = 0; i < totalWriters; i++) {
            if (i >= writerOffset && readerItems.size() + writerItems.size() < limit) {
                writerItems.add(formatMethodData(allWriters.get(i)));
            }
        }

        response.put("readers", readerItems);
        response.put("writers", writerItems);
        response.put("targetField", formatFieldData(fieldData));
    }

    private static void executeBatchStrings(ClassLoader loader, Object bridge, Map<String, Object> query, int offset, int limit, Map<String, Object> response) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> groups = (Map<String, Object>) query.get("groups");
        if (groups == null || groups.isEmpty()) {
            throw new IllegalArgumentException("Missing groups mapping for batch_strings query (e.g. { \"group1\": [\"keyword1\", \"keyword2\"] })");
        }

        String batchTarget = optString(query, "batchTarget", optString(query, "batch_target", "method"));
        Class<?> stringMatchTypeClz = loader.loadClass("org.luckypray.dexkit.query.enums.StringMatchType");
        String stringMatchTypeStr = optString(query, "stringMatchType", optString(query, "string_match_type", "Contains"));
        boolean ignoreCase = optBool(query, "ignoreCase", optBool(query, "ignore_case", false));

        Map<String, Object> groupResults = new LinkedHashMap<>();
        int combinedTotal = 0;
        boolean anyHasMore = false;

        if ("class".equalsIgnoreCase(batchTarget)) {
            List<String> baseStrings = optStringList(query, "usingStrings", optStringList(query, "using_strings", null));
            for (Map.Entry<String, Object> entry : groups.entrySet()) {
                String groupName = entry.getKey();
                List<String> words = toStringList(entry.getValue());
                List<String> combinedWords = new ArrayList<>();
                if (baseStrings != null && !baseStrings.isEmpty()) combinedWords.addAll(baseStrings);
                if (words != null && !words.isEmpty()) combinedWords.addAll(words);
                Map<String, Object> subQuery = new HashMap<>(query);
                subQuery.put("usingStrings", combinedWords);
                subQuery.put("stringMatchType", stringMatchTypeStr);
                subQuery.put("ignoreCase", ignoreCase);
                Map<String, Object> subResp = new LinkedHashMap<>();
                executeFindClass(loader, bridge, subQuery, offset, limit, subResp);
                groupResults.put(groupName, subResp.get("items"));
                combinedTotal += optInt(subResp, "total", 0);
                if (optBool(subResp, "has_more", false)) anyHasMore = true;
            }
        } else {
            List<String> baseStrings = optStringList(query, "usingStrings", optStringList(query, "using_strings", null));
            for (Map.Entry<String, Object> entry : groups.entrySet()) {
                String groupName = entry.getKey();
                List<String> words = toStringList(entry.getValue());
                List<String> combinedWords = new ArrayList<>();
                if (baseStrings != null && !baseStrings.isEmpty()) combinedWords.addAll(baseStrings);
                if (words != null && !words.isEmpty()) combinedWords.addAll(words);
                Map<String, Object> subQuery = new HashMap<>(query);
                subQuery.put("usingStrings", combinedWords);
                subQuery.put("stringMatchType", stringMatchTypeStr);
                subQuery.put("ignoreCase", ignoreCase);
                Map<String, Object> subResp = new LinkedHashMap<>();
                executeFindMethod(loader, bridge, subQuery, offset, limit, subResp);
                groupResults.put(groupName, subResp.get("items"));
                combinedTotal += optInt(subResp, "total", 0);
                if (optBool(subResp, "has_more", false)) anyHasMore = true;
            }
        }

        response.put("groups", groupResults);
        response.put("batchTarget", batchTarget);
        response.put("total", combinedTotal);
        response.put("offset", offset);
        response.put("limit", limit);
        response.put("has_more", anyHasMore);
    }

    private static List<Object> filterMethodList(List<?> methods, Map<String, Object> query) {
        List<String> searchPackages = optStringList(query, "searchPackages", optStringList(query, "search_packages", null));
        List<String> excludePackages = optStringList(query, "excludePackages", optStringList(query, "exclude_packages", null));
        Object modifiersObj = query.get("modifiers");
        int modifierMask = parseModifiers(modifiersObj);

        List<Object> filtered = new ArrayList<>();
        for (Object m : methods) {
            if (m == null) continue;
            Class<?> clz = m.getClass();
            String className = invokeString(m, clz, "getClassName");
            Integer mods = invokeInt(m, clz, "getModifiers");

            if (className != null) {
                if (searchPackages != null && !searchPackages.isEmpty()) {
                    boolean match = false;
                    for (String pkg : searchPackages) {
                        String normPkg = normalizeClassName(pkg);
                        if (className.startsWith(normPkg)) { match = true; break; }
                    }
                    if (!match) continue;
                }
                if (excludePackages != null && !excludePackages.isEmpty()) {
                    boolean excluded = false;
                    for (String pkg : excludePackages) {
                        String normPkg = normalizeClassName(pkg);
                        if (className.startsWith(normPkg)) { excluded = true; break; }
                    }
                    if (excluded) continue;
                }
            }

            if (modifierMask != 0 && mods != null) {
                if ((mods & modifierMask) != modifierMask) continue;
            }

            filtered.add(m);
        }
        return filtered;
    }

    private static String normalizeClassName(String name) {
        if (name == null) return null;
        String s = name.trim();
        if (s.startsWith("L") && s.endsWith(";") && s.length() > 2) {
            return s.substring(1, s.length() - 1).replace('/', '.');
        }
        if (s.startsWith("L") && s.contains("/")) {
            return s.substring(1).replace('/', '.');
        }
        return s;
    }

    private static void applyClassName(Class<?> matcherClz, Object matcher, String className, Object matchTypeEnum, boolean ignoreCase, Class<?> stringMatchTypeClz) {
        if (className == null || className.trim().isEmpty()) return;
        String normName = normalizeClassName(className);
        try {
            Method m = matcherClz.getMethod("className", String.class, stringMatchTypeClz, boolean.class);
            m.invoke(matcher, normName, matchTypeEnum, ignoreCase);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("className", String.class, stringMatchTypeClz);
            m.invoke(matcher, normName, matchTypeEnum);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("className", String.class);
            m.invoke(matcher, normName);
        } catch (Exception e) {
            throw new RuntimeException("Failed to apply className: " + e.getMessage(), e);
        }
    }

    private static void applyDeclaredClass(Class<?> matcherClz, Object matcher, String declaredClass, Object matchTypeEnum, boolean ignoreCase, Class<?> stringMatchTypeClz) {
        if (declaredClass == null || declaredClass.trim().isEmpty()) return;
        String normName = normalizeClassName(declaredClass);
        try {
            Method m = matcherClz.getMethod("declaredClass", String.class, stringMatchTypeClz, boolean.class);
            m.invoke(matcher, normName, matchTypeEnum, ignoreCase);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("declaredClass", String.class, stringMatchTypeClz);
            m.invoke(matcher, normName, matchTypeEnum);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("declaredClass", String.class);
            m.invoke(matcher, normName);
        } catch (Exception e) {
            throw new RuntimeException("Failed to apply declaredClass: " + e.getMessage(), e);
        }
    }

    private static void applyName(Class<?> matcherClz, Object matcher, String name, Object matchTypeEnum, boolean ignoreCase, Class<?> stringMatchTypeClz) {
        if (name == null || name.trim().isEmpty()) return;
        try {
            Method m = matcherClz.getMethod("name", String.class, stringMatchTypeClz, boolean.class);
            m.invoke(matcher, name.trim(), matchTypeEnum, ignoreCase);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("name", String.class, stringMatchTypeClz);
            m.invoke(matcher, name.trim(), matchTypeEnum);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("name", String.class);
            m.invoke(matcher, name.trim());
        } catch (Exception e) {
            throw new RuntimeException("Failed to apply name: " + e.getMessage(), e);
        }
    }

    private static void applyReturnType(Class<?> matcherClz, Object matcher, String returnType, Object matchTypeEnum, boolean ignoreCase, Class<?> stringMatchTypeClz) {
        if (returnType == null || returnType.trim().isEmpty()) return;
        try {
            Method m = matcherClz.getMethod("returnType", String.class, stringMatchTypeClz, boolean.class);
            m.invoke(matcher, returnType.trim(), matchTypeEnum, ignoreCase);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("returnType", String.class);
            m.invoke(matcher, returnType.trim());
        } catch (Exception e) {
            throw new RuntimeException("Failed to apply returnType: " + e.getMessage(), e);
        }
    }

    private static void applyFieldType(Class<?> matcherClz, Object matcher, String fieldType, Object matchTypeEnum, boolean ignoreCase, Class<?> stringMatchTypeClz) {
        if (fieldType == null || fieldType.trim().isEmpty()) return;
        try {
            Method m = matcherClz.getMethod("type", String.class, stringMatchTypeClz, boolean.class);
            m.invoke(matcher, fieldType.trim(), matchTypeEnum, ignoreCase);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("type", String.class);
            m.invoke(matcher, fieldType.trim());
        } catch (Exception e) {
            throw new RuntimeException("Failed to apply fieldType: " + e.getMessage(), e);
        }
    }

    private static void applyParamTypes(Class<?> matcherClz, Object matcher, List<String> paramTypes) {
        if (paramTypes == null) return;
        try {
            Method m = matcherClz.getMethod("paramTypes", Collection.class);
            m.invoke(matcher, paramTypes);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("paramTypes", String[].class);
            m.invoke(matcher, (Object) paramTypes.toArray(new String[0]));
        } catch (Exception e) {
            throw new RuntimeException("Failed to apply paramTypes: " + e.getMessage(), e);
        }
    }

    private static void applyUsingStrings(Class<?> matcherClz, Object matcher, List<String> strings, Object matchTypeEnum, boolean ignoreCase, Class<?> stringMatchTypeClz) {
        if (strings == null || strings.isEmpty()) return;
        try {
            Method m = matcherClz.getMethod("usingStrings", Collection.class, stringMatchTypeClz, boolean.class);
            m.invoke(matcher, strings, matchTypeEnum, ignoreCase);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("usingStrings", Collection.class, stringMatchTypeClz);
            m.invoke(matcher, strings, matchTypeEnum);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("usingStrings", Collection.class);
            m.invoke(matcher, strings);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("usingStrings", String[].class);
            m.invoke(matcher, (Object) strings.toArray(new String[0]));
        } catch (Exception e) {
            throw new RuntimeException("Failed to apply usingStrings: " + e.getMessage(), e);
        }
    }

    private static void applyUsingNumbers(Class<?> matcherClz, Object matcher, List<Number> numbers) {
        if (numbers == null || numbers.isEmpty()) return;
        try {
            Method m = matcherClz.getMethod("usingNumbers", Collection.class);
            m.invoke(matcher, numbers);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Method m = matcherClz.getMethod("usingNumbers", Number[].class);
            m.invoke(matcher, (Object) numbers.toArray(new Number[0]));
        } catch (Exception e) {
            throw new RuntimeException("Failed to apply usingNumbers: " + e.getMessage(), e);
        }
    }

    private static int parseModifiers(Object modObj) {
        if (modObj == null) return 0;
        if (modObj instanceof Number) return ((Number) modObj).intValue();
        if (modObj instanceof String) return parseModifierToken((String) modObj);
        if (modObj instanceof Collection) {
            int mask = 0;
            for (Object item : (Collection<?>) modObj) {
                mask |= parseModifierToken(String.valueOf(item));
            }
            return mask;
        }
        return 0;
    }

    private static int parseModifierToken(String token) {
        if (token == null) return 0;
        int mask = 0;
        for (String part : token.trim().toLowerCase().split("[\\s,|]+")) {
            if (part.isEmpty()) continue;
            switch (part) {
                case "public": mask |= Modifier.PUBLIC; break;
                case "private": mask |= Modifier.PRIVATE; break;
                case "protected": mask |= Modifier.PROTECTED; break;
                case "static": mask |= Modifier.STATIC; break;
                case "final": mask |= Modifier.FINAL; break;
                case "synchronized": mask |= Modifier.SYNCHRONIZED; break;
                case "volatile": mask |= Modifier.VOLATILE; break;
                case "transient": mask |= Modifier.TRANSIENT; break;
                case "native": mask |= Modifier.NATIVE; break;
                case "interface": mask |= Modifier.INTERFACE; break;
                case "abstract": mask |= Modifier.ABSTRACT; break;
                case "strict":
                case "strictfp": mask |= Modifier.STRICT; break;
                case "synthetic": mask |= 0x1000; break;
                case "bridge": mask |= 0x0040; break;
                case "varargs": mask |= 0x0080; break;
                case "annotation": mask |= 0x2000; break;
                case "enum": mask |= 0x4000; break;
                default:
                    try {
                        mask |= Integer.parseInt(part);
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException("Unrecognized modifier: '" + part + "'");
                    }
            }
        }
        return mask;
    }
    private static void applyModifiers(Class<?> matcherClz, Object matcher, Object modifiersObj, ClassLoader loader) {
        if (modifiersObj == null) return;
        int mask = parseModifiers(modifiersObj);
        if (mask == 0) return;
        try {
            Method m = matcherClz.getMethod("modifiers", int.class);
            m.invoke(matcher, mask);
            return;
        } catch (NoSuchMethodException ignored) {}
        catch (Exception e) { throw new RuntimeException(e); }

        try {
            Class<?> matchTypeClz = loader.loadClass("org.luckypray.dexkit.query.enums.MatchType");
            Object containsEnum = resolveEnum(matchTypeClz, "Contains");
            Method m = matcherClz.getMethod("modifiers", int.class, matchTypeClz);
            m.invoke(matcher, mask, containsEnum);
        } catch (Exception e) {
            throw new RuntimeException("Failed to apply modifiers to " + matcherClz.getName() + ": " + e.getMessage(), e);
        }
    }

    private static Map<String, Object> formatClassData(Object classData) {
        Map<String, Object> map = new LinkedHashMap<>();
        if (classData == null) return map;
        try {
            Class<?> clz = classData.getClass();
            map.put("descriptor", invokeString(classData, clz, "getDescriptor"));
            map.put("className", invokeString(classData, clz, "getName"));
            map.put("simpleName", invokeString(classData, clz, "getSimpleName"));
            map.put("sourceFile", invokeString(classData, clz, "getSourceFile"));

            Integer mods = invokeInt(classData, clz, "getModifiers");
            if (mods != null) {
                map.put("modifiers", mods);
                map.put("modifierStrings", decodeModifiers(mods, "class"));
            }

            Integer methodCount = invokeInt(classData, clz, "getMethodCount");
            if (methodCount != null) map.put("methodCount", methodCount);

            Integer fieldCount = invokeInt(classData, clz, "getFieldCount");
            if (fieldCount != null) map.put("fieldCount", fieldCount);

            Object superClass = invokeObj(classData, clz, "getSuperClass");
            if (superClass != null) {
                map.put("superClass", invokeString(superClass, superClass.getClass(), "getName"));
            }

            Object interfacesObj = invokeObj(classData, clz, "getInterfaces");
            List<?> interfacesList = toList(interfacesObj);
            List<String> ifaceNames = new ArrayList<>();
            for (Object iface : interfacesList) {
                String name = invokeString(iface, iface.getClass(), "getName");
                if (name != null) ifaceNames.add(name);
            }
            map.put("interfaces", ifaceNames);

        } catch (Exception ignored) {
        }
        return map;
    }

    private static Map<String, Object> formatMethodData(Object methodData) {
        Map<String, Object> map = new LinkedHashMap<>();
        if (methodData == null) return map;
        try {
            Class<?> clz = methodData.getClass();
            map.put("descriptor", invokeString(methodData, clz, "getDescriptor"));
            map.put("className", invokeString(methodData, clz, "getClassName"));
            map.put("name", invokeString(methodData, clz, "getName"));
            map.put("returnType", invokeString(methodData, clz, "getReturnTypeName"));

            Object paramNamesObj = invokeObj(methodData, clz, "getParamTypeNames");
            map.put("paramTypes", toStringList(paramNamesObj));

            Integer mods = invokeInt(methodData, clz, "getModifiers");
            if (mods != null) {
                map.put("modifiers", mods);
                map.put("modifierStrings", decodeModifiers(mods, "method"));
                map.put("isStatic", Modifier.isStatic(mods));
            }

            Boolean isCtor = invokeBool(methodData, clz, "isConstructor");
            if (isCtor != null) map.put("isConstructor", isCtor);

            Object stringsObj = invokeObj(methodData, clz, "getUsingStrings");
            map.put("usingStrings", toStringList(stringsObj));

        } catch (Exception ignored) {
        }
        return map;
    }

    private static Map<String, Object> formatFieldData(Object fieldData) {
        Map<String, Object> map = new LinkedHashMap<>();
        if (fieldData == null) return map;
        try {
            Class<?> clz = fieldData.getClass();
            map.put("descriptor", invokeString(fieldData, clz, "getDescriptor"));
            map.put("className", invokeString(fieldData, clz, "getClassName"));
            map.put("name", invokeString(fieldData, clz, "getName"));
            map.put("type", invokeString(fieldData, clz, "getTypeName"));

            Integer mods = invokeInt(fieldData, clz, "getModifiers");
            if (mods != null) {
                map.put("modifiers", mods);
                map.put("modifierStrings", decodeModifiers(mods, "field"));
                map.put("isStatic", Modifier.isStatic(mods));
            }

        } catch (Exception ignored) {
        }
        return map;
    }

    private static List<String> decodeModifiers(int modifiers, String entityKind) {
        List<String> list = new ArrayList<>();
        if ((modifiers & Modifier.PUBLIC) != 0) list.add("public");
        if ((modifiers & Modifier.PROTECTED) != 0) list.add("protected");
        if ((modifiers & Modifier.PRIVATE) != 0) list.add("private");
        if ((modifiers & Modifier.STATIC) != 0) list.add("static");
        if ((modifiers & Modifier.FINAL) != 0) list.add("final");
        if ((modifiers & Modifier.ABSTRACT) != 0) list.add("abstract");

        if ("class".equals(entityKind)) {
            if ((modifiers & Modifier.INTERFACE) != 0) list.add("interface");
            if ((modifiers & 0x2000) != 0) list.add("annotation");
            if ((modifiers & 0x4000) != 0) list.add("enum");
        } else if ("method".equals(entityKind)) {
            if ((modifiers & Modifier.SYNCHRONIZED) != 0) list.add("synchronized");
            if ((modifiers & Modifier.NATIVE) != 0) list.add("native");
            if ((modifiers & 0x0040) != 0) list.add("bridge");
            if ((modifiers & 0x0080) != 0) list.add("varargs");
            if ((modifiers & 0x0800) != 0) list.add("strictfp");
            if ((modifiers & 0x1000) != 0) list.add("synthetic");
        } else if ("field".equals(entityKind)) {
            if ((modifiers & Modifier.VOLATILE) != 0) list.add("volatile");
            if ((modifiers & Modifier.TRANSIENT) != 0) list.add("transient");
            if ((modifiers & 0x1000) != 0) list.add("synthetic");
            if ((modifiers & 0x4000) != 0) list.add("enum");
        }
        return list;
    }

    private static ClassLoader resolveDexKitClassLoader() throws ClassNotFoundException {
        try {
            Class.forName("org.luckypray.dexkit.DexKitBridge");
            return DexSearchBridge.class.getClassLoader();
        } catch (ClassNotFoundException e) {
            throw new ClassNotFoundException(
                "DexKit runtime classes not found on classpath (org.luckypray.dexkit.DexKitBridge). " +
                "Launch with: java -Djava.library.path=<toolsDir> -cp '<toolsDir>/*' org.reverse.dexsearch.DexSearchBridge",
                e
            );
        }
    }

    private static void applyPackageFilters(Class<?> finderClz, Object finder, Map<String, Object> query) {
        List<String> searchPackages = optStringList(query, "searchPackages", optStringList(query, "search_packages", null));
        if (searchPackages != null && !searchPackages.isEmpty()) {
            try {
                Method spMethod = finderClz.getMethod("searchPackages", String[].class);
                spMethod.invoke(finder, (Object) searchPackages.toArray(new String[0]));
            } catch (NoSuchMethodException e) {
                try {
                    Method spMethod = finderClz.getMethod("setSearchPackages", Collection.class);
                    spMethod.invoke(finder, searchPackages);
                } catch (Exception ignored) {}
            } catch (Exception ignored) {}
        }
        List<String> excludePackages = optStringList(query, "excludePackages", optStringList(query, "exclude_packages", null));
        if (excludePackages != null && !excludePackages.isEmpty()) {
            try {
                Method epMethod = finderClz.getMethod("excludePackages", String[].class);
                epMethod.invoke(finder, (Object) excludePackages.toArray(new String[0]));
            } catch (NoSuchMethodException e) {
                try {
                    Method epMethod = finderClz.getMethod("setExcludePackages", Collection.class);
                    epMethod.invoke(finder, excludePackages);
                } catch (Exception ignored) {}
            } catch (Exception ignored) {}
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Object resolveEnum(Class<?> enumClass, String name) {
        if (enumClass == null || name == null) return null;
        for (Object constant : enumClass.getEnumConstants()) {
            Enum<?> e = (Enum<?>) constant;
            if (e.name().equalsIgnoreCase(name.trim())) {
                return constant;
            }
        }
        return enumClass.getEnumConstants().length > 0 ? enumClass.getEnumConstants()[0] : null;
    }

    private static List<?> toList(Object obj) {
        if (obj == null) return Collections.emptyList();
        if (obj instanceof List) return (List<?>) obj;
        if (obj instanceof Collection) return new ArrayList<>((Collection<?>) obj);
        if (obj.getClass().isArray()) {
            int len = Array.getLength(obj);
            List<Object> list = new ArrayList<>(len);
            for (int i = 0; i < len; i++) list.add(Array.get(obj, i));
            return list;
        }
        return Collections.singletonList(obj);
    }

    private static List<String> toStringList(Object obj) {
        if (obj == null) return Collections.emptyList();
        List<?> raw = toList(obj);
        List<String> list = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (item != null) list.add(String.valueOf(item));
        }
        return list;
    }

    private static String invokeString(Object target, Class<?> clz, String methodName) {
        try {
            Method m = clz.getMethod(methodName);
            Object res = m.invoke(target);
            return res != null ? res.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static Integer invokeInt(Object target, Class<?> clz, String methodName) {
        try {
            Method m = clz.getMethod(methodName);
            Object res = m.invoke(target);
            return res instanceof Number ? ((Number) res).intValue() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static Boolean invokeBool(Object target, Class<?> clz, String methodName) {
        try {
            Method m = clz.getMethod(methodName);
            Object res = m.invoke(target);
            return res instanceof Boolean ? (Boolean) res : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static Object invokeObj(Object target, Class<?> clz, String methodName) {
        try {
            Method m = clz.getMethod(methodName);
            return m.invoke(target);
        } catch (Exception e) {
            return null;
        }
    }

    private static String optString(Map<String, Object> map, String key, String def) {
        Object val = map.get(key);
        return val != null ? String.valueOf(val) : def;
    }

    private static int optInt(Map<String, Object> map, String key, int def) {
        Object val = map.get(key);
        if (val instanceof Number) return ((Number) val).intValue();
        if (val instanceof String) {
            try { return Integer.parseInt(((String) val).trim()); } catch (Exception ignored) {}
        }
        return def;
    }

    private static long optLong(Map<String, Object> map, String key, long def) {
        Object val = map.get(key);
        if (val instanceof Number) return ((Number) val).longValue();
        if (val instanceof String) {
            try { return Long.parseLong(((String) val).trim()); } catch (Exception ignored) {}
        }
        return def;
    }

    private static boolean optBool(Map<String, Object> map, String key, boolean def) {
        Object val = map.get(key);
        if (val instanceof Boolean) return (Boolean) val;
        if (val instanceof String) {
            String s = ((String) val).trim().toLowerCase();
            return "true".equals(s) || "1".equals(s) || "yes".equals(s);
        }
        return def;
    }

    private static List<String> optStringList(Map<String, Object> map, String key, List<String> def) {
        Object val = map.get(key);
        if (val instanceof List) {
            return toStringList(val);
        }
        if (val instanceof String) {
            String s = (String) val;
            return Collections.singletonList(s);
        }
        return def;
    }

    private static List<Number> optNumberList(Map<String, Object> map, String key, List<Number> def) {
        Object val = map.get(key);
        if (val instanceof List) {
            List<?> raw = (List<?>) val;
            List<Number> list = new ArrayList<>(raw.size());
            for (Object item : raw) {
                if (item instanceof Number) list.add((Number) item);
                else if (item instanceof String) {
                    try { list.add(Double.parseDouble((String) item)); } catch (Exception ignored) {}
                }
            }
            return list;
        }
        if (val instanceof Number) {
            return Collections.singletonList((Number) val);
        }
        return def;
    }

    private static void emitError(String message) {
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("success", false);
        err.put("error", message);
        emitOutput(err);
    }

    private static void emitOutput(Map<String, Object> data) {
        System.out.println(START_TOKEN);
        System.out.println(SimpleJson.stringify(data));
        System.out.println(END_TOKEN);
        System.out.flush();
    }

    // ============================================================================
    // SimpleJson - Self-contained JSON Parser and Serializer
    // ============================================================================

    public static class SimpleJson {

        public static Object parse(String text) {
            if (text == null) return null;
            return new Parser(text.trim()).parseValue();
        }

        public static String stringify(Object value) {
            StringBuilder sb = new StringBuilder();
            writeValue(value, sb);
            return sb.toString();
        }

        private static void writeValue(Object value, StringBuilder sb) {
            if (value == null) {
                sb.append("null");
            } else if (value instanceof Boolean || value instanceof Number) {
                sb.append(value);
            } else if (value instanceof CharSequence) {
                writeString(value.toString(), sb);
            } else if (value instanceof Map) {
                writeMap((Map<?, ?>) value, sb);
            } else if (value instanceof Collection) {
                writeCollection((Collection<?>) value, sb);
            } else if (value.getClass().isArray()) {
                int len = Array.getLength(value);
                List<Object> list = new ArrayList<>(len);
                for (int i = 0; i < len; i++) list.add(Array.get(value, i));
                writeCollection(list, sb);
            } else {
                writeString(value.toString(), sb);
            }
        }

        private static void writeString(String s, StringBuilder sb) {
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
                    default:
                        if (c < 0x20) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                }
            }
            sb.append('"');
        }

        private static void writeMap(Map<?, ?> map, StringBuilder sb) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                writeString(String.valueOf(entry.getKey()), sb);
                sb.append(':');
                writeValue(entry.getValue(), sb);
            }
            sb.append('}');
        }

        private static void writeCollection(Collection<?> col, StringBuilder sb) {
            sb.append('[');
            boolean first = true;
            for (Object item : col) {
                if (!first) sb.append(',');
                first = false;
                writeValue(item, sb);
            }
            sb.append(']');
        }

        private static class Parser {
            private final String text;
            private int pos = 0;

            Parser(String text) {
                this.text = text;
            }

            Object parseValue() {
                skipWhitespace();
                if (pos >= text.length()) return null;
                char c = text.charAt(pos);
                if (c == '{') return parseObject();
                if (c == '[') return parseArray();
                if (c == '"' || c == '\'') return parseString();
                if (c == 't' || c == 'f') return parseBoolean();
                if (c == 'n') return parseNull();
                if (c == '-' || Character.isDigit(c)) return parseNumber();
                throw new IllegalArgumentException("Unexpected character '" + c + "' at position " + pos);
            }

            private Map<String, Object> parseObject() {
                Map<String, Object> map = new LinkedHashMap<>();
                pos++; // skip '{'
                skipWhitespace();
                if (pos < text.length() && text.charAt(pos) == '}') {
                    pos++;
                    return map;
                }
                while (pos < text.length()) {
                    skipWhitespace();
                    String key = parseString();
                    skipWhitespace();
                    if (pos >= text.length() || text.charAt(pos) != ':') {
                        throw new IllegalArgumentException("Expected ':' after key at position " + pos);
                    }
                    pos++; // skip ':'
                    Object val = parseValue();
                    map.put(key, val);
                    skipWhitespace();
                    if (pos < text.length() && text.charAt(pos) == ',') {
                        pos++;
                    } else if (pos < text.length() && text.charAt(pos) == '}') {
                        pos++;
                        break;
                    }
                }
                return map;
            }

            private List<Object> parseArray() {
                List<Object> list = new ArrayList<>();
                pos++; // skip '['
                skipWhitespace();
                if (pos < text.length() && text.charAt(pos) == ']') {
                    pos++;
                    return list;
                }
                while (pos < text.length()) {
                    Object val = parseValue();
                    list.add(val);
                    skipWhitespace();
                    if (pos < text.length() && text.charAt(pos) == ',') {
                        pos++;
                    } else if (pos < text.length() && text.charAt(pos) == ']') {
                        pos++;
                        break;
                    }
                }
                return list;
            }

            private String parseString() {
                char quote = text.charAt(pos);
                pos++; // skip open quote
                StringBuilder sb = new StringBuilder();
                while (pos < text.length()) {
                    char c = text.charAt(pos++);
                    if (c == quote) {
                        return sb.toString();
                    }
                    if (c == '\\' && pos < text.length()) {
                        char esc = text.charAt(pos++);
                        switch (esc) {
                            case '"': sb.append('"'); break;
                            case '\\': sb.append('\\'); break;
                            case '/': sb.append('/'); break;
                            case 'b': sb.append('\b'); break;
                            case 'f': sb.append('\f'); break;
                            case 'n': sb.append('\n'); break;
                            case 'r': sb.append('\r'); break;
                            case 't': sb.append('\t'); break;
                            case 'u':
                                if (pos + 4 <= text.length()) {
                                    String hex = text.substring(pos, pos + 4);
                                    sb.append((char) Integer.parseInt(hex, 16));
                                    pos += 4;
                                }
                                break;
                            default: sb.append(esc);
                        }
                    } else {
                        sb.append(c);
                    }
                }
                return sb.toString();
            }

            private Boolean parseBoolean() {
                if (text.startsWith("true", pos)) {
                    pos += 4;
                    return Boolean.TRUE;
                }
                if (text.startsWith("false", pos)) {
                    pos += 5;
                    return Boolean.FALSE;
                }
                throw new IllegalArgumentException("Invalid boolean at position " + pos);
            }

            private Object parseNull() {
                if (text.startsWith("null", pos)) {
                    pos += 4;
                    return null;
                }
                throw new IllegalArgumentException("Invalid null literal at position " + pos);
            }

            private Number parseNumber() {
                int start = pos;
                if (text.charAt(pos) == '-') pos++;
                while (pos < text.length()) {
                    char c = text.charAt(pos);
                    if (Character.isDigit(c) || c == '.' || c == 'e' || c == 'E' ||
                        ((c == '+' || c == '-') && (text.charAt(pos - 1) == 'e' || text.charAt(pos - 1) == 'E'))) {
                        pos++;
                    } else {
                        break;
                    }
                }
                String numStr = text.substring(start, pos);
                if (numStr.contains(".") || numStr.contains("e") || numStr.contains("E")) {
                    return Double.parseDouble(numStr);
                }
                long val = Long.parseLong(numStr);
                if (val >= Integer.MIN_VALUE && val <= Integer.MAX_VALUE) {
                    return (int) val;
                }
                return val;
            }

            private void skipWhitespace() {
                while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
                    pos++;
                }
            }
        }
    }
}

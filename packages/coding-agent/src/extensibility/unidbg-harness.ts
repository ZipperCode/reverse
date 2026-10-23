/**
 * Unidbg Emulation Harness Code Generator
 *
 * Generates compilable, parameterized Java harnesses for Android JNI and iOS IPA targets
 * supporting 32-bit and 64-bit architectures, Unicorn2 and Dynarmic backends, parameter conversions,
 * type-correct JNI return dispatch (void/int/long/boolean/byte/char/short/object), direct native export invocation,
 * sanitized Java identifiers, and canonical console-driven McpServer lifecycle wiring without reflection.
 */

import * as path from "node:path";

export interface UnidbgHarnessParam {
	name: string;
	type: "string" | "bytes" | "int" | "long" | "boolean";
	defaultValue?: string;
}

export interface UnidbgHarnessOptions {
	type: "jni" | "ipa";
	targetPath: string;
	entry?: string;
	className?: string;
	methodSignature?: string;
	isStatic?: boolean;
	callOnLoad?: boolean;
	arch?: 32 | 64 | "32" | "64";
	backend?: "unicorn2" | "dynarmic";
	port?: number;
	packageName?: string;
	harnessClassName?: string;
	params?: string | UnidbgHarnessParam[];
	processName?: string;
	outPath?: string;
}

const UPSTREAM_BUILTIN_TOOL_NAMES = new Set([
	"check_connection",
	"list_modules",
	"get_module_info",
	"list_exports",
	"find_symbol",
	"get_threads",
	"get_registers",
	"get_register",
	"set_register",
	"disassemble",
	"assemble",
	"get_callstack",
	"read_memory",
	"write_memory",
	"read_string",
	"read_std_string",
	"read_pointer",
	"read_typed",
	"search_memory",
	"list_memory_map",
	"allocate_memory",
	"free_memory",
	"list_allocations",
	"patch",
	"add_breakpoint",
	"add_breakpoint_by_symbol",
	"add_breakpoint_by_offset",
	"remove_breakpoint",
	"list_breakpoints",
	"continue_execution",
	"step_over",
	"step_into",
	"step_out",
	"next_block",
	"step_until_mnemonic",
	"poll_events",
	"trace_code",
	"trace_read",
	"trace_write",
	"call_function",
	"call_symbol",
	"inspect_objc_msg",
	"get_objc_class_name",
	"dump_objc_class",
	"dump_gpb_protobuf",
	"dumpClass",
]);

export function resolveCustomToolName(rawName: string, prefix = "invoke"): string {
	const sanitized = sanitizeJavaIdentifier(rawName, prefix);
	if (UPSTREAM_BUILTIN_TOOL_NAMES.has(sanitized)) {
		return `${prefix}_${sanitized}`;
	}
	return sanitized;
}

export function escapeJavaString(str: string): string {
	return str
		.replace(/\\/g, "\\\\")
		.replace(/"/g, '\\"')
		.replace(/\n/g, "\\n")
		.replace(/\r/g, "\\r")
		.replace(/\t/g, "\\t");
}

export function sanitizeJavaIdentifier(name: string, fallback = "param"): string {
	const cleaned = name.replace(/[^a-zA-Z0-9_]/g, "_");
	if (!cleaned || /^[0-9]/.test(cleaned)) {
		return `${fallback}_${cleaned}`;
	}
	return cleaned;
}

export function parseHarnessParams(params?: string | UnidbgHarnessParam[]): UnidbgHarnessParam[] {
	if (!params) return [];
	if (Array.isArray(params)) {
		return params.map(p => ({
			...p,
			name: sanitizeJavaIdentifier(p.name),
		}));
	}

	const tokens = params
		.split(",")
		.map(t => t.trim())
		.filter(Boolean);
	return tokens.map((token, idx) => {
		let type: "string" | "bytes" | "int" | "long" | "boolean" = "string";
		let rawName = `param${idx}`;

		if (token.includes(":")) {
			const [n, t] = token.split(":");
			rawName = n.trim();
			const lowerType = t.trim().toLowerCase();
			if (lowerType === "bytes" || lowerType === "byte[]" || lowerType === "bytearray" || lowerType === "hex") {
				type = "bytes";
			} else if (lowerType === "int" || lowerType === "integer" || lowerType === "i") {
				type = "int";
			} else if (lowerType === "long" || lowerType === "j") {
				type = "long";
			} else if (lowerType === "bool" || lowerType === "boolean" || lowerType === "z") {
				type = "boolean";
			} else {
				type = "string";
			}
		} else {
			const lowerToken = token.toLowerCase();
			if (lowerToken === "bytes" || lowerToken === "byte[]" || lowerToken === "bytearray" || lowerToken === "hex") {
				type = "bytes";
				rawName = `bytesParam${idx}`;
			} else if (lowerToken === "int" || lowerToken === "integer") {
				type = "int";
				rawName = `intParam${idx}`;
			} else if (lowerToken === "long") {
				type = "long";
				rawName = `longParam${idx}`;
			} else if (lowerToken === "bool" || lowerToken === "boolean") {
				type = "boolean";
				rawName = `boolParam${idx}`;
			} else {
				type = "string";
				rawName = `strParam${idx}`;
			}
		}
		return { name: sanitizeJavaIdentifier(rawName, `param${idx}`), type };
	});
}

export function parseJniSignatureParams(signature: string): UnidbgHarnessParam[] {
	const match = signature.match(/^\(([^)]*)\)/);
	if (!match) return [];
	const raw = match[1];
	const params: UnidbgHarnessParam[] = [];
	let i = 0;
	let idx = 0;
	while (i < raw.length) {
		const c = raw[i];
		if (c === "[") {
			if (raw[i + 1] === "B") {
				params.push({ name: `bytesParam${idx++}`, type: "bytes" });
				i += 2;
			} else {
				throw new Error(
					`Unsupported JNI array parameter descriptor in '${signature}'. Only '[B' (byte[]) is supported.`,
				);
			}
		} else if (c === "L") {
			const end = raw.indexOf(";", i);
			if (end === -1) throw new Error(`Malformed JNI class descriptor in signature '${signature}'`);
			const className = raw.substring(i + 1, end);
			if (className === "java/lang/String") {
				params.push({ name: `strParam${idx++}`, type: "string" });
			} else {
				throw new Error(
					`Unsupported JNI object parameter 'L${className};' in '${signature}'. Only 'Ljava/lang/String;' is directly supported for automated harness generation.`,
				);
			}
			i = end + 1;
		} else if (c === "I" || c === "S" || c === "C" || c === "B") {
			params.push({ name: `intParam${idx++}`, type: "int" });
			i++;
		} else if (c === "J") {
			params.push({ name: `longParam${idx++}`, type: "long" });
			i++;
		} else if (c === "Z") {
			params.push({ name: `boolParam${idx++}`, type: "boolean" });
			i++;
		} else {
			throw new Error(`Unsupported JNI parameter type '${c}' in signature '${signature}'.`);
		}
	}
	return params;
}

function deriveJniSignature(params: UnidbgHarnessParam[], returnType = "V"): string {
	const argSig = params
		.map(p => {
			switch (p.type) {
				case "bytes":
					return "[B";
				case "string":
					return "Ljava/lang/String;";
				case "int":
					return "I";
				case "long":
					return "J";
				case "boolean":
					return "Z";
				default:
					return "Ljava/lang/String;";
			}
		})
		.join("");
	return `(${argSig})${returnType}`;
}

/**
 * Generate Android JNI emulation harness Java source code.
 */
export function generateAndroidJniHarness(options: UnidbgHarnessOptions): string {
	let clsName = options.harnessClassName;
	if (!clsName && options.outPath) {
		const base = path.basename(options.outPath);
		clsName = sanitizeJavaIdentifier(base.replace(/\.java$/i, ""));
	}
	if (!clsName) {
		clsName = "UnidbgHarness";
	}

	const pkg = options.packageName ?? "com.reverse.unidbg.harness";
	const is64 = String(options.arch ?? "64") === "64";
	const backend = options.backend ?? "unicorn2";
	const port = options.port ?? 9239;
	const entry = options.entry ?? "entry";
	const toolName = resolveCustomToolName(entry, "tool");
	const targetClass = options.className;
	const isStatic = options.isStatic ?? true;
	const callOnLoad = options.callOnLoad ?? true;
	let parsedParams = parseHarnessParams(options.params);
	if (parsedParams.length === 0 && options.methodSignature) {
		parsedParams = parseJniSignatureParams(options.methodSignature);
	}
	const signature = options.methodSignature ?? deriveJniSignature(parsedParams, "V");
	const processName = options.processName ?? "com.reverse.unidbg.app";

	const paramNamesArray = parsedParams.map(p => `"${escapeJavaString(p.name)}"`).join(", ");
	const escapedTargetPath = escapeJavaString(options.targetPath.replace(/\\/g, "/"));
	const safeCommentTarget = escapedTargetPath.replace(/\*\//g, "* /");

	const backendFactory =
		backend === "dynarmic"
			? "builder.addBackendFactory(new DynarmicFactory(true));"
			: "builder.addBackendFactory(new Unicorn2Factory(true));";

	// Parse return type from signature: (args)ret
	const sigMatch = signature.match(/\)(.+)$/);
	const returnType = sigMatch ? sigMatch[1] : "V";

	if (targetClass && (returnType === "F" || returnType === "D")) {
		throw new Error(
			`Floating point JNI return types ('${returnType}') are not supported by upstream Unidbg DvmClass JNI methods. Please use void, primitive integer types (I, J, Z, B, C, S), or object/array types.`,
		);
	}
	// Generate parameter conversions for McpTool.execute
	const paramConversions: string[] = [];
	const invocationArgs: string[] = [];

	parsedParams.forEach((p, idx) => {
		const varName = `arg_${idx}`;
		if (targetClass) {
			// JNI Object conversion
			if (p.type === "bytes") {
				paramConversions.push(
					`            byte[] ${varName}Raw = params.length > ${idx} ? parseBytes(params[${idx}]) : new byte[16];`,
				);
				paramConversions.push(`            ByteArray ${varName} = new ByteArray(vm, ${varName}Raw);`);
				invocationArgs.push(varName);
			} else if (p.type === "string") {
				paramConversions.push(
					`            String ${varName}Raw = params.length > ${idx} ? parseString(params[${idx}]) : "";`,
				);
				paramConversions.push(`            StringObject ${varName} = new StringObject(vm, ${varName}Raw);`);
				invocationArgs.push(varName);
			} else if (p.type === "int") {
				paramConversions.push(
					`            int ${varName} = params.length > ${idx} ? parseInt(params[${idx}]) : 0;`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "long") {
				paramConversions.push(
					`            long ${varName} = params.length > ${idx} ? parseLong(params[${idx}]) : 0L;`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "boolean") {
				paramConversions.push(
					`            boolean ${varName} = params.length > ${idx} ? Boolean.parseBoolean(params[${idx}].trim()) : true;`,
				);
				invocationArgs.push(varName);
			}
		} else {
			// Direct native function call conversion (String, byte[], Number)
			if (p.type === "bytes") {
				paramConversions.push(
					`            byte[] ${varName} = params.length > ${idx} ? parseBytes(params[${idx}]) : new byte[0];`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "string") {
				paramConversions.push(
					`            String ${varName} = params.length > ${idx} ? parseString(params[${idx}]) : "";`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "int") {
				paramConversions.push(
					`            int ${varName} = params.length > ${idx} ? parseInt(params[${idx}]) : 0;`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "long") {
				paramConversions.push(
					`            long ${varName} = params.length > ${idx} ? parseLong(params[${idx}]) : 0L;`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "boolean") {
				paramConversions.push(
					`            int ${varName} = (params.length > ${idx} && Boolean.parseBoolean(params[${idx}].trim())) ? 1 : 0;`,
				);
				invocationArgs.push(varName);
			}
		}
	});

	const argsCall = invocationArgs.length > 0 ? `, ${invocationArgs.join(", ")}` : "";
	let classResolutionCode = "";
	let methodCallCode = "";

	if (targetClass) {
		const escapedClass = escapeJavaString(targetClass);
		classResolutionCode = `        this.dvmClass = vm.resolveClass("${escapedClass}");\n        System.out.println("Target class resolved: " + dvmClass + " on backend: " + emulator.getBackend());`;
		if (returnType === "V") {
			methodCallCode = isStatic
				? `            dvmClass.callStaticJniMethod(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("${escapeJavaString(entry)} completed successfully (void)");`
				: `            DvmObject<?> instance = dvmClass.newObject(null);\n            instance.callJniMethod(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("${escapeJavaString(entry)} completed successfully (void)");`;
		} else if (returnType === "I") {
			methodCallCode = isStatic
				? `            int ret = dvmClass.callStaticJniMethodInt(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (int): " + ret);`
				: `            DvmObject<?> instance = dvmClass.newObject(null);\n            int ret = instance.callJniMethodInt(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (int): " + ret);`;
		} else if (returnType === "B") {
			methodCallCode = isStatic
				? `            byte ret = (byte) dvmClass.callStaticJniMethodInt(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (byte): " + ret);`
				: `            DvmObject<?> instance = dvmClass.newObject(null);\n            byte ret = (byte) instance.callJniMethodInt(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (byte): " + ret);`;
		} else if (returnType === "C") {
			methodCallCode = isStatic
				? `            char ret = (char) dvmClass.callStaticJniMethodInt(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (char): " + ret);`
				: `            DvmObject<?> instance = dvmClass.newObject(null);\n            char ret = (char) instance.callJniMethodInt(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (char): " + ret);`;
		} else if (returnType === "S") {
			methodCallCode = isStatic
				? `            short ret = (short) dvmClass.callStaticJniMethodInt(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (short): " + ret);`
				: `            DvmObject<?> instance = dvmClass.newObject(null);\n            short ret = (short) instance.callJniMethodInt(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (short): " + ret);`;
		} else if (returnType === "J") {
			methodCallCode = isStatic
				? `            long ret = dvmClass.callStaticJniMethodLong(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (long): " + ret);`
				: `            DvmObject<?> instance = dvmClass.newObject(null);\n            long ret = instance.callJniMethodLong(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (long): " + ret);`;
		} else if (returnType === "Z") {
			methodCallCode = isStatic
				? `            boolean ret = dvmClass.callStaticJniMethodBoolean(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (boolean): " + ret);`
				: `            DvmObject<?> instance = dvmClass.newObject(null);\n            boolean ret = instance.callJniMethodBoolean(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (boolean): " + ret);`;
		} else {
			methodCallCode = isStatic
				? `            DvmObject<?> ret = dvmClass.callStaticJniMethodObject(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (object): " + (ret != null ? ret.getValue() : "null"));\n            if (ret != null && ret.getValue() instanceof byte[]) {\n                Inspector.inspect((byte[]) ret.getValue(), "${escapeJavaString(entry)} output");\n            }`
				: `            DvmObject<?> instance = dvmClass.newObject(null);\n            DvmObject<?> ret = instance.callJniMethodObject(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            System.out.println("Return (object): " + (ret != null ? ret.getValue() : "null"));\n            if (ret != null && ret.getValue() instanceof byte[]) {\n                Inspector.inspect((byte[]) ret.getValue(), "${escapeJavaString(entry)} output");\n            }`;
		}
	} else {
		classResolutionCode = `        this.dvmClass = null;\n        System.out.println("No target JNI class specified. Direct native module export mode on backend: " + emulator.getBackend());`;
		methodCallCode = `            Module module = dalvikModule.getModule();\n            Number ret = module.callFunction(emulator, "${escapeJavaString(entry)}"${argsCall});\n            System.out.println("Return: 0x" + Long.toHexString(ret.longValue()) + " (" + ret + ")");`;
	}

	return `package ${pkg};

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.debugger.McpTool;
import com.github.unidbg.debugger.McpToolkit;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;
import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.Permission;
import java.util.Arrays;

/**
 * Auto-generated Unidbg Android JNI Emulation Harness
 * Target: ${safeCommentTarget}
 * Arch: ${is64 ? "ARM64" : "ARM32"} | Backend: ${backend} | Port: ${port}
 */
public class ${clsName} extends TestCase {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final DalvikModule dalvikModule;
    private final DvmClass dvmClass;
    private final int port = Integer.getInteger("unidbg.port", ${port});

    public ${clsName}() {
        AndroidEmulatorBuilder builder = ${is64 ? "AndroidEmulatorBuilder.for64Bit()" : "AndroidEmulatorBuilder.for32Bit()"};
        builder.setProcessName("${escapeJavaString(processName)}");
        ${backendFactory}
        this.emulator = builder.build();

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        this.vm = emulator.createDalvikVM();
        this.vm.setDvmClassFactory(new ProxyClassFactory());
        this.vm.setVerbose(true);

        new JniGraphics(emulator, vm).register(memory);
        new AndroidModule(emulator, vm).register(memory);

        String customTarget = System.getProperty("unidbg.target");
        File targetFile = resolveTargetFile(customTarget != null && !customTarget.trim().isEmpty() ? customTarget.trim() : "${escapedTargetPath}");
        System.out.println("Loading native library from: " + targetFile.getAbsolutePath());
        this.dalvikModule = vm.loadLibrary(targetFile, true);

        ${callOnLoad ? "dalvikModule.callJNI_OnLoad(emulator);" : "// JNI_OnLoad skipped"}

${classResolutionCode}

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                if (emulator != null) emulator.close();
            } catch (Throwable ignored) {}
        }));
    }

    private static File resolveTargetFile(String path) {
        File file = new File(path);
        if (file.canRead()) return file;
        File inAndroid = new File("unidbg-android", path);
        if (inAndroid.canRead()) return inAndroid;
        File inCurrent = new File(System.getProperty("user.dir"), path);
        if (inCurrent.canRead()) return inCurrent;
        return file;
    }

    private static byte[] parseBytes(String input) {
        if (input == null || input.isEmpty()) return new byte[0];
        String trimmed = input.trim();
        if (trimmed.startsWith("b64:") || trimmed.startsWith("base64:")) {
            try {
                return java.util.Base64.getDecoder().decode(trimmed.substring(trimmed.indexOf(':') + 1));
            } catch (Exception ignored) {}
        }
        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
            String hex = trimmed.substring(2);
            int len = hex.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                        + Character.digit(hex.charAt(i + 1), 16));
            }
            return data;
        }
        return trimmed.getBytes(StandardCharsets.UTF_8);
    }

    private static String parseString(String input) {
        if (input == null || input.isEmpty()) return "";
        String trimmed = input.trim();
        if (trimmed.startsWith("b64:") || trimmed.startsWith("base64:")) {
            try {
                byte[] decoded = java.util.Base64.getDecoder().decode(trimmed.substring(trimmed.indexOf(':') + 1));
                return new String(decoded, StandardCharsets.UTF_8);
            } catch (Exception ignored) {}
        }
        return input;
    }
    private static int parseInt(String input) {
        if (input == null || input.isEmpty()) return 0;
        String trimmed = input.trim();
        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
            return (int) Long.parseLong(trimmed.substring(2), 16);
        }
        return Integer.parseInt(trimmed);
    }

    private static long parseLong(String input) {
        if (input == null || input.isEmpty()) return 0L;
        String trimmed = input.trim();
        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
            return Long.parseUnsignedLong(trimmed.substring(2), 16);
        }
        return Long.parseLong(trimmed);
    }

    public void runMcpToolkit() throws Exception {
        // Enforce loopback security: restrict incoming socket connections to loopback interfaces only
        System.setSecurityManager(new SecurityManager() {
            @Override
            public void checkAccept(String host, int port) {
                try {
                    if (!InetAddress.getByName(host).isLoopbackAddress()) {
                        throw new SecurityException("Non-loopback connection rejected: " + host);
                    }
                } catch (Exception e) {
                    throw new SecurityException("Failed to verify loopback address for host: " + host, e);
                }
            }

            @Override
            public void checkPermission(Permission perm) {}

            @Override
            public void checkPermission(Permission perm, Object context) {}
        });
        McpToolkit toolkit = new McpToolkit() {
            private boolean initialized = false;
            @Override
            public Void runWithArgs(String[] args) throws Exception {
                if (!initialized) {
                    initialized = true;
                    return null;
                }
                return super.runWithArgs(args);
            }
        };
        toolkit.addTool(new McpTool() {
            @Override
            public String name() {
                return "${toolName}";
            }

            @Override
            public String description() {
                return "Emulate function ${escapeJavaString(entry)} (strings with whitespace can be base64-encoded as 'b64:<data>')";
            }

            @Override
            public String[] paramNames() {
                return new String[]{${paramNamesArray}};
            }

            @Override
            public void execute(String[] params) {
                System.out.println("Invoking ${escapeJavaString(entry)} with params: " + Arrays.toString(params));
                long start = System.currentTimeMillis();
                try {
${paramConversions.join("\n")}
${methodCallCode}
                    long duration = System.currentTimeMillis() - start;
                    System.out.println("Execution finished in " + duration + "ms");
                } catch (Exception e) {
                    System.err.println("Invocation error: " + e.getMessage());
                    throw (e instanceof RuntimeException) ? (RuntimeException) e : new RuntimeException(e);
                }
            }
        });

        Debugger debugger = emulator.attach();

        // Feed "mcp <port>\\n" through System.in prior to entering loop, invoking upstream's
        // native console command handler to start McpServer and bind custom tools without reflection.
        InputStream initStream = new ByteArrayInputStream(("mcp " + port + "\\n").getBytes(StandardCharsets.UTF_8));
        System.setIn(new SequenceInputStream(initStream, System.in));

        System.out.println("Unidbg harness entering loop on port " + port);

        toolkit.run(debugger);
    }

    public void testHarness() throws Exception {
        runMcpToolkit();
    }

    public static void main(String[] args) throws Exception {
        ${clsName} harness = new ${clsName}();
        harness.runMcpToolkit();
    }
}
`;
}

/**
 * Generate iOS IPA emulation harness Java source code.
 */
export function generateIpaHarness(options: UnidbgHarnessOptions): string {
	let clsName = options.harnessClassName;
	if (!clsName && options.outPath) {
		const base = path.basename(options.outPath);
		clsName = sanitizeJavaIdentifier(base.replace(/\.java$/i, ""));
	}
	if (!clsName) {
		clsName = "UnidbgIpaHarness";
	}

	const pkg = options.packageName ?? "com.reverse.unidbg.harness";
	const is64 = String(options.arch ?? "64") === "64";
	const backend = options.backend ?? "unicorn2";
	const port = options.port ?? 9239;
	const entry = options.entry;
	const escapedTargetPath = escapeJavaString(options.targetPath.replace(/\\/g, "/"));
	const safeCommentTarget = escapedTargetPath.replace(/\*\//g, "* /");
	const parsedParams = parseHarnessParams(options.params);

	const backendFactory =
		backend === "dynarmic"
			? "ipaLoader.addBackendFactory(new DynarmicFactory(true));"
			: "ipaLoader.addBackendFactory(new Unicorn2Factory(true));";

	let customEntryToolCode = "";

	if (entry && entry !== "dumpClass") {
		const entryToolName = resolveCustomToolName(entry, "invoke");
		const paramNamesArray = parsedParams.map(p => `"${escapeJavaString(p.name)}"`).join(", ");
		const paramConversions: string[] = [];
		const invocationArgs: string[] = [];

		parsedParams.forEach((p, idx) => {
			const varName = `arg_${idx}`;
			if (p.type === "bytes") {
				paramConversions.push(
					`            byte[] ${varName} = params.length > ${idx} ? parseBytes(params[${idx}]) : new byte[0];`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "string") {
				paramConversions.push(
					`            String ${varName} = params.length > ${idx} ? parseString(params[${idx}]) : "";`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "int") {
				paramConversions.push(
					`            int ${varName} = params.length > ${idx} ? parseInt(params[${idx}]) : 0;`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "long") {
				paramConversions.push(
					`            long ${varName} = params.length > ${idx} ? parseLong(params[${idx}]) : 0L;`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "boolean") {
				paramConversions.push(
					`            int ${varName} = (params.length > ${idx} && Boolean.parseBoolean(params[${idx}].trim())) ? 1 : 0;`,
				);
				invocationArgs.push(varName);
			}
		});

		const argsCall = invocationArgs.length > 0 ? `, ${invocationArgs.join(", ")}` : "";

		customEntryToolCode = `
        toolkit.addTool(new McpTool() {
            @Override
            public String name() {
                return "${entryToolName}";
            }

            @Override
            public String description() {
                return "Invoke entry point or function '${escapeJavaString(entry)}'";
            }

            @Override
            public String[] paramNames() {
                return new String[]{${paramNamesArray}};
            }

            @Override
            public void execute(String[] params) {
                if (module != null) {
                    System.out.println("Invoking ${escapeJavaString(entry)} with params: " + Arrays.toString(params));
                    try {
${paramConversions.join("\n")}
                        Number ret = module.callFunction(emulator, "${escapeJavaString(entry)}"${argsCall});
                        System.out.println("Return: 0x" + Long.toHexString(ret.longValue()) + " (" + ret + ")");
                    } catch (Exception e) {
                        System.err.println("Invocation error: " + e.getMessage());
                        throw (e instanceof RuntimeException) ? (RuntimeException) e : new RuntimeException(e);
                    }
                }
            }
        });`;
	}

	return `package ${pkg};

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.debugger.McpTool;
import com.github.unidbg.debugger.McpToolkit;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.ios.ipa.IpaLoader32;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.Permission;
import java.util.Arrays;

/**
 * Auto-generated Unidbg iOS IPA Emulation Harness
 * Target: ${safeCommentTarget}
 * Arch: ${is64 ? "ARM64" : "ARM32"} | Backend: ${backend} | Port: ${port}
 */
public class ${clsName} extends TestCase implements EmulatorConfigurator {

    private Emulator<?> emulator;
    private Module module;
    private final int port = Integer.getInteger("unidbg.port", ${port});

    private static byte[] parseBytes(String input) {
        if (input == null || input.isEmpty()) return new byte[0];
        String trimmed = input.trim();
        if (trimmed.startsWith("b64:") || trimmed.startsWith("base64:")) {
            try {
                return java.util.Base64.getDecoder().decode(trimmed.substring(trimmed.indexOf(':') + 1));
            } catch (Exception ignored) {}
        }
        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
            String hex = trimmed.substring(2);
            int len = hex.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                        + Character.digit(hex.charAt(i + 1), 16));
            }
            return data;
        }
        return trimmed.getBytes(StandardCharsets.UTF_8);
    }

    private static String parseString(String input) {
        if (input == null || input.isEmpty()) return "";
        String trimmed = input.trim();
        if (trimmed.startsWith("b64:") || trimmed.startsWith("base64:")) {
            try {
                byte[] decoded = java.util.Base64.getDecoder().decode(trimmed.substring(trimmed.indexOf(':') + 1));
                return new String(decoded, StandardCharsets.UTF_8);
            } catch (Exception ignored) {}
        }
        return input;
    }
    private static int parseInt(String input) {
        if (input == null || input.isEmpty()) return 0;
        String trimmed = input.trim();
        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
            return (int) Long.parseLong(trimmed.substring(2), 16);
        }
        return Integer.parseInt(trimmed);
    }

    private static long parseLong(String input) {
        if (input == null || input.isEmpty()) return 0L;
        String trimmed = input.trim();
        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
            return Long.parseUnsignedLong(trimmed.substring(2), 16);
        }
        return Long.parseLong(trimmed);
    }

    public void runMcpToolkit() throws Exception {
        // Enforce loopback security: restrict incoming socket connections to loopback interfaces only
        System.setSecurityManager(new SecurityManager() {
            @Override
            public void checkAccept(String host, int port) {
                try {
                    if (!InetAddress.getByName(host).isLoopbackAddress()) {
                        throw new SecurityException("Non-loopback connection rejected: " + host);
                    }
                } catch (Exception e) {
                    throw new SecurityException("Failed to verify loopback address for host: " + host, e);
                }
            }

            @Override
            public void checkPermission(Permission perm) {}

            @Override
            public void checkPermission(Permission perm, Object context) {}
        });
        String customTarget = System.getProperty("unidbg.target");
        File ipa = new File(customTarget != null && !customTarget.trim().isEmpty() ? customTarget.trim() : "${escapedTargetPath}");
        if (!ipa.canRead()) {
            File inIos = new File("unidbg-ios", "${escapedTargetPath}");
            if (inIos.canRead()) ipa = inIos;
        }

        IpaLoader ipaLoader = ${is64 ? "new IpaLoader64(ipa, new File(\"target/rootfs/ipa\"))" : "new IpaLoader32(ipa, new File(\"target/rootfs/ipa\"))"};
        ${backendFactory}

        LoadedIpa loader = ipaLoader.load(this);
        this.emulator = loader.getEmulator();
        loader.callEntry();
        this.module = loader.getExecutable();

        McpToolkit toolkit = new McpToolkit() {
            private boolean initialized = false;
            @Override
            public Void runWithArgs(String[] args) throws Exception {
                if (!initialized) {
                    initialized = true;
                    return null;
                }
                return super.runWithArgs(args);
            }
        };
        toolkit.addTool(new McpTool() {
            @Override
            public String name() {
                return "dumpClass";
            }

            @Override
            public String description() {
                return "Dump ObjC class definition by name";
            }

            @Override
            public String[] paramNames() {
                return new String[]{"className"};
            }

            @Override
            public void execute(String[] params) {
                String className = params.length > 0 ? params[0] : "AppDelegate";
                try {
                    IClassDumper classDumper = ClassDumper.getInstance(emulator);
                    Backend backend = emulator.getBackend();
                    String classDef = classDumper.dumpClass(className);
                    System.out.printf("dumpClass(%s):\\n%s\\nbackend=%s%n", className, classDef, backend);
                } catch (Exception e) {
                    System.err.println("dumpClass failed: " + e.getMessage());
                    throw (e instanceof RuntimeException) ? (RuntimeException) e : new RuntimeException(e);
                }
            }
        });
${customEntryToolCode}

        Debugger debugger = emulator.attach();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                if (emulator != null) emulator.close();
            } catch (Throwable ignored) {}
        }));

        InputStream initStream = new ByteArrayInputStream(("mcp " + port + "\\n").getBytes(StandardCharsets.UTF_8));
        System.setIn(new SequenceInputStream(initStream, System.in));

        System.out.println("Unidbg harness entering loop on port " + port);

        toolkit.run(debugger);
    }

    public void testHarness() throws Exception {
        runMcpToolkit();
    }

    public static void main(String[] args) throws Exception {
        ${clsName} harness = new ${clsName}();
        harness.runMcpToolkit();
    }

    @Override
    public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir, String bundleIdentifier) {
    }

    @Override
    public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
    }
}
`;
}

/**
 * Main scaffolding dispatcher: generates harness source code according to options.
 */
export function generateUnidbgHarness(options: UnidbgHarnessOptions): string {
	if (options.type === "ipa") {
		return generateIpaHarness(options);
	}
	return generateAndroidJniHarness(options);
}

/**
 * Unidbg Emulation Harness Code Generator
 *
 * Generates compilable, parameterized Java harnesses for Android JNI and iOS IPA targets
 * supporting 32-bit and 64-bit architectures, Unicorn2 and Dynarmic backends, parameter conversions,
 * type-correct JNI return dispatch (void/int/long/boolean/byte/char/short/object), direct native export invocation,
 * sanitized Java identifiers, and canonical console-driven McpServer lifecycle wiring without reflection.
 */

import * as path from "node:path";

export type UnidbgParamType =
	| "string"
	| "bytes"
	| "int"
	| "long"
	| "boolean"
	| "int[]"
	| "short[]"
	| "float[]"
	| "double[]"
	| "string[]"
	| "object[]"
	| "context"
	| "object";

export interface UnidbgHarnessParam {
	name: string;
	type: UnidbgParamType;
	className?: string;
	defaultValue?: string;
}

export interface UnidbgJniOverride {
	signature: string;
	isStatic?: boolean;
	returnType?:
		| "string"
		| "int"
		| "boolean"
		| "long"
		| "bytes"
		| "int[]"
		| "short[]"
		| "float[]"
		| "double[]"
		| "string[]"
		| "object"
		| "void";
	value?: unknown;
}

export interface UnidbgEnvProfile {
	packageName?: string;
	appName?: string;
	versionName?: string;
	versionCode?: number;
	filesDir?: string;
	cacheDir?: string;
	apiLevel?: number;
	properties?: Record<string, string>;
	overrides?: UnidbgJniOverride[];
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
	apkPath?: string;
	apiLevel?: number;
	envProfile?: UnidbgEnvProfile | string;
}

export interface UnidbgProbeOptions {
	targetPath: string;
	arch?: 32 | 64 | "32" | "64";
	backend?: "unicorn2" | "dynarmic";
	callOnLoad?: boolean;
	apkPath?: string;
	apiLevel?: number;
	processName?: string;
	packageName?: string;
	harnessClassName?: string;
	envProfile?: UnidbgEnvProfile | string;
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

	if (typeof params === "string" && params.trim().startsWith("[")) {
		try {
			const parsed = JSON.parse(params);
			if (Array.isArray(parsed)) return parseHarnessParams(parsed);
		} catch {}
	}

	const tokens = params
		.split(",")
		.map(t => t.trim())
		.filter(Boolean);
	return tokens.map((token, idx) => {
		let type: UnidbgParamType = "string";
		let rawName = `param${idx}`;
		let className: string | undefined;

		if (token.includes(":")) {
			const [n, t] = token.split(":");
			rawName = n.trim();
			const lowerType = t.trim().toLowerCase();
			if (
				lowerType === "bytes" ||
				lowerType === "byte[]" ||
				lowerType === "bytearray" ||
				lowerType === "hex" ||
				lowerType === "[b"
			) {
				type = "bytes";
			} else if (lowerType === "int[]" || lowerType === "intarray" || lowerType === "[i") {
				type = "int[]";
			} else if (lowerType === "short[]" || lowerType === "shortarray" || lowerType === "[s") {
				type = "short[]";
			} else if (lowerType === "float[]" || lowerType === "floatarray" || lowerType === "[f") {
				type = "float[]";
			} else if (lowerType === "double[]" || lowerType === "doublearray" || lowerType === "[d") {
				type = "double[]";
			} else if (
				lowerType === "string[]" ||
				lowerType === "str[]" ||
				lowerType === "stringarray" ||
				lowerType === "[ljava/lang/string;"
			) {
				type = "string[]";
			} else if (
				lowerType === "context" ||
				lowerType === "android/content/context" ||
				lowerType === "landroid/content/context;"
			) {
				type = "context";
				className = "android/content/Context";
			} else if (lowerType === "object[]" || lowerType.startsWith("[l")) {
				type = "object[]";
				className = t
					.trim()
					.replace(/^object\[\]:?/i, "")
					.replace(/^\[L?/i, "")
					.replace(/;?$/, "");
			} else if (lowerType === "int" || lowerType === "integer" || lowerType === "i") {
				type = "int";
			} else if (lowerType === "long" || lowerType === "j") {
				type = "long";
			} else if (lowerType === "bool" || lowerType === "boolean" || lowerType === "z") {
				type = "boolean";
			} else if (lowerType.startsWith("object") || lowerType.startsWith("l")) {
				type = "object";
				className = t
					.trim()
					.replace(/^object:?/i, "")
					.replace(/^L/i, "")
					.replace(/;$/, "");
			} else {
				type = "string";
			}
		} else {
			const lowerToken = token.toLowerCase();
			if (
				lowerToken === "bytes" ||
				lowerToken === "byte[]" ||
				lowerToken === "bytearray" ||
				lowerToken === "hex" ||
				lowerToken === "[b"
			) {
				type = "bytes";
				rawName = `bytesParam${idx}`;
			} else if (lowerToken === "int[]" || lowerToken === "intarray" || lowerToken === "[i") {
				type = "int[]";
				rawName = `intArrayParam${idx}`;
			} else if (lowerToken === "short[]" || lowerToken === "shortarray" || lowerToken === "[s") {
				type = "short[]";
				rawName = `shortArrayParam${idx}`;
			} else if (lowerToken === "float[]" || lowerToken === "floatarray" || lowerToken === "[f") {
				type = "float[]";
				rawName = `floatArrayParam${idx}`;
			} else if (lowerToken === "double[]" || lowerToken === "doublearray" || lowerToken === "[d") {
				type = "double[]";
				rawName = `doubleArrayParam${idx}`;
			} else if (
				lowerToken === "string[]" ||
				lowerToken === "str[]" ||
				lowerToken === "stringarray" ||
				lowerToken === "[ljava/lang/string;"
			) {
				type = "string[]";
				rawName = `stringArrayParam${idx}`;
			} else if (
				lowerToken === "context" ||
				lowerToken === "android/content/context" ||
				lowerToken === "landroid/content/context;"
			) {
				type = "context";
				className = "android/content/Context";
				rawName = `contextParam${idx}`;
			} else if (lowerToken === "object[]" || lowerToken.startsWith("[l")) {
				type = "object[]";
				rawName = `objArrayParam${idx}`;
				className = token
					.trim()
					.replace(/^object\[\]:?/i, "")
					.replace(/^\[L?/i, "")
					.replace(/;?$/, "");
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
		return { name: sanitizeJavaIdentifier(rawName, `param${idx}`), type, className };
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
			} else if (raw[i + 1] === "I") {
				params.push({ name: `intArrayParam${idx++}`, type: "int[]" });
				i += 2;
			} else if (raw[i + 1] === "S") {
				params.push({ name: `shortArrayParam${idx++}`, type: "short[]" });
				i += 2;
			} else if (raw[i + 1] === "F") {
				params.push({ name: `floatArrayParam${idx++}`, type: "float[]" });
				i += 2;
			} else if (raw[i + 1] === "D") {
				params.push({ name: `doubleArrayParam${idx++}`, type: "double[]" });
				i += 2;
			} else if (raw[i + 1] === "L") {
				const end = raw.indexOf(";", i + 1);
				if (end === -1) throw new Error(`Malformed JNI class descriptor in signature '${signature}'`);
				const className = raw.substring(i + 2, end);
				if (className === "java/lang/String") {
					params.push({ name: `stringArrayParam${idx++}`, type: "string[]" });
				} else {
					params.push({ name: `objArrayParam${idx++}`, type: "object[]", className });
				}
				i = end + 1;
			} else if (raw[i + 1] === "Z" || raw[i + 1] === "J" || raw[i + 1] === "C") {
				throw new Error(
					`Unsupported JNI primitive array parameter descriptor '[${raw[i + 1]}' in '${signature}'. Upstream Unidbg provides ByteArray ([B), IntArray ([I), ShortArray ([S), FloatArray ([F), DoubleArray ([D), and ArrayObject; LongArray ([J), BooleanArray ([Z), and CharArray ([C) are not provided by upstream Unidbg.`,
				);
			} else {
				throw new Error(
					`Unsupported JNI array parameter descriptor in '${signature}'. Supported array types include '[B' (byte[]), '[I' (int[]), '[S' (short[]), '[F' (float[]), '[D' (double[]), and '[L...;' (Object[]).`,
				);
			}
		} else if (c === "L") {
			const end = raw.indexOf(";", i);
			if (end === -1) throw new Error(`Malformed JNI class descriptor in signature '${signature}'`);
			const className = raw.substring(i + 1, end);
			if (className === "java/lang/String") {
				params.push({ name: `strParam${idx++}`, type: "string" });
			} else if (className === "android/content/Context") {
				params.push({ name: `contextParam${idx++}`, type: "context", className: "android/content/Context" });
			} else {
				params.push({ name: `objParam${idx++}`, type: "object", className });
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
				case "int[]":
					return "[I";
				case "short[]":
					return "[S";
				case "float[]":
					return "[F";
				case "double[]":
					return "[D";
				case "string[]":
					return "[Ljava/lang/String;";
				case "object[]":
					return p.className
						? p.className.startsWith("[")
							? p.className
							: `[L${p.className.replace(/^L|;$/g, "")};`
						: "[Ljava/lang/Object;";
				case "context":
					return "Landroid/content/Context;";
				case "object":
					return p.className
						? p.className.startsWith("[") || p.className.startsWith("L")
							? p.className
							: `L${p.className};`
						: "Ljava/lang/Object;";
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

interface SharedVmSetupOptions {
	apkPath?: string;
	apiLevel?: number;
	envProfile?: UnidbgEnvProfile | string;
	isProbe?: boolean;
}

function buildSharedVmSetup(options: SharedVmSetupOptions): { imports: string[]; setupCode: string } {
	const apiLevel = options.apiLevel ?? 23;
	const label = options.isProbe ? "[Unidbg Probe]" : "[Unidbg Env]";

	let envProfileObj: UnidbgEnvProfile | undefined;
	if (typeof options.envProfile === "string") {
		try {
			envProfileObj = JSON.parse(options.envProfile);
		} catch {
			envProfileObj = { packageName: options.envProfile };
		}
	} else if (options.envProfile) {
		envProfileObj = options.envProfile;
	}

	const apkBindingCode = options.apkPath
		? `        String configuredApk = "${escapeJavaString(options.apkPath.replace(/\\/g, "/"))}";
        File apkFile = resolveTargetFile(configuredApk);
        if (!apkFile.canRead()) {
            throw new IllegalArgumentException("${label} Requested APK not found or not readable: " + configuredApk);
        }
        System.out.println("${label} Binding APK package: " + apkFile.getAbsolutePath());
        this.vm = emulator.createDalvikVM(apkFile);
        try {
            System.out.println("${label} APK Package: " + vm.getPackageName());
            System.out.println("${label} APK Version: " + vm.getVersionName() + " (Code: " + vm.getVersionCode() + ")");
        } catch (Throwable t) {
            System.out.println("${label} APK metadata note: " + t.getMessage());
        }`
		: `        this.vm = emulator.createDalvikVM();`;

	let systemPropsCode = "";
	if (envProfileObj?.properties) {
		const propStatements = Object.entries(envProfileObj.properties).map(
			([k, v]) => `        System.setProperty("${escapeJavaString(k)}", "${escapeJavaString(v)}");`,
		);
		if (propStatements.length > 0) {
			systemPropsCode = `\n        // Explicit Environment System Properties\n${propStatements.join("\n")}\n`;
		}
	}

	let jniEnvCode = "";
	if (envProfileObj) {
		const fDir = envProfileObj.filesDir
			? escapeJavaString(envProfileObj.filesDir)
			: envProfileObj.packageName
				? `/data/data/${escapeJavaString(envProfileObj.packageName)}/files`
				: undefined;
		const cDir = envProfileObj.cacheDir
			? escapeJavaString(envProfileObj.cacheDir)
			: envProfileObj.packageName
				? `/data/data/${escapeJavaString(envProfileObj.packageName)}/cache`
				: undefined;

		const objectMethodCases: string[] = [];
		const staticObjectMethodCases: string[] = [];
		const booleanMethodCases: string[] = [];
		const staticBooleanMethodCases: string[] = [];
		const intMethodCases: string[] = [];
		const staticIntMethodCases: string[] = [];
		const longMethodCases: string[] = [];
		const staticLongMethodCases: string[] = [];

		if (envProfileObj.packageName) {
			objectMethodCases.push(
				`                    case "android/content/Context->getPackageName()Ljava/lang/String;":\n                        return new StringObject(vm, "${escapeJavaString(envProfileObj.packageName)}");`,
			);
		}
		objectMethodCases.push(
			`                    case "android/content/Context->getApplicationContext()Landroid/content/Context;":\n                        return dvmObject;`,
		);
		if (fDir) {
			objectMethodCases.push(
				`                    case "android/content/Context->getFilesDir()Ljava/io/File;":\n                        return vm.resolveClass("java/io/File").newObject(new File("${fDir}"));`,
			);
		}
		if (cDir) {
			objectMethodCases.push(
				`                    case "android/content/Context->getCacheDir()Ljava/io/File;":\n                        return vm.resolveClass("java/io/File").newObject(new File("${cDir}"));`,
			);
		}
		if (envProfileObj.appName) {
			objectMethodCases.push(
				`                    case "android/content/pm/ApplicationInfo->loadLabel(Landroid/content/pm/PackageManager;)Ljava/lang/CharSequence;":\n                        return new StringObject(vm, "${escapeJavaString(envProfileObj.appName)}");`,
			);
		}
		staticObjectMethodCases.push(
			`                    case "android/app/ActivityThread->currentActivityThread()Landroid/app/ActivityThread;":\n                        return vm.resolveClass("android/app/ActivityThread").newObject(null);`,
		);
		objectMethodCases.push(
			`                    case "android/app/ActivityThread->getApplication()Landroid/app/Application;":\n                        return vm.resolveClass("android/app/Application").newObject(null);`,
		);

		if (envProfileObj.overrides && Array.isArray(envProfileObj.overrides)) {
			for (const ov of envProfileObj.overrides) {
				const sig = escapeJavaString(ov.signature);
				const isStatic = Boolean(ov.isStatic);
				const targetList = isStatic ? staticObjectMethodCases : objectMethodCases;
				const targetBoolList = isStatic ? staticBooleanMethodCases : booleanMethodCases;
				const targetIntList = isStatic ? staticIntMethodCases : intMethodCases;
				const targetLongList = isStatic ? staticLongMethodCases : longMethodCases;

				switch (ov.returnType) {
					case "int":
						targetIntList.push(
							`                    case "${sig}":\n                        return ${Number.parseInt(String(ov.value ?? 0), 10)};`,
						);
						break;
					case "long":
						targetLongList.push(
							`                    case "${sig}":\n                        return ${BigInt(String(ov.value ?? 0)).toString()}L;`,
						);
						break;
					case "boolean":
						targetBoolList.push(
							`                    case "${sig}":\n                        return ${Boolean(ov.value)};`,
						);
						break;
					case "bytes":
						targetList.push(
							`                    case "${sig}":\n                        return new ByteArray(vm, parseBytes("${escapeJavaString(String(ov.value ?? ""))}"));`,
						);
						break;
					case "int[]": {
						const valStr = Array.isArray(ov.value) ? ov.value.join(",") : String(ov.value ?? "");
						targetList.push(
							`                    case "${sig}":\n                        return new IntArray(vm, parseIntArray("${escapeJavaString(valStr)}"));`,
						);
						break;
					}
					case "short[]": {
						const valStr = Array.isArray(ov.value) ? ov.value.join(",") : String(ov.value ?? "");
						targetList.push(
							`                    case "${sig}":\n                        return new ShortArray(vm, parseShortArray("${escapeJavaString(valStr)}"));`,
						);
						break;
					}
					case "float[]": {
						const valStr = Array.isArray(ov.value) ? ov.value.join(",") : String(ov.value ?? "");
						targetList.push(
							`                    case "${sig}":\n                        return new FloatArray(vm, parseFloatArray("${escapeJavaString(valStr)}"));`,
						);
						break;
					}
					case "double[]": {
						const valStr = Array.isArray(ov.value) ? ov.value.join(",") : String(ov.value ?? "");
						targetList.push(
							`                    case "${sig}":\n                        return new DoubleArray(vm, parseDoubleArray("${escapeJavaString(valStr)}"));`,
						);
						break;
					}
					case "string[]": {
						const strs = (Array.isArray(ov.value) ? ov.value : [])
							.map(s => `"${escapeJavaString(String(s))}"`)
							.join(", ");
						targetList.push(
							`                    case "${sig}":\n                        return ArrayObject.newStringArray(vm, ${strs});`,
						);
						break;
					}
					case "void":
						break;
					case "string":
					default:
						targetList.push(
							`                    case "${sig}":\n                        return new StringObject(vm, "${escapeJavaString(String(ov.value ?? ""))}");`,
						);
						break;
				}
			}
		}

		jniEnvCode = `
        // Explicit JNI Environment Profile
        this.vm.setJni(new AbstractJni() {
            @Override
            public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
                switch (signature) {
${objectMethodCases.join("\n")}
                    default:
                        System.err.println("[Truthful JNI Warning] Unsupported JNI method: " + signature + " on object: " + dvmObject);
                        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
                }
            }

            @Override
            public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
                switch (signature) {
${staticObjectMethodCases.join("\n")}
                    default:
                        System.err.println("[Truthful JNI Warning] Unsupported JNI static method: " + signature + " on class: " + dvmClass);
                        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
                }
            }

            @Override
            public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
                switch (signature) {
${booleanMethodCases.join("\n")}
                    default:
                        System.err.println("[Truthful JNI Warning] Unsupported JNI boolean method: " + signature + " on object: " + dvmObject);
                        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
                }
            }

            @Override
            public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
                switch (signature) {
${staticBooleanMethodCases.join("\n")}
                    default:
                        System.err.println("[Truthful JNI Warning] Unsupported JNI static boolean method: " + signature + " on class: " + dvmClass);
                        return super.callStaticBooleanMethodV(vm, dvmClass, signature, vaList);
                }
            }

            @Override
            public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
                switch (signature) {
${intMethodCases.join("\n")}
                    default:
                        System.err.println("[Truthful JNI Warning] Unsupported JNI int method: " + signature + " on object: " + dvmObject);
                        return super.callIntMethodV(vm, dvmObject, signature, vaList);
                }
            }

            @Override
            public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
                switch (signature) {
${staticIntMethodCases.join("\n")}
                    default:
                        System.err.println("[Truthful JNI Warning] Unsupported JNI static int method: " + signature + " on class: " + dvmClass);
                        return super.callStaticIntMethodV(vm, dvmClass, signature, vaList);
                }
            }

            @Override
            public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
                switch (signature) {
${longMethodCases.join("\n")}
                    default:
                        System.err.println("[Truthful JNI Warning] Unsupported JNI long method: " + signature + " on object: " + dvmObject);
                        return super.callLongMethodV(vm, dvmObject, signature, vaList);
                }
            }

            @Override
            public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
                switch (signature) {
${staticLongMethodCases.join("\n")}
                    default:
                        System.err.println("[Truthful JNI Warning] Unsupported JNI static long method: " + signature + " on class: " + dvmClass);
                        return super.callStaticLongMethodV(vm, dvmClass, signature, vaList);
                }
            }
        });`;
	}

	const setupCode = `        Memory memory = emulator.getMemory();
        int apiLevel = ${apiLevel};
        if (apiLevel != 19 && apiLevel != 23) {
            System.out.println("${label} [Warning] API level " + apiLevel + " requested; upstream Unidbg bundles sdk19 and sdk23 sysroots. If symbols are missing, supply custom sysroot or APK dependencies.");
        }
        memory.setLibraryResolver(new AndroidResolver(apiLevel));
${systemPropsCode}
${apkBindingCode}

        this.vm.setDvmClassFactory(new ProxyClassFactory());
        this.vm.setVerbose(true);

        new JniGraphics(emulator, vm).register(memory);
        new AndroidModule(emulator, vm).register(memory);
${jniEnvCode}`;

	const imports = [
		"import com.github.unidbg.linux.android.AndroidResolver;",
		"import com.github.unidbg.linux.android.dvm.AbstractJni;",
		"import com.github.unidbg.linux.android.dvm.BaseVM;",
		"import com.github.unidbg.linux.android.dvm.DalvikModule;",
		"import com.github.unidbg.linux.android.dvm.DvmClass;",
		"import com.github.unidbg.linux.android.dvm.DvmObject;",
		"import com.github.unidbg.linux.android.dvm.StringObject;",
		"import com.github.unidbg.linux.android.dvm.VM;",
		"import com.github.unidbg.linux.android.dvm.VaList;",
		"import com.github.unidbg.linux.android.dvm.VarArg;",
		"import com.github.unidbg.linux.android.dvm.array.ArrayObject;",
		"import com.github.unidbg.linux.android.dvm.array.ByteArray;",
		"import com.github.unidbg.linux.android.dvm.array.DoubleArray;",
		"import com.github.unidbg.linux.android.dvm.array.FloatArray;",
		"import com.github.unidbg.linux.android.dvm.array.IntArray;",
		"import com.github.unidbg.linux.android.dvm.array.ShortArray;",
		"import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;",
		"import com.github.unidbg.memory.Memory;",
		"import com.github.unidbg.utils.Inspector;",
		"import com.github.unidbg.virtualmodule.android.AndroidModule;",
		"import com.github.unidbg.virtualmodule.android.JniGraphics;",
	];

	return { imports, setupCode };
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
			} else if (p.type === "int[]") {
				paramConversions.push(
					`            int[] ${varName}Raw = params.length > ${idx} ? parseIntArray(params[${idx}]) : new int[0];`,
				);
				paramConversions.push(`            IntArray ${varName} = new IntArray(vm, ${varName}Raw);`);
				invocationArgs.push(varName);
			} else if (p.type === "short[]") {
				paramConversions.push(
					`            short[] ${varName}Raw = params.length > ${idx} ? parseShortArray(params[${idx}]) : new short[0];`,
				);
				paramConversions.push(`            ShortArray ${varName} = new ShortArray(vm, ${varName}Raw);`);
				invocationArgs.push(varName);
			} else if (p.type === "float[]") {
				paramConversions.push(
					`            float[] ${varName}Raw = params.length > ${idx} ? parseFloatArray(params[${idx}]) : new float[0];`,
				);
				paramConversions.push(`            FloatArray ${varName} = new FloatArray(vm, ${varName}Raw);`);
				invocationArgs.push(varName);
			} else if (p.type === "double[]") {
				paramConversions.push(
					`            double[] ${varName}Raw = params.length > ${idx} ? parseDoubleArray(params[${idx}]) : new double[0];`,
				);
				paramConversions.push(`            DoubleArray ${varName} = new DoubleArray(vm, ${varName}Raw);`);
				invocationArgs.push(varName);
			} else if (p.type === "string[]") {
				paramConversions.push(
					`            String[] ${varName}Raw = params.length > ${idx} ? parseStringArray(params[${idx}]) : new String[0];`,
				);
				paramConversions.push(
					`            ArrayObject ${varName} = ArrayObject.newStringArray(vm, ${varName}Raw);`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "object[]") {
				const elemCls = p.className ? p.className.replace(/^\[L?/, "").replace(/;?$/, "") : "java/lang/Object";
				paramConversions.push(
					`            DvmClass ${varName}ElemCls = vm.resolveClass("${escapeJavaString(elemCls)}");`,
				);
				paramConversions.push(
					`            DvmObject<?>[] ${varName}Items = parseDvmObjectArray(vm, ${varName}ElemCls, params.length > ${idx} ? params[${idx}] : null);`,
				);
				paramConversions.push(
					`            ArrayObject ${varName} = ArrayObject.newObjectArray(${varName}ElemCls, ${varName}Items);`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "context") {
				paramConversions.push(
					`            DvmObject<?> ${varName} = vm.resolveClass("android/content/Context").newObject(params.length > ${idx} ? parseString(params[${idx}]) : null);`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "object") {
				const targetObjClass = p.className || "java/lang/Object";
				paramConversions.push(
					`            String ${varName}Raw = params.length > ${idx} ? parseString(params[${idx}]) : null;`,
				);
				paramConversions.push(
					`            DvmObject<?> ${varName} = vm.resolveClass("${escapeJavaString(targetObjClass)}").newObject(${varName}Raw);`,
				);
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
			if (p.type === "context" || p.type === "object" || p.type === "object[]" || p.type === "string[]") {
				throw new Error(
					`Direct native export mode does not support complex parameter '${p.name}: ${p.type}'. Direct native exports only support scalar primitives (int, long, boolean), 'bytes' (byte buffer), and 'string' (C string). Use target class name and JNI signature to invoke JNI methods.`,
				);
			} else if (p.type === "bytes") {
				paramConversions.push(
					`            byte[] ${varName} = params.length > ${idx} ? parseBytes(params[${idx}]) : new byte[0];`,
				);
				invocationArgs.push(varName);
			} else if (p.type === "int[]") {
				paramConversions.push(
					`            int[] ${varName}Arr = params.length > ${idx} ? parseIntArray(params[${idx}]) : new int[0];`,
				);
				paramConversions.push(
					`            com.sun.jna.Pointer ${varName} = emulator.getMemory().allocate(Math.max(4, ${varName}Arr.length * 4), "intArray_${idx}");`,
				);
				paramConversions.push(
					`            for (int i = 0; i < ${varName}Arr.length; i++) { ${varName}.setInt(i * 4L, ${varName}Arr[i]); }`,
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
				? `            DvmObject<?> ret = dvmClass.callStaticJniMethodObject(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            printReturnValue(ret, "${escapeJavaString(entry)}");`
				: `            DvmObject<?> instance = dvmClass.newObject(null);\n            DvmObject<?> ret = instance.callJniMethodObject(emulator, "${escapeJavaString(entry)}${escapeJavaString(signature)}"${argsCall});\n            printReturnValue(ret, "${escapeJavaString(entry)}");`;
		}
	} else {
		classResolutionCode = `        this.dvmClass = null;\n        System.out.println("No target JNI class specified. Direct native module export mode on backend: " + emulator.getBackend());`;
		methodCallCode = `            Module module = dalvikModule.getModule();\n            Number ret = module.callFunction(emulator, "${escapeJavaString(entry)}"${argsCall});\n            System.out.println("Return: 0x" + Long.toHexString(ret.longValue()) + " (" + ret + ")");`;
	}

	const arrayArgInspections: string[] = [];
	if (targetClass) {
		parsedParams.forEach((p, idx) => {
			if (
				p.type === "bytes" ||
				p.type === "int[]" ||
				p.type === "short[]" ||
				p.type === "float[]" ||
				p.type === "double[]" ||
				p.type === "string[]"
			) {
				arrayArgInspections.push(
					`            printReturnValue(arg_${idx}, "Argument '${escapeJavaString(p.name)}'");`,
				);
			}
		});
	}
	const arrayArgInspectionCode = arrayArgInspections.length > 0 ? "\n" + arrayArgInspections.join("\n") : "";
	const { imports: vmImports, setupCode: vmSetupCode } = buildSharedVmSetup({
		apkPath: options.apkPath,
		apiLevel: options.apiLevel,
		envProfile: options.envProfile,
		isProbe: false,
	});

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
${vmImports.join("\n")}
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

${vmSetupCode}
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

    private static int[] parseIntArray(String input) {
        if (input == null || input.isEmpty()) return new int[0];
        String trimmed = input.trim();
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
        }
        if (trimmed.isEmpty()) return new int[0];
        String[] tokens = trimmed.split(",");
        int[] result = new int[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            result[i] = parseInt(tokens[i].trim());
        }
        return result;
    }

    private static short[] parseShortArray(String input) {
        if (input == null || input.isEmpty()) return new short[0];
        String trimmed = input.trim();
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
        }
        if (trimmed.isEmpty()) return new short[0];
        String[] tokens = trimmed.split(",");
        short[] result = new short[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            result[i] = (short) parseInt(tokens[i].trim());
        }
        return result;
    }

    private static float[] parseFloatArray(String input) {
        if (input == null || input.isEmpty()) return new float[0];
        String trimmed = input.trim();
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
        }
        if (trimmed.isEmpty()) return new float[0];
        String[] tokens = trimmed.split(",");
        float[] result = new float[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            result[i] = Float.parseFloat(tokens[i].trim());
        }
        return result;
    }

    private static double[] parseDoubleArray(String input) {
        if (input == null || input.isEmpty()) return new double[0];
        String trimmed = input.trim();
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
        }
        if (trimmed.isEmpty()) return new double[0];
        String[] tokens = trimmed.split(",");
        double[] result = new double[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            result[i] = Double.parseDouble(tokens[i].trim());
        }
        return result;
    }

    private static String[] parseStringArray(String input) {
        if (input == null || input.isEmpty()) return new String[0];
        String trimmed = input.trim();
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
        }
        if (trimmed.isEmpty()) return new String[0];
        String[] tokens = trimmed.split(",");
        String[] result = new String[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            result[i] = parseString(tokens[i].trim());
        }
        return result;
    }
    private static DvmObject<?>[] parseDvmObjectArray(VM vm, DvmClass elementClass, String input) {
        if (input == null || input.isEmpty()) return new DvmObject<?>[0];
        String trimmed = input.trim();
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
        }
        if (trimmed.isEmpty()) return new DvmObject<?>[0];
        String[] tokens = trimmed.split(",");
        DvmObject<?>[] result = new DvmObject<?>[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            String val = parseString(tokens[i].trim());
            result[i] = elementClass != null ? elementClass.newObject(val) : new StringObject(vm, val);
        }
        return result;
    }

    private static void printReturnValue(Object ret, String entry) {
        if (ret == null) {
            System.out.println("Return (object): null");
            return;
        }
        if (ret instanceof DvmObject) {
            DvmObject<?> dvmObj = (DvmObject<?>) ret;
            Object val = dvmObj.getValue();
            if (val instanceof byte[]) {
                byte[] b = (byte[]) val;
                System.out.println("Return (ByteArray, len=" + b.length + "): " + bytesToHex(b));
                Inspector.inspect(b, entry + " output");
            } else if (val instanceof int[]) {
                System.out.println("Return (IntArray): " + Arrays.toString((int[]) val));
            } else if (val instanceof short[]) {
                System.out.println("Return (ShortArray): " + Arrays.toString((short[]) val));
            } else if (val instanceof float[]) {
                System.out.println("Return (FloatArray): " + Arrays.toString((float[]) val));
            } else if (val instanceof double[]) {
                System.out.println("Return (DoubleArray): " + Arrays.toString((double[]) val));
            } else if (val instanceof DvmObject[]) {
                DvmObject<?>[] arr = (DvmObject<?>[]) val;
                StringBuilder sb = new StringBuilder("[");
                for (int i = 0; i < arr.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(arr[i] != null ? String.valueOf(arr[i].getValue()) : "null");
                }
                sb.append("]");
                System.out.println("Return (ArrayObject, len=" + arr.length + "): " + sb.toString());
            } else if (val instanceof String) {
                System.out.println("Return (StringObject): \\"" + val + "\\"");
            } else {
                System.out.println("Return (DvmObject: " + dvmObj.getObjectType() + "): " + val);
            }
        } else {
            System.out.println("Return: " + ret);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
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
${methodCallCode}${arrayArgInspectionCode}
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

        IpaLoader ipaLoader = ${is64 ? 'new IpaLoader64(ipa, new File("target/rootfs/ipa"))' : 'new IpaLoader32(ipa, new File("target/rootfs/ipa"))'};
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

/**
 * Generate Android RegisterNatives dynamic probe Java source code.
 *
 * Hooks JNIEnv vtable index 215 (RegisterNatives) via Unidbg Svc wrapper,
 * runs target library load + JNI_OnLoad, captures all registered methods,
 * verifies retval === 0 confirmation status, and emits structured events.
 */
export function generateAndroidProbeHarness(options: UnidbgProbeOptions): string {
	let clsName = options.harnessClassName;
	if (!clsName && options.outPath) {
		const base = path.basename(options.outPath);
		clsName = sanitizeJavaIdentifier(base.replace(/\.java$/i, ""));
	}
	if (!clsName) {
		clsName = "UnidbgProbe";
	}

	const pkg = options.packageName ?? "com.reverse.unidbg.probe";
	const is64 = String(options.arch ?? "64") === "64";
	const backend = options.backend ?? "unicorn2";
	const callOnLoad = options.callOnLoad ?? true;
	const processName = options.processName ?? "com.reverse.unidbg.probe";
	const apiLevel = options.apiLevel ?? 23;
	const escapedTargetPath = escapeJavaString(options.targetPath.replace(/\\/g, "/"));
	const safeCommentTarget = escapedTargetPath.replace(/\*\//g, "* /");

	const backendFactory =
		backend === "dynarmic"
			? "builder.addBackendFactory(new DynarmicFactory(true));"
			: "builder.addBackendFactory(new Unicorn2Factory(true));";

	const { imports: vmImports, setupCode: vmSetupCode } = buildSharedVmSetup({
		apkPath: options.apkPath,
		apiLevel: options.apiLevel,
		envProfile: options.envProfile,
		isProbe: true,
	});

	return `package ${pkg};

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
${vmImports.join("\n")}
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Auto-generated Unidbg Android RegisterNatives Dynamic Probe Harness
 * Target: ${safeCommentTarget}
 * Arch: ${is64 ? "ARM64" : "ARM32"} | Backend: ${backend} | API Level: ${apiLevel}
 */
public class ${clsName} {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final List<Map<String, Object>> capturedEvents = Collections.synchronizedList(new ArrayList<>());

    public ${clsName}() {
        AndroidEmulatorBuilder builder = ${is64 ? "AndroidEmulatorBuilder.for64Bit()" : "AndroidEmulatorBuilder.for32Bit()"};
        builder.setProcessName("${escapeJavaString(processName)}");
        ${backendFactory}
        this.emulator = builder.build();

${vmSetupCode}

        installRegisterNativesHook();
    }

    private void installRegisterNativesHook() {
        Pointer jniEnv = vm.getJNIEnv();
        Pointer vtable = jniEnv.getPointer(0);
        int ptrSize = emulator.getPointerSize();
        int regNativesOffset = 215 * ptrSize;
        Pointer origRegNatives = vtable.getPointer(regNativesOffset);

        int origInsn = origRegNatives.getInt(0);
        int origSvcNumber = emulator.is64Bit()
            ? ((origInsn ^ 0xd4000001) >>> 5)
            : (origInsn & 0x00ffffff);
        final Svc origSvc = emulator.getSvcMemory().getSvc(origSvcNumber);
        if (origSvc == null) {
            throw new IllegalStateException("Failed to resolve upstream RegisterNatives SVC from vtable[215] at " + origRegNatives + " (svc number: 0x" + Integer.toHexString(origSvcNumber) + ")");
        }
        Svc probeSvc = emulator.is64Bit() ? new Arm64Svc("ProbeRegisterNatives") {
            @Override
            public long handle(Emulator<?> emu) {
                return onRegisterNatives(emu, origSvc);
            }
        } : new ArmSvc("ProbeRegisterNatives") {
            @Override
            public long handle(Emulator<?> emu) {
                return onRegisterNatives(emu, origSvc);
            }
        };

        Pointer probePtr = emulator.getSvcMemory().registerSvc(probeSvc);
        vtable.setPointer(regNativesOffset, probePtr);
    }

    private long onRegisterNatives(Emulator<?> emu, Svc origSvc) {
        RegisterContext context = emu.getContext();
        UnidbgPointer clazz = context.getPointerArg(1);
        Pointer methods = context.getPointerArg(2);
        int nMethods = context.getIntArg(3);

        // Execute original upstream RegisterNatives first so nativesMap is updated and status code is genuine
        long ret = origSvc.handle(emu);
        boolean isConfirmed = (ret == 0L);

        DvmClass dvmClass = null;
        try {
            dvmClass = (DvmClass) vm.getObject(clazz.toIntPeer());
        } catch (Throwable ignored) {}
        String className = dvmClass != null ? dvmClass.getClassName() : "UnknownClass";

        List<Map<String, Object>> methodList = new ArrayList<>();
        int entrySize = 3 * emu.getPointerSize();
        int cappedMethods = Math.min(Math.max(0, nMethods), 256);
        boolean truncated = (nMethods > 256);

        for (int i = 0; i < cappedMethods; i++) {
            Map<String, Object> m = new LinkedHashMap<>();
            try {
                Pointer method = methods.share(i * (long) entrySize);
                Pointer namePtr = method.getPointer(0);
                Pointer sigPtr = method.getPointer(emu.getPointerSize());
                Pointer fnPtr = method.getPointer(2L * emu.getPointerSize());

                String methodName = namePtr != null ? namePtr.getString(0) : null;
                if (methodName != null && methodName.length() > 512) {
                    methodName = methodName.substring(0, 512);
                }
                String sigName = sigPtr != null ? sigPtr.getString(0) : null;
                if (sigName != null && sigName.length() > 1024) {
                    sigName = sigName.substring(0, 1024);
                }
                long fnAddr = fnPtr != null ? UnidbgPointer.nativeValue(fnPtr) : 0L;
                Module mod = emu.getMemory().findModuleByAddress(fnAddr);
                String modName = mod != null ? mod.name : null;
                String modPath = mod != null ? mod.getPath() : null;
                String baseHex = mod != null ? ("0x" + Long.toHexString(mod.base)) : null;
                String offsetHex = mod != null ? ("0x" + Long.toHexString(fnAddr - mod.base)) : null;
                String fnPtrHex = "0x" + Long.toHexString(fnAddr);

                m.put("name", methodName);
                m.put("signature", sigName);
                m.put("fnPtr", fnPtrHex);
                m.put("module", modName);
                m.put("modulePath", modPath);
                m.put("base", baseHex);
                m.put("offset", offsetHex);
            } catch (Exception e) {
                m.put("error", e.getMessage());
                m.put("index", i);
            }
            methodList.add(m);
        }

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("event", "jni_register_natives");
        event.put("status", isConfirmed ? "confirmed" : "rejected");
        event.put("retval", ret);
        event.put("class", className);
        event.put("nMethods", nMethods);
        event.put("methods", methodList);
        if (truncated) {
            event.put("truncated", true);
        }
        event.put("source", "unidbg");
        event.put("timestamp", System.currentTimeMillis());
        capturedEvents.add(event);

        String json = toJson(event);
        System.out.println("__UNIDBG_PROBE_EVENT_START__" + json + "__UNIDBG_PROBE_EVENT_END__");

        return ret;
    }

    public void runProbe(String targetPath, boolean callOnLoad) throws Exception {
        File targetFile = resolveTargetFile(targetPath);
        if (!targetFile.canRead()) {
            throw new IllegalArgumentException("Target binary not found or not readable: " + targetPath);
        }
        System.out.println("[Unidbg Probe] Loading target library: " + targetFile.getAbsolutePath());
        DalvikModule dalvikModule = vm.loadLibrary(targetFile, true);

        if (callOnLoad) {
            System.out.println("[Unidbg Probe] Calling JNI_OnLoad...");
            try {
                dalvikModule.callJNI_OnLoad(emulator);
                System.out.println("[Unidbg Probe] JNI_OnLoad completed successfully.");
            } catch (Throwable t) {
                System.err.println("[Unidbg Probe Error] JNI_OnLoad failed: " + t.getMessage());
                t.printStackTrace(System.err);
            }
        }

        System.out.println("__UNIDBG_PROBE_COMPLETE__TotalEvents=" + capturedEvents.size());
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

    private static String toJson(Object obj) {
        if (obj == null) return "null";
        if (obj instanceof String) {
            return "\\"" + escapeJson((String) obj) + "\\"";
        }
        if (obj instanceof Number || obj instanceof Boolean) {
            return String.valueOf(obj);
        }
        if (obj instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) obj;
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) sb.append(",");
                first = false;
                sb.append("\\"").append(escapeJson(String.valueOf(entry.getKey()))).append("\\":");
                sb.append(toJson(entry.getValue()));
            }
            sb.append("}");
            return sb.toString();
        }
        if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : list) {
                if (!first) sb.append(",");
                first = false;
                sb.append(toJson(item));
            }
            sb.append("]");
            return sb.toString();
        }
        return "\\"" + escapeJson(String.valueOf(obj)) + "\\"";
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') sb.append("\\\\\\"");
            else if (c == '\\\\') sb.append("\\\\\\\\");
            else if (c == '\\b') sb.append("\\\\b");
            else if (c == '\\f') sb.append("\\\\f");
            else if (c == '\\n') sb.append("\\\\n");
            else if (c == '\\r') sb.append("\\\\r");
            else if (c == '\\t') sb.append("\\\\t");
            else if (c < 32) sb.append(String.format("\\\\u%04x", (int) c));
            else sb.append(c);
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        try {
            ${clsName} probe = new ${clsName}();
            String target = args.length > 0 ? args[0] : "${escapedTargetPath}";
            boolean callOnLoad = args.length > 1 ? Boolean.parseBoolean(args[1]) : ${callOnLoad ? "true" : "false"};
            probe.runProbe(target, callOnLoad);
            System.exit(0);
        } catch (Throwable t) {
            System.err.println("[Unidbg Probe Fatal] " + t.getMessage());
            t.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
`;
}

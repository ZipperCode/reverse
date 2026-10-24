/**
 * JNI Enrichment and Signature Processing Utilities
 *
 * Implements standard official Android NDK JNI type and signature mapping,
 * BigInt-based load bias and static address conversion, ARM32 Thumb semantics
 * (bit 0 clearing with Thumb execution flag), target sample identity verification,
 * and canonicalization of confirmed dynamic RegisterNatives trace events.
 */
import { ToolError } from "@reverse/tui/tools/tool-errors";

/**
 * Standard Canonical JNI Method Record.
 * Represents a verified or proposed JNI method binding.
 */
export interface CanonicalJniMethodRecord {
	/** Canonical Java class name, e.g. "com/example/app/MainActivity" */
	className: string;
	/** Java native method name, e.g. "verifyLicense" */
	methodName: string;
	/** Java method signature in standard JVM descriptor format, e.g. "(Ljava/lang/String;[B)Z" */
	signature: string;
	/** Shared library / module name, e.g. "libnative-lib.so" */
	moduleName: string;
	/** Runtime module base address as hex string, e.g. "0x7f000000" */
	moduleBase?: string;
	/** Runtime or static native function pointer address as hex string, e.g. "0x7f001001" */
	functionAddress: string;
	/** Relative hex offset from module base, e.g. "0x1000" */
	moduleOffset?: string;
	/** Confirmation status; ONLY "confirmed" can be applied as verified facts */
	status: "confirmed";
	/**
	 * Provenance source: runtime tracer ("frida", "unidbg") or "manual" unverified supplied annotation.
	 * Manual entries cannot be certified as verified runtime facts.
	 */
	source: "frida" | "unidbg" | "manual" | string;
	/** Target binary SHA256; required for writeback verification */
	sampleSha256?: string;
	/**
	 * Verified runtime evidence flag.
	 * Derived internally from confirmed runtime event and target SHA-256 match.
	 * Caller-supplied values are never trusted alone for writeback.
	 */
	evidenceVerified?: boolean;
	/**
	 * Explicit static flag from DEX method flags (ACC_STATIC).
	 * If true: second JNI parameter is 'jclass clazz'.
	 * If false: second JNI parameter is 'jobject thiz'.
	 * If undefined: CANNOT be inferred from dynamic RegisterNatives alone.
	 */
	isStatic?: boolean;
	/**
	 * ARM32 Thumb mode flag.
	 * Set when function pointer has bit 0 set (fnPtr & 1n === 1n).
	 */
	isThumb?: boolean;
}

/**
 * Individual method entry inside a raw RegisterNatives event.
 */
export interface RawRegisterNativesMethod {
	name: string;
	signature: string;
	fnPtr: string;
	module?: string | null;
	modulePath?: string | null;
	base?: string | null;
	offset?: string | null;
}

/**
 * Raw RegisterNatives trace event emitted by frida or unidbg.
 */
export interface RawRegisterNativesEvent {
	event: "jni_register_natives";
	status: "confirmed" | "rejected" | string;
	retval: number;
	class: string;
	nMethods?: number;
	methods: RawRegisterNativesMethod[];
	source?: string;
	sampleSha256?: string;
}

/**
 * Parsed parameter representation for JNI functions.
 */
export interface ParsedJniParam {
	type: string;
	name: string;
	rawDescriptor: string;
	byteSize: number;
	isPointer: boolean;
	isJniObject: boolean;
}

/**
 * Parsed JNI method prototype.
 */
export interface ParsedJniPrototype {
	returnType: string;
	rawReturnDescriptor: string;
	parameters: ParsedJniParam[];
	isStatic?: boolean;
	cPrototype: string;
	ghidraPrototype: string;
}

export interface AddressRange {
	start: bigint;
	end: bigint;
}

export interface StaticAddressConversionOptions {
	runtimeAddress: string | bigint;
	moduleBase?: string | bigint;
	loadBias?: string | bigint;
	staticImageBase?: string | bigint;
	arch?: string;
	executableRanges?: AddressRange[];
	minLoadVaddr?: bigint;
}

export interface StaticAddressConversionResult {
	staticAddress: bigint;
	staticAddressHex: string;
	rva: bigint;
	rvaHex: string;
	isThumb: boolean;
}
export interface ElfJniMetadata {
	arch: string;
	bitness: 32 | 64;
	minLoadVaddr: bigint;
	executableRanges: AddressRange[];
	isArm32: boolean;
}

/**
 * Parse ELF headers to extract architecture, bitness, load bias base, and executable segment ranges.
 */
export function parseElfMetadataForJni(buf: Buffer): ElfJniMetadata {
	if (buf.length < 52 || buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
		return {
			arch: "unknown",
			bitness: 64,
			minLoadVaddr: 0n,
			executableRanges: [],
			isArm32: false,
		};
	}

	const is64 = buf[4] === 2;
	const isLe = buf[5] === 1;
	const bitness = is64 ? 64 : 32;

	const eMachine = isLe ? buf.readUInt16LE(18) : buf.readUInt16BE(18);
	let arch = "unknown";
	let isArm32 = false;
	if (eMachine === 40) {
		arch = "arm";
		isArm32 = true;
	} else if (eMachine === 183) {
		arch = "aarch64";
	} else if (eMachine === 3) {
		arch = "x86";
	} else if (eMachine === 62) {
		arch = "x86_64";
	}

	const phOff = is64
		? isLe
			? buf.readBigUInt64LE(32)
			: buf.readBigUInt64BE(32)
		: isLe
			? BigInt(buf.readUInt32LE(28))
			: BigInt(buf.readUInt32BE(28));

	const phEntSize = isLe ? buf.readUInt16LE(is64 ? 54 : 42) : buf.readUInt16BE(is64 ? 54 : 42);
	const phNum = isLe ? buf.readUInt16LE(is64 ? 56 : 44) : buf.readUInt16BE(is64 ? 56 : 44);

	const executableRanges: AddressRange[] = [];
	let minLoadVaddr: bigint | undefined;

	const phOffNum = Number(phOff);
	if (phOffNum > 0 && phEntSize > 0 && phNum > 0 && phOffNum + phNum * phEntSize <= buf.length) {
		for (let i = 0; i < phNum; i++) {
			const entryOff = phOffNum + i * phEntSize;
			const pType = isLe ? buf.readUInt32LE(entryOff) : buf.readUInt32BE(entryOff);

			// PT_LOAD = 1
			if (pType === 1) {
				const pFlags = is64
					? isLe
						? buf.readUInt32LE(entryOff + 4)
						: buf.readUInt32BE(entryOff + 4)
					: isLe
						? buf.readUInt32LE(entryOff + 24)
						: buf.readUInt32BE(entryOff + 24);

				const pVaddr = is64
					? isLe
						? buf.readBigUInt64LE(entryOff + 16)
						: buf.readBigUInt64BE(entryOff + 16)
					: isLe
						? BigInt(buf.readUInt32LE(entryOff + 8))
						: BigInt(buf.readUInt32BE(entryOff + 8));

				const pMemsz = is64
					? isLe
						? buf.readBigUInt64LE(entryOff + 40)
						: buf.readBigUInt64BE(entryOff + 40)
					: isLe
						? BigInt(buf.readUInt32LE(entryOff + 20))
						: BigInt(buf.readUInt32BE(entryOff + 20));

				if (minLoadVaddr === undefined || pVaddr < minLoadVaddr) {
					minLoadVaddr = pVaddr;
				}

				// Check executable flag: PF_X = 1
				if ((pFlags & 1) !== 0 && pMemsz > 0n) {
					executableRanges.push({
						start: pVaddr,
						end: pVaddr + pMemsz,
					});
				}
			}
		}
	}

	return {
		arch,
		bitness,
		minLoadVaddr: minLoadVaddr ?? 0n,
		executableRanges,
		isArm32,
	};
}

export interface JniEnrichPreviewItem {
	className: string;
	methodName: string;
	signature: string;
	isStatic: boolean | "unverified";
	originalAddress: string;
	staticAddress: string;
	isThumb: boolean;
	targetFunctionName: string;
	cPrototype: string;
	status: "eligible" | "rejected" | "out_of_bounds";
	reason?: string;
}

export interface JniEnrichSummary {
	total: number;
	eligible: number;
	rejected: number;
	items: JniEnrichPreviewItem[];
}

const HEX_ADDRESS_REGEX = /^(?:0[xX])?[0-9a-fA-F]{1,16}$/;
const METHOD_SIGNATURE_REGEX =
	/^\((?:\[*(?:[ZBCSIJFD]|L[a-zA-Z0-9_/$]+;))*\)(?:\[*(?:[ZBCSIJFD]|L[a-zA-Z0-9_/$]+;)|V)$/;

/**
 * Parse an address string or bigint into a validated non-negative BigInt.
 */
export function parseBigIntAddress(value: string | bigint, fieldName = "address"): bigint {
	if (typeof value === "bigint") {
		if (value < 0n) throw new ToolError(`${fieldName} cannot be negative`);
		return value;
	}
	if (typeof value !== "string" || !value.trim()) {
		throw new ToolError(`Missing or empty ${fieldName}`);
	}
	const clean = value.trim();
	if (!HEX_ADDRESS_REGEX.test(clean)) {
		throw new ToolError(`Invalid hex address format for ${fieldName}: '${value}'`);
	}
	const hexStr = clean.startsWith("0x") || clean.startsWith("0X") ? clean : `0x${clean}`;
	const parsed = BigInt(hexStr);
	if (parsed < 0n) throw new ToolError(`${fieldName} cannot be negative`);
	return parsed;
}

/**
 * Format a BigInt address into standard lowercase hex string (e.g. 0x1000).
 */
export function formatHexAddress(addr: bigint): string {
	return `0x${addr.toString(16)}`;
}

/**
 * Normalize a Java class name into standard internal slash-separated format (e.g. "com/example/MyClass").
 */
export function normalizeJavaClassName(className: string): string {
	let clean = className.trim();
	if (clean.startsWith("L") && clean.endsWith(";")) {
		clean = clean.slice(1, -1);
	}
	clean = clean.replace(/\./g, "/");
	while (clean.startsWith("/")) clean = clean.slice(1);
	while (clean.endsWith("/")) clean = clean.slice(0, -1);
	if (!clean) throw new ToolError("Empty Java class name");
	return clean;
}

/**
 * Canonicalize raw RegisterNatives events into verified CanonicalJniMethodRecords.
 *
 * Enforces strict confirmation contract:
 * - Event must be "jni_register_natives".
 * - ONLY status === "confirmed" and retval === 0 are accepted.
 * - Non-zero retval or rejected status is rejected.
 * - Verifies sample SHA-256 against expected hash if provided.
 */
export function canonicalizeRegisterNativesEvent(
	raw: unknown,
	options: {
		expectedSha256?: string;
		defaultModule?: string;
		isStaticMap?: Record<string, boolean>;
	} = {},
): CanonicalJniMethodRecord[] {
	if (!raw || typeof raw !== "object") {
		throw new ToolError("RegisterNatives event must be an object");
	}

	const event = raw as Record<string, unknown>;
	if (event.event !== "jni_register_natives") {
		throw new ToolError(`Unsupported event kind '${String(event.event)}': expected 'jni_register_natives'`);
	}

	const status = typeof event.status === "string" ? event.status.trim().toLowerCase() : "";
	const retval = event.retval;

	// In JNI spec, RegisterNatives returns 0 on success. ONLY numeric integer 0 confirms registration.
	if (status !== "confirmed" || typeof retval !== "number" || !Number.isInteger(retval) || retval !== 0) {
		throw new ToolError(
			`Cannot certify unconfirmed JNI registration: status is '${status}', retval is ${String(retval)}. ` +
				"Only confirmed registrations (status === 'confirmed' and numeric integer retval === 0) can be applied.",
		);
	}

	const rawSource = typeof event.source === "string" ? event.source : "frida";
	const isRuntimeSource =
		rawSource !== "manual" &&
		rawSource !== "supplied" &&
		(rawSource.includes("libart") ||
			rawSource.includes("RegisterNatives") ||
			rawSource.includes("jni") ||
			rawSource.includes("vtable") ||
			rawSource === "frida" ||
			rawSource === "unidbg");

	const defaultModule = options.defaultModule ?? "unknown.so";
	const eventSha256 =
		typeof event.sampleSha256 === "string"
			? event.sampleSha256.trim().toLowerCase()
			: typeof event.sha256 === "string"
				? event.sha256.trim().toLowerCase()
				: undefined;

	// Verify provenance: manual registrations cannot be certified as verified runtime facts
	const evidenceVerified = isRuntimeSource && retval === 0 && !!eventSha256;
	if (options.expectedSha256 && eventSha256) {
		const expectedLower = options.expectedSha256.trim().toLowerCase();
		if (eventSha256 !== expectedLower) {
			throw new ToolError(
				`Target sample SHA-256 mismatch: event was captured for '${eventSha256}', but active target has '${expectedLower}'.`,
			);
		}
	}

	const rawClass = String(event.class ?? "").trim();
	if (!rawClass) {
		throw new ToolError("Missing class name in RegisterNatives event");
	}
	const className = normalizeJavaClassName(rawClass);

	const rawMethods = event.methods;
	if (!Array.isArray(rawMethods) || rawMethods.length === 0) {
		throw new ToolError("RegisterNatives event contains no methods to enrich");
	}

	// Bound batch size to prevent uncontrolled allocation
	const maxBatch = 500;
	if (rawMethods.length > maxBatch) {
		throw new ToolError(
			`RegisterNatives method count (${rawMethods.length}) exceeds maximum batch limit of ${maxBatch}`,
		);
	}

	const records: CanonicalJniMethodRecord[] = [];
	for (let i = 0; i < rawMethods.length; i++) {
		const m = rawMethods[i];
		if (!m || typeof m !== "object") continue;

		const methodName = String(m.name ?? "").trim();
		if (!methodName || !/^[a-zA-Z0-9_$]+$/.test(methodName)) {
			throw new ToolError(`Invalid or empty method name at index ${i}: '${String(m.name)}'`);
		}

		const signature = String(m.signature ?? "").trim();
		if (!signature || !METHOD_SIGNATURE_REGEX.test(signature)) {
			throw new ToolError(
				`Invalid JVM method signature for method '${methodName}' at index ${i}: '${String(m.signature)}'`,
			);
		}

		const rawFnPtr = String(m.fnPtr ?? "").trim();
		if (!rawFnPtr) {
			throw new ToolError(`Missing fnPtr for method '${methodName}' at index ${i}`);
		}
		const fnPtrBigInt = parseBigIntAddress(rawFnPtr, `fnPtr for ${methodName}`);
		const functionAddress = formatHexAddress(fnPtrBigInt);

		const moduleName = String(m.module || defaultModule).trim();
		const baseStr = m.base ? String(m.base).trim() : undefined;
		let moduleBase: string | undefined;
		let moduleOffset: string | undefined;

		if (baseStr) {
			const baseBigInt = parseBigIntAddress(baseStr, `module base for ${methodName}`);
			moduleBase = formatHexAddress(baseBigInt);
			if (fnPtrBigInt >= baseBigInt) {
				const offsetBigInt = fnPtrBigInt - baseBigInt;
				moduleOffset = formatHexAddress(offsetBigInt);
			}
		}

		if (!moduleOffset && m.offset) {
			const offBigInt = parseBigIntAddress(String(m.offset), `offset for ${methodName}`);
			moduleOffset = formatHexAddress(offBigInt);
		}

		// Detect Thumb mode: lowest bit of ARM address is 1
		const isThumb = (fnPtrBigInt & 1n) === 1n;

		// Check isStatic from DEX metadata map if provided
		const mapKey = `${className}->${methodName}${signature}`;
		const isStatic = options.isStaticMap ? options.isStaticMap[mapKey] : undefined;

		records.push({
			className,
			methodName,
			signature,
			moduleName,
			moduleBase,
			functionAddress,
			moduleOffset,
			status: "confirmed",
			source: rawSource,
			sampleSha256: eventSha256,
			evidenceVerified,
			isStatic,
			isThumb,
		});
	}
	// Verify no conflicting duplicate function addresses in the same batch
	// Reject conflicting SAME method identity mapping to different addresses
	const methodToAddr = new Map<string, string>();
	for (const rec of records) {
		const methodKey = `${rec.className}->${rec.methodName}${rec.signature}`;
		const addr = rec.functionAddress.toLowerCase();
		if (methodToAddr.has(methodKey) && methodToAddr.get(methodKey) !== addr) {
			throw new ToolError(
				`Conflicting native function address for method '${methodKey}': mapped to both '${methodToAddr.get(methodKey)}' and '${addr}' in the same batch. Registration batch rejected.`,
			);
		}
		methodToAddr.set(methodKey, addr);
	}

	return records;
}

/**
 * Map an individual JNI type descriptor to C type and bitness byte size
 * according to official Android NDK jni.h specifications.
 */
export function mapJniDescriptorToCType(
	descriptor: string,
	bitness: 32 | 64 = 64,
): { cType: string; byteSize: number; isPointer: boolean; isJniObject: boolean } {
	const pointerSize = bitness === 32 ? 4 : 8;

	// Array types
	if (descriptor.startsWith("[")) {
		if (descriptor.length === 2) {
			switch (descriptor[1]) {
				case "Z":
					return { cType: "jbooleanArray", byteSize: pointerSize, isPointer: true, isJniObject: true };
				case "B":
					return { cType: "jbyteArray", byteSize: pointerSize, isPointer: true, isJniObject: true };
				case "C":
					return { cType: "jcharArray", byteSize: pointerSize, isPointer: true, isJniObject: true };
				case "S":
					return { cType: "jshortArray", byteSize: pointerSize, isPointer: true, isJniObject: true };
				case "I":
					return { cType: "jintArray", byteSize: pointerSize, isPointer: true, isJniObject: true };
				case "J":
					return { cType: "jlongArray", byteSize: pointerSize, isPointer: true, isJniObject: true };
				case "F":
					return { cType: "jfloatArray", byteSize: pointerSize, isPointer: true, isJniObject: true };
				case "D":
					return { cType: "jdoubleArray", byteSize: pointerSize, isPointer: true, isJniObject: true };
			}
		}
		// Multi-dimensional array or Object array
		return { cType: "jobjectArray", byteSize: pointerSize, isPointer: true, isJniObject: true };
	}

	// Class types
	if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
		const internalName = descriptor.slice(1, -1);
		if (internalName === "java/lang/String") {
			return { cType: "jstring", byteSize: pointerSize, isPointer: true, isJniObject: true };
		}
		if (internalName === "java/lang/Class") {
			return { cType: "jclass", byteSize: pointerSize, isPointer: true, isJniObject: true };
		}
		if (internalName === "java/lang/Throwable") {
			return { cType: "jthrowable", byteSize: pointerSize, isPointer: true, isJniObject: true };
		}
		return { cType: "jobject", byteSize: pointerSize, isPointer: true, isJniObject: true };
	}

	// Primitive types
	switch (descriptor) {
		case "Z":
			return { cType: "jboolean", byteSize: 1, isPointer: false, isJniObject: false };
		case "B":
			return { cType: "jbyte", byteSize: 1, isPointer: false, isJniObject: false };
		case "C":
			return { cType: "jchar", byteSize: 2, isPointer: false, isJniObject: false };
		case "S":
			return { cType: "jshort", byteSize: 2, isPointer: false, isJniObject: false };
		case "I":
			return { cType: "jint", byteSize: 4, isPointer: false, isJniObject: false };
		case "J":
			return { cType: "jlong", byteSize: 8, isPointer: false, isJniObject: false };
		case "F":
			return { cType: "jfloat", byteSize: 4, isPointer: false, isJniObject: false };
		case "D":
			return { cType: "jdouble", byteSize: 8, isPointer: false, isJniObject: false };
		case "V":
			return { cType: "void", byteSize: 0, isPointer: false, isJniObject: false };
		default:
			throw new ToolError(`Unrecognized JNI type descriptor: '${descriptor}'`);
	}
}

/**
 * Parse a full JNI method signature (e.g. "(ILjava/lang/String;[B)Z") into structured types
 * including implicit JNIEnv* and jobject/jclass parameters.
 */
export function parseJniMethodSignature(
	signature: string,
	options: { bitness?: 32 | 64; isStatic?: boolean } = {},
): ParsedJniPrototype {
	const bitness = options.bitness ?? 64;
	const pointerSize = bitness === 32 ? 4 : 8;

	if (!signature.startsWith("(") || !signature.includes(")")) {
		throw new ToolError(`Malformed JNI signature '${signature}': missing parentheses`);
	}

	const closeParenIndex = signature.indexOf(")");
	const paramSection = signature.slice(1, closeParenIndex);
	const returnSection = signature.slice(closeParenIndex + 1);

	// 1. Build initial standard JNI parameters
	const parameters: ParsedJniParam[] = [
		{
			type: "JNIEnv*",
			name: "env",
			rawDescriptor: "Lgov/nasa/ghidra/JNIEnv;",
			byteSize: pointerSize,
			isPointer: true,
			isJniObject: false,
		},
	];
	// If isStatic is undefined, do NOT guess or default to non-static; require explicit DEX flag or unverified note.
	if (options.isStatic === true) {
		parameters.push({
			type: "jclass",
			name: "clazz",
			rawDescriptor: "Ljava/lang/Class;",
			byteSize: pointerSize,
			isPointer: true,
			isJniObject: true,
		});
	} else if (options.isStatic === false) {
		parameters.push({
			type: "jobject",
			name: "thiz",
			rawDescriptor: "Ljava/lang/Object;",
			byteSize: pointerSize,
			isPointer: true,
			isJniObject: true,
		});
	} else {
		parameters.push({
			type: "jobject /* unverified receiver: ACC_STATIC required */",
			name: "receiver",
			rawDescriptor: "Ljava/lang/Object;",
			byteSize: pointerSize,
			isPointer: true,
			isJniObject: true,
		});
	}

	// 2. Parse method parameter descriptors
	let i = 0;
	let paramIndex = 0;
	while (i < paramSection.length) {
		let arrayPrefix = "";
		while (i < paramSection.length && paramSection[i] === "[") {
			arrayPrefix += "[";
			i++;
		}
		if (i >= paramSection.length) {
			throw new ToolError(`Incomplete array descriptor in signature '${signature}'`);
		}

		const char = paramSection[i];
		let descriptor = "";

		if (char === "L") {
			const semiIndex = paramSection.indexOf(";", i);
			if (semiIndex === -1) {
				throw new ToolError(`Unterminated class descriptor in signature '${signature}'`);
			}
			descriptor = arrayPrefix + paramSection.slice(i, semiIndex + 1);
			i = semiIndex + 1;
		} else {
			descriptor = arrayPrefix + char;
			i++;
		}

		const mapped = mapJniDescriptorToCType(descriptor, bitness);
		parameters.push({
			type: mapped.cType,
			name: `arg${paramIndex}`,
			rawDescriptor: descriptor,
			byteSize: mapped.byteSize,
			isPointer: mapped.isPointer,
			isJniObject: mapped.isJniObject,
		});
		paramIndex++;
	}

	// 3. Parse return descriptor
	const returnMapped = mapJniDescriptorToCType(returnSection, bitness);

	const paramListStr = parameters.map(p => `${p.type} ${p.name}`).join(", ");
	const cPrototype = `${returnMapped.cType} FUNCTION_NAME(${paramListStr})`;
	const ghidraPrototype = `${returnMapped.cType} FUNCTION_NAME(${parameters.map(p => p.type).join(", ")})`;

	return {
		returnType: returnMapped.cType,
		rawReturnDescriptor: returnSection,
		parameters,
		isStatic: options.isStatic,
		cPrototype,
		ghidraPrototype,
	};
}

/**
 * Format standard native JNI symbol name (e.g. Java_com_example_app_MainActivity_verifyLicense).
 */
export function formatJniSymbolName(className: string, methodName: string): string {
	const cleanClass = normalizeJavaClassName(className);
	// Escape JNI name: '/' -> '_', '_' -> '_1', ';' -> '_2', '[' -> '_3'
	const escapedClass = cleanClass.replace(/_/g, "_1").replace(/\//g, "_");
	const escapedMethod = methodName.replace(/_/g, "_1");
	return `Java_${escapedClass}_${escapedMethod}`;
}

/**
 * Convert dynamic runtime function pointer to static program address
 * using BigInt load bias and preserving ARM32 Thumb semantics.
 */
export function convertJniRuntimeToStaticAddress(
	options: StaticAddressConversionOptions,
): StaticAddressConversionResult {
	const runtimeBigInt = parseBigIntAddress(options.runtimeAddress, "runtimeAddress");

	const arch = options.arch?.toLowerCase() ?? "";
	const isArm32 =
		arch.includes("armv7") ||
		arch.includes("armeabi") ||
		arch === "arm" ||
		(arch.includes("arm") && !arch.includes("64"));

	// ARM32 Thumb semantics: bit 0 of runtime function pointer indicates Thumb instruction set
	const isThumb = isArm32 && (runtimeBigInt & 1n) === 1n;
	const effectiveRuntime = isThumb ? runtimeBigInt & ~1n : runtimeBigInt;

	let staticAddress: bigint;
	let rva: bigint;

	if (options.loadBias !== undefined) {
		const loadBiasBigInt = parseBigIntAddress(options.loadBias, "loadBias");
		if (effectiveRuntime < loadBiasBigInt) {
			throw new ToolError(
				`Invalid address coordinates: runtimeAddress (${formatHexAddress(effectiveRuntime)}) is less than loadBias (${formatHexAddress(loadBiasBigInt)})`,
			);
		}
		staticAddress = effectiveRuntime - loadBiasBigInt;
		rva = options.minLoadVaddr !== undefined ? staticAddress - options.minLoadVaddr : staticAddress;
	} else if (options.moduleBase !== undefined) {
		const moduleBaseBigInt = parseBigIntAddress(options.moduleBase, "moduleBase");
		if (effectiveRuntime < moduleBaseBigInt) {
			throw new ToolError(
				`Invalid address coordinates: runtimeAddress (${formatHexAddress(effectiveRuntime)}) is less than moduleBase (${formatHexAddress(moduleBaseBigInt)})`,
			);
		}
		rva = effectiveRuntime - moduleBaseBigInt;
		const staticBaseBigInt =
			options.staticImageBase !== undefined
				? parseBigIntAddress(options.staticImageBase, "staticImageBase")
				: options.minLoadVaddr !== undefined
					? options.minLoadVaddr
					: 0n;
		staticAddress = staticBaseBigInt + rva;
	} else {
		throw new ToolError("Either 'loadBias' or 'moduleBase' must be provided for address conversion");
	}
	// Verify static address falls within executable ranges if ranges provided
	if (options.executableRanges && options.executableRanges.length > 0) {
		const inRange = options.executableRanges.some(range => staticAddress >= range.start && staticAddress < range.end);
		if (!inRange) {
			const rangesStr = options.executableRanges
				.map(r => `[${formatHexAddress(r.start)} - ${formatHexAddress(r.end)}]`)
				.join(", ");
			throw new ToolError(
				`Computed static address ${formatHexAddress(staticAddress)} is outside executable ranges of the target: ${rangesStr}. ` +
					"Address rejected to prevent corrupting non-executable data or invalid memory.",
			);
		}
	}

	return {
		staticAddress,
		staticAddressHex: formatHexAddress(staticAddress),
		rva,
		rvaHex: formatHexAddress(rva),
		isThumb,
	};
}

/**
 * Generate preview items for a batch of CanonicalJniMethodRecords against a target image base.
 */
export function previewJniEnrichment(
	records: CanonicalJniMethodRecord[],
	options: {
		staticImageBase?: string | bigint;
		loadBias?: string | bigint;
		arch?: string;
		bitness?: 32 | 64;
		executableRanges?: AddressRange[];
		minLoadVaddr?: bigint;
	} = {},
): JniEnrichSummary {
	const bitness = options.bitness ?? 64;
	const items: JniEnrichPreviewItem[] = [];
	const seenStaticAddresses = new Map<string, string>();
	let eligibleCount = 0;
	let rejectedCount = 0;
	for (const rec of records) {
		try {
			if (rec.status !== "confirmed") {
				items.push({
					className: rec.className,
					methodName: rec.methodName,
					signature: rec.signature,
					isStatic: rec.isStatic ?? "unverified",
					originalAddress: rec.functionAddress,
					staticAddress: "0x0",
					isThumb: false,
					targetFunctionName: formatJniSymbolName(rec.className, rec.methodName),
					cPrototype: "",
					status: "rejected",
					reason: `Registration status is '${rec.status}', not confirmed`,
				});
				rejectedCount++;
				continue;
			}

			const targetName = formatJniSymbolName(rec.className, rec.methodName);
			const parsedSig = parseJniMethodSignature(rec.signature, {
				bitness,
				isStatic: rec.isStatic,
			});
			const cPrototype = parsedSig.cPrototype.replace("FUNCTION_NAME", targetName);

			let staticAddressHex = rec.functionAddress;
			let isThumb = rec.isThumb ?? false;

			if (options.loadBias !== undefined || rec.moduleBase) {
				const converted = convertJniRuntimeToStaticAddress({
					runtimeAddress: rec.functionAddress,
					moduleBase: rec.moduleBase,
					loadBias: options.loadBias,
					staticImageBase: options.staticImageBase,
					arch: options.arch,
					executableRanges: options.executableRanges,
					minLoadVaddr: options.minLoadVaddr,
				});
				staticAddressHex = converted.staticAddressHex;
				isThumb = converted.isThumb;
			}

			if (seenStaticAddresses.has(staticAddressHex)) {
				items.push({
					className: rec.className,
					methodName: rec.methodName,
					signature: rec.signature,
					isStatic: rec.isStatic ?? "unverified",
					originalAddress: rec.functionAddress,
					staticAddress: staticAddressHex,
					isThumb,
					targetFunctionName: targetName,
					cPrototype,
					status: "rejected",
					reason: `Native function address ${staticAddressHex} is shared with '${seenStaticAddresses.get(staticAddressHex)}'; disambiguation required to select single prototype in Ghidra`,
				});
				rejectedCount++;
			} else {
				seenStaticAddresses.set(staticAddressHex, `${rec.className}->${rec.methodName}`);
				items.push({
					className: rec.className,
					methodName: rec.methodName,
					signature: rec.signature,
					isStatic: rec.isStatic ?? "unverified",
					originalAddress: rec.functionAddress,
					staticAddress: staticAddressHex,
					isThumb,
					targetFunctionName: targetName,
					cPrototype,
					status: "eligible",
				});
				eligibleCount++;
			}
		} catch (err) {
			items.push({
				className: rec.className,
				methodName: rec.methodName,
				signature: rec.signature,
				isStatic: rec.isStatic ?? "unverified",
				originalAddress: rec.functionAddress,
				staticAddress: "0x0",
				isThumb: false,
				targetFunctionName: formatJniSymbolName(rec.className, rec.methodName),
				cPrototype: "",
				status: "out_of_bounds",
				reason: err instanceof Error ? err.message : String(err),
			});
			rejectedCount++;
		}
	}

	return {
		total: records.length,
		eligible: eligibleCount,
		rejected: rejectedCount,
		items,
	};
}

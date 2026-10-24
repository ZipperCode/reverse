import { describe, expect, it } from "bun:test";
import {
	canonicalizeRegisterNativesEvent,
	mapJniDescriptorToCType,
	parseJniMethodSignature,
	formatJniSymbolName,
	convertJniRuntimeToStaticAddress,
	previewJniEnrichment,
	parseElfMetadataForJni,
	type CanonicalJniMethodRecord,
	type RawRegisterNativesEvent,
} from "../../src/tools/jni-enrichment";

describe("jni-enrichment: Canonicalization and confirmation contract", () => {
	it("canonicalizes confirmed RegisterNatives event with retval === 0", () => {
		const rawEvent: RawRegisterNativesEvent = {
			event: "jni_register_natives",
			status: "confirmed",
			retval: 0,
			class: "com.example.app.SecurityBridge",
			methods: [
				{
					name: "computeDigest",
					signature: "(Ljava/lang/String;[B)Z",
					fnPtr: "0x7f002000",
					module: "libsec.so",
					base: "0x7f000000",
					offset: "0x2000",
				},
			],
			source: "frida",
			sampleSha256: "47c9f80ffbf7ee39da8dad759dc70aafdaab17e972bb8e849354de18cc8cf344",
		};

		const records = canonicalizeRegisterNativesEvent(rawEvent, {
			expectedSha256: "47c9f80ffbf7ee39da8dad759dc70aafdaab17e972bb8e849354de18cc8cf344",
		});

		expect(records.length).toBe(1);
		expect(records[0].className).toBe("com/example/app/SecurityBridge");
		expect(records[0].methodName).toBe("computeDigest");
		expect(records[0].signature).toBe("(Ljava/lang/String;[B)Z");
		expect(records[0].functionAddress).toBe("0x7f002000");
		expect(records[0].moduleOffset).toBe("0x2000");
		expect(records[0].status).toBe("confirmed");
		expect(records[0].evidenceVerified).toBe(true);
		expect(records[0].isThumb).toBe(false);
	});

	it("rejects unconfirmed RegisterNatives events with non-zero retval or rejected status", () => {
		const rejectedEvent: RawRegisterNativesEvent = {
			event: "jni_register_natives",
			status: "rejected",
			retval: -1,
			class: "com.example.app.SecurityBridge",
			methods: [
				{
					name: "verifyToken",
					signature: "()V",
					fnPtr: "0x7f001000",
				},
			],
		};

		expect(() => canonicalizeRegisterNativesEvent(rejectedEvent)).toThrow(
			"Cannot certify unconfirmed JNI registration",
		);

		const nonZeroRetvalEvent: RawRegisterNativesEvent = {
			event: "jni_register_natives",
			status: "confirmed",
			retval: 1, // Invalid per JNI specification (0 is success)
			class: "com.example.app.SecurityBridge",
			methods: [
				{
					name: "verifyToken",
					signature: "()V",
					fnPtr: "0x7f001000",
				},
			],
		};

		expect(() => canonicalizeRegisterNativesEvent(nonZeroRetvalEvent)).toThrow(
			"Cannot certify unconfirmed JNI registration",
		);
	});

	it("rejects events when target sample SHA-256 does not match", () => {
		const event: RawRegisterNativesEvent = {
			event: "jni_register_natives",
			status: "confirmed",
			retval: 0,
			class: "com.example.app.Native",
			methods: [
				{
					name: "init",
					signature: "()V",
					fnPtr: "0x7f001000",
				},
			],
			sampleSha256: "47c9f80ffbf7ee39da8dad759dc70aafdaab17e972bb8e849354de18cc8cf344",
		};

		expect(() =>
			canonicalizeRegisterNativesEvent(event, {
				expectedSha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			}),
		).toThrow("Target sample SHA-256 mismatch");
	});

	it("calculates moduleOffset if missing and derives isThumb for ARM32", () => {
		const rawEvent: RawRegisterNativesEvent = {
			event: "jni_register_natives",
			status: "confirmed",
			retval: 0,
			class: "com.example.app.NativeCrypto",
			methods: [
				{
					name: "decryptPayload",
					signature: "([BI)[B",
					fnPtr: "0x7f001001", // Thumb bit set (ARM32)
					base: "0x7f000000",
				},
			],
		};

		const records = canonicalizeRegisterNativesEvent(rawEvent);
		expect(records[0].moduleOffset).toBe("0x1001");
		expect(records[0].isThumb).toBe(true);
	});
	it("rejects batches mapping the same method identity to conflicting addresses", () => {
		const rawEvent: RawRegisterNativesEvent = {
			event: "jni_register_natives",
			status: "confirmed",
			retval: 0,
			class: "com.example.app.Collision",
			methods: [
				{
					name: "funcA",
					signature: "()V",
					fnPtr: "0x7f001000",
				},
				{
					name: "funcA",
					signature: "()V",
					fnPtr: "0x7f002000",
				},
			],
		};

		expect(() => canonicalizeRegisterNativesEvent(rawEvent)).toThrow("Conflicting native function address");
	});

	it("allows different methods sharing the same native address and flags alias in preview", () => {
		const rawEvent: RawRegisterNativesEvent = {
			event: "jni_register_natives",
			status: "confirmed",
			retval: 0,
			class: "com.example.app.Shared",
			methods: [
				{
					name: "nativeEncrypt",
					signature: "([B)[B",
					fnPtr: "0x7f001000",
				},
				{
					name: "nativeVerify",
					signature: "([B)Z",
					fnPtr: "0x7f001000",
				},
			],
		};

		const records = canonicalizeRegisterNativesEvent(rawEvent);
		expect(records.length).toBe(2);

		const preview = previewJniEnrichment(records, { staticImageBase: "0x0" });
		expect(preview.total).toBe(2);
		expect(preview.eligible).toBe(1);
		expect(preview.rejected).toBe(1);
		expect(preview.items[1].reason).toContain("shared");
	});

	it("does not set evidenceVerified for manual or unverified sources", () => {
		const manualEvent: RawRegisterNativesEvent = {
			event: "jni_register_natives",
			status: "confirmed",
			retval: 0,
			class: "com.example.app.Manual",
			methods: [
				{
					name: "manualFunc",
					signature: "()V",
					fnPtr: "0x7f001000",
				},
			],
			source: "manual",
			sampleSha256: "47c9f80ffbf7ee39da8dad759dc70aafdaab17e972bb8e849354de18cc8cf344",
		};

		const records = canonicalizeRegisterNativesEvent(manualEvent);
		expect(records[0].evidenceVerified).toBe(false);
	});

	it("parses ELF metadata and detects architecture and executable ranges", () => {
		// Valid ELF64 header buffer
		const elfBuf = Buffer.alloc(128);
		elfBuf[0] = 0x7f;
		elfBuf[1] = 0x45;
		elfBuf[2] = 0x4c;
		elfBuf[3] = 0x46; // ELF magic
		elfBuf[4] = 2; // ELFCLASS64
		elfBuf[5] = 1; // ELFDATA2LSB (little endian)
		elfBuf.writeUInt16LE(183, 18); // EM_AARCH64 = 183

		const meta = parseElfMetadataForJni(elfBuf);
		expect(meta.arch).toBe("aarch64");
		expect(meta.bitness).toBe(64);
		expect(meta.isArm32).toBe(false);
	});
});

describe("jni-enrichment: Official NDK types and signature parsing", () => {
	it("maps primitive JNI types correctly", () => {
		expect(mapJniDescriptorToCType("Z")).toEqual({
			cType: "jboolean",
			byteSize: 1,
			isPointer: false,
			isJniObject: false,
		});
		expect(mapJniDescriptorToCType("B")).toEqual({
			cType: "jbyte",
			byteSize: 1,
			isPointer: false,
			isJniObject: false,
		});
		expect(mapJniDescriptorToCType("C")).toEqual({
			cType: "jchar",
			byteSize: 2,
			isPointer: false,
			isJniObject: false,
		});
		expect(mapJniDescriptorToCType("S")).toEqual({
			cType: "jshort",
			byteSize: 2,
			isPointer: false,
			isJniObject: false,
		});
		expect(mapJniDescriptorToCType("I")).toEqual({
			cType: "jint",
			byteSize: 4,
			isPointer: false,
			isJniObject: false,
		});
		expect(mapJniDescriptorToCType("J")).toEqual({
			cType: "jlong",
			byteSize: 8,
			isPointer: false,
			isJniObject: false,
		});
		expect(mapJniDescriptorToCType("F")).toEqual({
			cType: "jfloat",
			byteSize: 4,
			isPointer: false,
			isJniObject: false,
		});
		expect(mapJniDescriptorToCType("D")).toEqual({
			cType: "jdouble",
			byteSize: 8,
			isPointer: false,
			isJniObject: false,
		});
		expect(mapJniDescriptorToCType("V")).toEqual({
			cType: "void",
			byteSize: 0,
			isPointer: false,
			isJniObject: false,
		});
	});

	it("preserves pointer-sized types across 32-bit and 64-bit architectures", () => {
		const str32 = mapJniDescriptorToCType("Ljava/lang/String;", 32);
		expect(str32.cType).toBe("jstring");
		expect(str32.byteSize).toBe(4);
		expect(str32.isPointer).toBe(true);

		const str64 = mapJniDescriptorToCType("Ljava/lang/String;", 64);
		expect(str64.cType).toBe("jstring");
		expect(str64.byteSize).toBe(8);
		expect(str64.isPointer).toBe(true);

		const arr32 = mapJniDescriptorToCType("[B", 32);
		expect(arr32.cType).toBe("jbyteArray");
		expect(arr32.byteSize).toBe(4);

		const arr64 = mapJniDescriptorToCType("[B", 64);
		expect(arr64.cType).toBe("jbyteArray");
		expect(arr64.byteSize).toBe(8);
	});

	it("parses full method signature with explicit DEX static declaration", () => {
		const staticParsed = parseJniMethodSignature("(ILjava/lang/String;[B)Z", {
			bitness: 64,
			isStatic: true,
		});

		expect(staticParsed.returnType).toBe("jboolean");
		expect(staticParsed.parameters.length).toBe(5);
		expect(staticParsed.parameters[0].type).toBe("JNIEnv*");
		expect(staticParsed.parameters[1].type).toBe("jclass");
		expect(staticParsed.parameters[1].name).toBe("clazz");
		expect(staticParsed.parameters[2].type).toBe("jint");
		expect(staticParsed.parameters[3].type).toBe("jstring");
		expect(staticParsed.parameters[4].type).toBe("jbyteArray");

		expect(staticParsed.cPrototype).toBe(
			"jboolean FUNCTION_NAME(JNIEnv* env, jclass clazz, jint arg0, jstring arg1, jbyteArray arg2)",
		);
	});

	it("parses full method signature with explicit virtual declaration and unverified note", () => {
		const virtualParsed = parseJniMethodSignature("()V", {
			bitness: 64,
			isStatic: false,
		});
		expect(virtualParsed.parameters[1].type).toBe("jobject");
		expect(virtualParsed.parameters[1].name).toBe("thiz");

		const unverifiedParsed = parseJniMethodSignature("()V", {
			bitness: 64,
			isStatic: undefined,
		});
		expect(unverifiedParsed.parameters[1].type).toContain("unverified receiver");
	});

	it("formats standard JNI symbol names according to JNI specification", () => {
		expect(formatJniSymbolName("com/example/app/MainActivity", "verifyLicense")).toBe(
			"Java_com_example_app_MainActivity_verifyLicense",
		);
		expect(formatJniSymbolName("com.example.pkg_sub.Test_Class", "check_value")).toBe(
			"Java_com_example_pkg_1sub_Test_1Class_check_1value",
		);
	});
});

describe("jni-enrichment: Address conversion, Thumb semantics, and bounds validation", () => {
	it("converts runtime address with load bias and clears ARM32 Thumb bit", () => {
		const res = convertJniRuntimeToStaticAddress({
			runtimeAddress: "0x7f001001",
			moduleBase: "0x7f000000",
			staticImageBase: "0x10000",
			arch: "armeabi-v7a",
		});

		expect(res.isThumb).toBe(true);
		expect(res.rvaHex).toBe("0x1000"); // 0x7f001001 & ~1 - 0x7f000000 = 0x1000
		expect(res.staticAddressHex).toBe("0x11000"); // 0x10000 + 0x1000
	});

	it("does not clear bit 0 on 64-bit architectures", () => {
		const res = convertJniRuntimeToStaticAddress({
			runtimeAddress: "0x7f001001",
			moduleBase: "0x7f000000",
			staticImageBase: "0x100000",
			arch: "aarch64",
		});

		expect(res.isThumb).toBe(false);
		expect(res.rvaHex).toBe("0x1001");
		expect(res.staticAddressHex).toBe("0x101001");
	});

	it("enforces executable ranges and rejects out-of-bounds addresses", () => {
		const executableRanges = [
			{ start: 0x1000n, end: 0x2000n },
			{ start: 0x5000n, end: 0x6000n },
		];

		// Inside range: 0x0 + (0x7f001500 - 0x7f000000) = 0x1500 (within [0x1000, 0x2000])
		const valid = convertJniRuntimeToStaticAddress({
			runtimeAddress: "0x7f001500",
			moduleBase: "0x7f000000",
			staticImageBase: "0x0",
			executableRanges,
		});
		expect(valid.staticAddressHex).toBe("0x1500");

		// Outside ranges: 0x0 + (0x7f003000 - 0x7f000000) = 0x3000 (outside executable ranges)
		expect(() =>
			convertJniRuntimeToStaticAddress({
				runtimeAddress: "0x7f003000",
				moduleBase: "0x7f000000",
				staticImageBase: "0x0",
				executableRanges,
			}),
		).toThrow("outside executable ranges");
	});

	it("generates structured preview for batches of records", () => {
		const records: CanonicalJniMethodRecord[] = [
			{
				className: "com/example/Auth",
				methodName: "checkLicense",
				signature: "(Ljava/lang/String;)Z",
				moduleName: "libauth.so",
				moduleBase: "0x7f000000",
				functionAddress: "0x7f001000",
				status: "confirmed",
				source: "frida",
				isStatic: true,
			},
			{
				className: "com/example/Auth",
				methodName: "hashPassword",
				signature: "([B)[B",
				moduleName: "libauth.so",
				moduleBase: "0x7f000000",
				functionAddress: "0x7f002000",
				status: "confirmed",
				source: "frida",
				isStatic: false,
			},
		];

		const preview = previewJniEnrichment(records, {
			staticImageBase: "0x10000",
		});

		expect(preview.total).toBe(2);
		expect(preview.eligible).toBe(2);
		expect(preview.rejected).toBe(0);
		expect(preview.items[0].targetFunctionName).toBe("Java_com_example_Auth_checkLicense");
		expect(preview.items[0].staticAddress).toBe("0x11000");
		expect(preview.items[0].cPrototype).toContain("jclass clazz");
		expect(preview.items[1].cPrototype).toContain("jobject thiz");
	});
});

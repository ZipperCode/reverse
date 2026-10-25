/**
 * Regression and contract tests for DexSearchTool:
 * - Structured missing dependency contract and active fallbacks
 * - Input validation (missing target, non-existent target, non-regular files)
 * - Fallback resolution mapping for all query types
 * - Frida hook and JADX filter generation for classes, methods, and fields
 * - Rich deterministic Dalvik DEX fixture with string constants, field reads/writes, and method call xrefs
 * - Valid APK archive container generation and verification
 * - Gated real engine query execution against raw DEX and APK
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { crc32 } from "node:zlib";
import * as vm from "node:vm";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { Settings } from "../src/config/settings";
import type { ToolSession } from "../src/tools";
import {
	DexSearchTool,
	generateFridaHook,
	generateJadxFilter,
	resolveDexSearchFallback,
	type DexSearchResultItem,
} from "../src/tools/dex-search";
import { resolveProtectionTool } from "../src/extensibility/protection-toolchain";

function createMockSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: false,
		settings: Settings.isolated({}),
	} as unknown as ToolSession;
}

// ============================================================================
// Rich Deterministic DEX & APK Fixture Builder
// ============================================================================

function adler32(buf: Buffer): number {
	let a = 1;
	let b = 0;
	const MOD = 65521;
	for (let i = 0; i < buf.length; i++) {
		a = (a + buf[i]!) % MOD;
		b = (b + a) % MOD;
	}
	return ((b << 16) | a) >>> 0;
}

function uleb128(n: number): Buffer {
	const out: number[] = [];
	let val = n;
	while (true) {
		let byte = val & 0x7f;
		val >>>= 7;
		if (val !== 0) {
			byte |= 0x80;
			out.push(byte);
		} else {
			out.push(byte);
			break;
		}
	}
	return Buffer.from(out);
}

const p16 = (n: number) => {
	const b = Buffer.alloc(2);
	b.writeUInt16LE(n, 0);
	return b;
};

const p32 = (n: number) => {
	const b = Buffer.alloc(4);
	b.writeUInt32LE(n, 0);
	return b;
};

/**
 * Builds a deterministic synthetic Dalvik executable with:
 * - Class Lcom/example/AuthGate;
 * - Field `token:Ljava/lang/String;`
 * - Method `compute()I` (returns literal 2)
 * - Method `isLicensed()Z` (uses string literal "LICENSE_ACTIVE", returns literal 1)
 * - Method `verifyToken(Ljava/lang/String;)Z` (reads field `token`, calls `isLicensed()`)
 * - Method `writeToken(Ljava/lang/String;)V` (writes field `token`)
 */
export function buildRichDexFixture(): Buffer {
	const CALLER = "Lcom/example/AuthGate;";
	const OBJECT = "Ljava/lang/Object;";
	const STRING = "Ljava/lang/String;";
	const STR_LITERAL = "LICENSE_ACTIVE";

	const strings = [
		CALLER,
		OBJECT,
		STRING,
		"I",
		"V",
		"Z",
		"ZL",
		"VL",
		"compute",
		"isLicensed",
		"verifyToken",
		"writeToken",
		"token",
		STR_LITERAL,
		"AuthGate.java",
	].sort();
	const sidx: Record<string, number> = {};
	strings.forEach((s, i) => {
		sidx[s] = i;
	});

	const types = [CALLER, OBJECT, STRING, "I", "V", "Z"].sort((a, b) => sidx[a]! - sidx[b]!);
	const tidx: Record<string, number> = {};
	types.forEach((t, i) => {
		tidx[t] = i;
	});

	const protos = [
		{ shorty: "I", ret: "I", params: [] as string[] },
		{ shorty: "V", ret: "V", params: [] as string[] },
		{ shorty: "VL", ret: "V", params: [STRING] },
		{ shorty: "Z", ret: "Z", params: [] as string[] },
		{ shorty: "ZL", ret: "Z", params: [STRING] },
	].sort((a, b) => {
		if (tidx[a.ret] !== tidx[b.ret]) return tidx[a.ret]! - tidx[b.ret]!;
		return a.shorty.localeCompare(b.shorty);
	});
	const pidx = (ret: string, params: string[]) => {
		return protos.findIndex(p => p.ret === ret && p.params.join(",") === params.join(","));
	};

	const fields = [{ cls: CALLER, type: STRING, name: "token" }];

	const methods = [
		{ cls: CALLER, name: "compute", ret: "I", params: [] as string[] },
		{ cls: CALLER, name: "isLicensed", ret: "Z", params: [] as string[] },
		{ cls: CALLER, name: "verifyToken", ret: "Z", params: [STRING] },
		{ cls: CALLER, name: "writeToken", ret: "V", params: [STRING] },
	].sort((a, b) => {
		if (tidx[a.cls] !== tidx[b.cls]) return tidx[a.cls]! - tidx[b.cls]!;
		if (sidx[a.name] !== sidx[b.name]) return sidx[a.name]! - sidx[b.name]!;
		return pidx(a.ret, a.params) - pidx(b.ret, b.params);
	});
	const midx = (name: string) => methods.findIndex(m => m.name === name);

	// Instructions
	const insns_compute = [0x2012, 0x000f]; // const/4 v0, #2; return v0

	const sLitIdx = sidx[STR_LITERAL]!;
	const insns_licensed = [
		(0x00 << 8) | 0x1a, // const-string v0, STR_LITERAL
		sLitIdx,
		0x1012, // const/4 v0, #1
		0x000f, // return v0
	];

	const isLicIdx = midx("isLicensed");
	const insns_verify = [
		(0x00 << 8) | 0x62, // sget-object v0, field@0 (token)
		0x0000,
		0x0071, // invoke-static {}
		isLicIdx,
		0x0000,
		0x000a, // move-result v0
		0x000f, // return v0
	];

	const insns_write = [
		(0x01 << 8) | 0x69, // sput-object v1, field@0 (token, parameter p0 in v1)
		0x0000,
		0x000e, // return-void
	];

	function makeCodeItem(registers: number, insns: number[], ins_size = 0, outs_size = 0): Buffer {
		const body = Buffer.concat(insns.map(p16));
		return Buffer.concat([p16(registers), p16(ins_size), p16(outs_size), p16(0), p32(0), p32(insns.length), body]);
	}

	let off = 0x70;
	const string_ids_off = off;
	off += 4 * strings.length;
	const type_ids_off = off;
	off += 4 * types.length;
	const proto_ids_off = off;
	off += 12 * protos.length;
	const field_ids_off = off;
	off += 8 * fields.length;
	const method_ids_off = off;
	off += 8 * methods.length;
	const class_defs_off = off;
	off += 32 * 1;
	const data_off = off;

	const dataParts: Buffer[] = [];
	let dataLen = 0;
	function align4() {
		while (dataLen % 4 !== 0) {
			dataParts.push(Buffer.from([0]));
			dataLen += 1;
		}
	}

	const strOffs: number[] = [];
	for (const s of strings) {
		strOffs.push(data_off + dataLen);
		const sBuf = Buffer.from(s, "utf8");
		const part = Buffer.concat([uleb128(s.length), sBuf, Buffer.from([0])]);
		dataParts.push(part);
		dataLen += part.length;
	}

	const typeListOffs: Record<number, number> = {};
	let typeListCount = 0;
	for (let i = 0; i < protos.length; i++) {
		const p = protos[i]!;
		if (p.params.length > 0) {
			align4();
			typeListOffs[i] = data_off + dataLen;
			const part = Buffer.concat([p32(p.params.length), Buffer.concat(p.params.map(t => p16(tidx[t]!)))]);
			dataParts.push(part);
			dataLen += part.length;
			typeListCount++;
		}
	}

	align4();
	const codeOff_compute = data_off + dataLen;
	const code_compute = makeCodeItem(2, insns_compute, 0, 0);
	dataParts.push(code_compute);
	dataLen += code_compute.length;

	align4();
	const codeOff_licensed = data_off + dataLen;
	const code_licensed = makeCodeItem(2, insns_licensed, 0, 0);
	dataParts.push(code_licensed);
	dataLen += code_licensed.length;

	align4();
	const codeOff_verify = data_off + dataLen;
	const code_verify = makeCodeItem(2, insns_verify, 1, 0);
	dataParts.push(code_verify);
	dataLen += code_verify.length;

	align4();
	const codeOff_write = data_off + dataLen;
	const code_write = makeCodeItem(2, insns_write, 1, 0);
	dataParts.push(code_write);
	dataLen += code_write.length;

	const codeOffsets: Record<string, number> = {
		compute: codeOff_compute,
		isLicensed: codeOff_licensed,
		verifyToken: codeOff_verify,
		writeToken: codeOff_write,
	};

	align4();
	const class_data_off = data_off + dataLen;
	const cdBufParts: Buffer[] = [
		uleb128(1), // static_fields: 1 (token)
		uleb128(0), // instance_fields: 0
		uleb128(4), // direct_methods: 4
		uleb128(0), // virtual_methods: 0
		uleb128(0),
		uleb128(0x0009), // public static field
	];
	let lastMethodIdx = 0;
	for (let i = 0; i < methods.length; i++) {
		const m = methods[i]!;
		const diff = i - lastMethodIdx;
		lastMethodIdx = i;
		cdBufParts.push(uleb128(diff), uleb128(0x0009), uleb128(codeOffsets[m.name]!));
	}
	const cdBuf = Buffer.concat(cdBufParts);
	dataParts.push(cdBuf);
	dataLen += cdBuf.length;

	// Dalvik map_list with official type codes
	align4();
	const map_off = data_off + dataLen;
	const firstTypeListOff = Object.values(typeListOffs)[0] ?? 0;
	const mapItems = [
		{ type: 0x0000, size: 1, off: 0 },
		{ type: 0x0001, size: strings.length, off: string_ids_off },
		{ type: 0x0002, size: types.length, off: type_ids_off },
		{ type: 0x0003, size: protos.length, off: proto_ids_off },
		{ type: 0x0004, size: fields.length, off: field_ids_off },
		{ type: 0x0005, size: methods.length, off: method_ids_off },
		{ type: 0x0006, size: 1, off: class_defs_off },
		{ type: 0x1001, size: typeListCount, off: firstTypeListOff },
		{ type: 0x2002, size: strings.length, off: strOffs[0]! },
		{ type: 0x2001, size: 4, off: codeOff_compute },
		{ type: 0x2000, size: 1, off: class_data_off },
		{ type: 0x1000, size: 1, off: map_off },
	].filter(m => m.size > 0 && m.off > 0);
	mapItems.sort((a, b) => a.off - b.off);
	mapItems.unshift({ type: 0x0000, size: 1, off: 0 });

	const mapBufParts: Buffer[] = [p32(mapItems.length)];
	for (const m of mapItems) {
		mapBufParts.push(p16(m.type), p16(0), p32(m.size), p32(m.off));
	}
	const mapBuf = Buffer.concat(mapBufParts);
	dataParts.push(mapBuf);
	dataLen += mapBuf.length;

	const totalSize = data_off + dataLen;
	const stringIdsBuf = Buffer.concat(strOffs.map(p32));
	const typeIdsBuf = Buffer.concat(types.map(t => p32(sidx[t]!)));
	const protoIdsBuf = Buffer.concat(
		protos.map((p, i) => {
			return Buffer.concat([p32(sidx[p.shorty]!), p32(tidx[p.ret]!), p32(typeListOffs[i] ?? 0)]);
		}),
	);
	const fieldIdsBuf = Buffer.concat(
		fields.map(f => {
			return Buffer.concat([p16(tidx[f.cls]!), p16(tidx[f.type]!), p32(sidx[f.name]!)]);
		}),
	);
	const methodIdsBuf = Buffer.concat(
		methods.map(m => {
			return Buffer.concat([p16(tidx[m.cls]!), p16(pidx(m.ret, m.params)), p32(sidx[m.name]!)]);
		}),
	);
	const classDefBuf = Buffer.concat([
		p32(tidx[CALLER]!),
		p32(0x0001), // public
		p32(tidx[OBJECT]!),
		p32(0),
		p32(sidx["AuthGate.java"]!),
		p32(0),
		p32(class_data_off),
		p32(0),
	]);

	const dataSection = Buffer.concat(dataParts);

	const header = Buffer.alloc(0x70);
	header.write("dex\n035\0", 0, 8, "ascii");
	header.writeUInt32LE(totalSize, 32);
	header.writeUInt32LE(0x70, 36);
	header.writeUInt32LE(0x12345678, 40);
	header.writeUInt32LE(0, 44);
	header.writeUInt32LE(0, 48);
	header.writeUInt32LE(map_off, 52);
	header.writeUInt32LE(strings.length, 56);
	header.writeUInt32LE(string_ids_off, 60);
	header.writeUInt32LE(types.length, 64);
	header.writeUInt32LE(type_ids_off, 68);
	header.writeUInt32LE(protos.length, 72);
	header.writeUInt32LE(proto_ids_off, 76);
	header.writeUInt32LE(fields.length, 80);
	header.writeUInt32LE(field_ids_off, 84);
	header.writeUInt32LE(methods.length, 88);
	header.writeUInt32LE(method_ids_off, 92);
	header.writeUInt32LE(1, 96);
	header.writeUInt32LE(class_defs_off, 100);
	header.writeUInt32LE(dataLen, 104);
	header.writeUInt32LE(data_off, 108);

	const fullWithoutSign = Buffer.concat([
		header,
		stringIdsBuf,
		typeIdsBuf,
		protoIdsBuf,
		fieldIdsBuf,
		methodIdsBuf,
		classDefBuf,
		dataSection,
	]);

	const sha1 = crypto.createHash("sha1").update(fullWithoutSign.subarray(32)).digest();
	sha1.copy(fullWithoutSign, 12);

	const checksum = adler32(fullWithoutSign.subarray(12));
	fullWithoutSign.writeUInt32LE(checksum, 8);

	return fullWithoutSign;
}

/**
 * Packages a raw DEX buffer into an uncompressed valid ZIP APK container with `classes.dex`.
 */
export function buildApkFixture(dexContent: Buffer): Buffer {
	const filename = "classes.dex";
	const fnBuf = Buffer.from(filename, "utf8");
	const crc = crc32(dexContent);

	const lh = Buffer.alloc(30);
	lh.writeUInt32LE(0x04034b50, 0);
	lh.writeUInt16LE(20, 4);
	lh.writeUInt16LE(0, 6);
	lh.writeUInt16LE(0, 8); // Stored
	lh.writeUInt16LE(0, 10);
	lh.writeUInt16LE(0, 12);
	lh.writeUInt32LE(crc, 14);
	lh.writeUInt32LE(dexContent.length, 18);
	lh.writeUInt32LE(dexContent.length, 22);
	lh.writeUInt16LE(fnBuf.length, 26);
	lh.writeUInt16LE(0, 28);
	const local = Buffer.concat([lh, fnBuf, dexContent]);

	const cd = Buffer.alloc(46);
	cd.writeUInt32LE(0x02014b50, 0);
	cd.writeUInt16LE(20, 4);
	cd.writeUInt16LE(20, 6);
	cd.writeUInt16LE(0, 8);
	cd.writeUInt16LE(0, 10);
	cd.writeUInt16LE(0, 12);
	cd.writeUInt16LE(0, 14);
	cd.writeUInt32LE(crc, 16);
	cd.writeUInt32LE(dexContent.length, 20);
	cd.writeUInt32LE(dexContent.length, 24);
	cd.writeUInt16LE(fnBuf.length, 28);
	cd.writeUInt16LE(0, 30);
	cd.writeUInt16LE(0, 32);
	cd.writeUInt16LE(0, 34);
	cd.writeUInt16LE(0, 36);
	cd.writeUInt32LE(0, 38);
	cd.writeUInt32LE(0, 42);
	const cdFull = Buffer.concat([cd, fnBuf]);

	const eocd = Buffer.alloc(22);
	eocd.writeUInt32LE(0x06054b50, 0);
	eocd.writeUInt16LE(0, 4);
	eocd.writeUInt16LE(0, 6);
	eocd.writeUInt16LE(1, 8);
	eocd.writeUInt16LE(1, 10);
	eocd.writeUInt32LE(cdFull.length, 12);
	eocd.writeUInt32LE(local.length, 16);
	eocd.writeUInt16LE(0, 20);

	return Buffer.concat([local, cdFull, eocd]);
}

// ============================================================================
// Tests
// ============================================================================

describe("DexSearchTool", () => {
	let tempDir: string;
	let session: ToolSession;
	let dexFixturePath: string;
	let apkFixturePath: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "dexsearch-test-"));
		session = createMockSession(tempDir);

		// Stage rich synthetic DEX fixture (with strings, fields, calls)
		const dexBuffer = buildRichDexFixture();
		dexFixturePath = path.join(tempDir, "classes.dex");
		await fs.promises.writeFile(dexFixturePath, dexBuffer);

		// Stage APK fixture
		const apkBuffer = buildApkFixture(dexBuffer);
		apkFixturePath = path.join(tempDir, "app.apk");
		await fs.promises.writeFile(apkFixturePath, apkBuffer);
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {
			// Ignore cleanup errors
		}
	});

	// ========================================================================
	// 1. Missing Dependency Contract
	// ========================================================================

	it("returns structured missing dependency notice when dexkit runtime is absent", async () => {
		const emptyAgentDir = path.join(tempDir, "empty-agent");
		await fs.promises.mkdir(emptyAgentDir, { recursive: true });

		const tool = new DexSearchTool(session, {
			agentDir: emptyAgentDir,
		});

		const res = await tool.execute("call-1", {
			target: dexFixturePath,
			type: "method",
			name: "isLicensed",
		});

		expect(res.details).toBeDefined();
		if (!res.details) {
			throw new Error("Expected res.details to be defined");
		}
		expect(res.details.status).toBe("missing_dependency");
		expect(res.details.executed).toBe(false);
		expect(res.details.setupCommand).toBe("reverse setup reverse dexkit --execute");
		expect(res.details.fallback).toBeDefined();
		expect(res.details.fallback?.primary).toBe("dex_search");
		expect(res.details.fallback?.suggestedFallback).toContain("droidasc");
	});

	it("resolves active fallbacks correctly for all query types", () => {
		const target = "test.apk";
		const classFallback = resolveDexSearchFallback("class", target, { className: "com.example.Main" });
		expect(classFallback.suggestedFallback).toContain("listclass");
		expect(classFallback.alternatives.length).toBeGreaterThan(0);

		const methodFallback = resolveDexSearchFallback("method", target, { query: "verifyLicense" });
		expect(methodFallback.suggestedFallback).toContain("findrefs");
		expect(methodFallback.suggestedFallback).toContain("method");

		const callersFallback = resolveDexSearchFallback("callers", target, { query: "checkAuth" });
		expect(callersFallback.suggestedFallback).toContain("findrefs");

		const fieldUsesFallback = resolveDexSearchFallback("field_uses", target, { query: "secretKey" });
		expect(fieldUsesFallback.suggestedFallback).toContain("field");

		const batchFallback = resolveDexSearchFallback("batch_strings", target, { usingStrings: ["auth_token"] });
		expect(batchFallback.suggestedFallback).toContain("string");
	});

	// ========================================================================
	// 2. Input Validations
	// ========================================================================

	it("throws ToolError for missing or empty target path", async () => {
		const tool = new DexSearchTool(session);
		await expect(tool.execute("call-val-1", { target: "" })).rejects.toThrow(ToolError);
		await expect(tool.execute("call-val-1", { target: "   " })).rejects.toThrow(/target is required/);
	});

	it("throws ToolError when target file does not exist", async () => {
		const tool = new DexSearchTool(session);
		await expect(tool.execute("call-val-2", { target: path.join(tempDir, "non_existent.dex") })).rejects.toThrow(
			/Target file not found/,
		);
	});

	it("throws ToolError when target is a directory rather than a file", async () => {
		const subDir = path.join(tempDir, "test-subdir");
		await fs.promises.mkdir(subDir, { recursive: true });
		const tool = new DexSearchTool(session);
		await expect(tool.execute("call-val-3", { target: subDir })).rejects.toThrow(/Not a regular file/);
	});

	// ========================================================================
	// 3. Frida & JADX Handoff Template Generation
	// ========================================================================

	function createFridaMockContext() {
		const calls: Array<{ target: string; args: unknown[] }> = [];

		class MockOverload {
			public implementation: ((...args: unknown[]) => unknown) | null = null;
			constructor(
				public name: string,
				public signatureKey: string,
				public originalFn: (...args: unknown[]) => unknown,
			) {}

			call(thisArg: unknown, ...args: unknown[]) {
				calls.push({ target: `${this.name}(${this.signatureKey})`, args });
				return this.originalFn.apply(thisArg, args);
			}

			invoke(thisArg: unknown, ...args: unknown[]) {
				if (this.implementation) {
					return this.implementation.apply(thisArg, args);
				}
				return this.call(thisArg, ...args);
			}
		}

		class MockMethodGroup {
			private overloads = new Map<string, MockOverload>();
			constructor(public name: string) {}

			register(signature: string[], fn: (...args: unknown[]) => unknown) {
				const key = signature.join(",");
				const ov = new MockOverload(this.name, key, fn);
				this.overloads.set(key, ov);
				return ov;
			}

			overload(...types: string[]) {
				const key = types.join(",");
				const ov = this.overloads.get(key);
				if (!ov) {
					throw new Error(`NoSuchMethodError: overload (${types.join(", ")}) not defined for ${this.name}`);
				}
				return ov;
			}
		}

		class MockJavaClass {
			public methods = new Map<string, MockMethodGroup>();
			public $init = new MockMethodGroup("$init");
			public fields: Record<string, { value: unknown }> = {};

			getMethod(name: string): MockMethodGroup {
				let m = this.methods.get(name);
				if (!m) {
					m = new MockMethodGroup(name);
					this.methods.set(name, m);
				}
				return m;
			}
		}

		const classRegistry = new Map<string, MockJavaClass>();

		function getOrCreateClass(name: string): MockJavaClass {
			let c = classRegistry.get(name);
			if (!c) {
				c = new MockJavaClass();
				classRegistry.set(name, c);
			}
			return c;
		}

		const sandbox = {
			console: {
				log: () => {},
				warn: () => {},
				error: () => {},
			},
			Java: {
				perform: (fn: () => void) => fn(),
				use: (className: string) => {
					const cls = getOrCreateClass(className);
					return new Proxy(cls, {
						get(target, prop: string) {
							if (prop === "$init") return target.$init;
							if (prop in target.fields) return target.fields[prop];
							return target.getMethod(prop);
						},
						set(target, prop: string, val: unknown) {
							target.fields[prop] = val as { value: unknown };
							return true;
						},
					});
				},
			},
		};

		return {
			sandbox,
			calls,
			getOrCreateClass,
			runHook: (hookScript: string) => {
				vm.runInNewContext(hookScript, sandbox);
			},
		};
	}

	it("executes generated Frida hook in VM against overloaded methods ensuring exact overload dispatch vs competing overload", () => {
		const ctx = createFridaMockContext();
		const authClass = ctx.getOrCreateClass("com.example.AuthGate");

		const targetOverload = authClass.getMethod("login").register(["java.lang.String", "int"], () => true);
		const competingOverload = authClass.getMethod("login").register(["java.lang.String"], () => false);

		const methodItem: DexSearchResultItem = {
			descriptor: "Lcom/example/AuthGate;->login(Ljava/lang/String;I)Z",
			className: "com.example.AuthGate",
			name: "login",
			paramTypes: ["java.lang.String", "int"],
			returnType: "boolean",
		};

		const hook = generateFridaHook(methodItem, "method");
		ctx.runHook(hook);

		expect(targetOverload.implementation).not.toBeNull();
		expect(competingOverload.implementation).toBeNull();

		const targetResult = targetOverload.invoke(null, "admin", 1234);
		expect(targetResult).toBe(true);
		expect(ctx.calls.some(c => c.target === "login(java.lang.String,int)")).toBe(true);

		const competingResult = competingOverload.invoke(null, "guest");
		expect(competingResult).toBe(false);
		expect(ctx.calls.some(c => c.target === "login(java.lang.String)")).toBe(true);
	});

	it("executes generated Frida hook in VM for constructors, zero-arg methods, and multidimensional arrays", () => {
		const ctx = createFridaMockContext();
		const authClass = ctx.getOrCreateClass("com.example.AuthGate");
		const cryptoClass = ctx.getOrCreateClass("com.example.Crypto");

		const ctorOverload = authClass.$init.register(["java.lang.String"], arg => `ctor:${arg}`);
		const ctorItem: DexSearchResultItem = {
			descriptor: "Lcom/example/AuthGate;-><init>(Ljava/lang/String;)V",
			className: "com.example.AuthGate",
			name: "<init>",
			isConstructor: true,
			paramTypes: ["java.lang.String"],
			returnType: "void",
		};
		ctx.runHook(generateFridaHook(ctorItem, "method"));
		expect(ctorOverload.implementation).not.toBeNull();
		ctorOverload.invoke(null, "token_xyz");
		expect(ctx.calls.some(c => c.target === "$init(java.lang.String)")).toBe(true);

		const zeroOverload = authClass.getMethod("isLicensed").register([], () => true);
		const zeroItem: DexSearchResultItem = {
			descriptor: "Lcom/example/AuthGate;->isLicensed()Z",
			className: "com.example.AuthGate",
			name: "isLicensed",
			paramTypes: [],
			returnType: "boolean",
		};
		ctx.runHook(generateFridaHook(zeroItem, "method"));
		expect(zeroOverload.implementation).not.toBeNull();
		const zeroResult = zeroOverload.invoke(null);
		expect(zeroResult).toBe(true);

		const arrayOverload = cryptoClass
			.getMethod("decrypt")
			.register(["[B", "[[I", "[Ljava.lang.String;"], (_b, _i, _s) => Buffer.from("decrypted"));
		const arrayItem: DexSearchResultItem = {
			descriptor: "Lcom/example/Crypto;->decrypt([B[[I[Ljava/lang/String;)[B",
			className: "com.example.Crypto",
			name: "decrypt",
			paramTypes: ["byte[]", "int[][]", "java.lang.String[]"],
			returnType: "byte[]",
		};
		ctx.runHook(generateFridaHook(arrayItem, "method"));
		expect(arrayOverload.implementation).not.toBeNull();
		const arrayResult = arrayOverload.invoke(null, Buffer.from("x"), [[1]], ["key"]);
		expect(arrayResult).toBeInstanceOf(Buffer);
	});

	it("executes generated Frida hook in VM for class and field targets", () => {
		const ctx = createFridaMockContext();
		const authClass = ctx.getOrCreateClass("com.example.AuthGate");
		authClass.fields.token = { value: "active_token" };

		const classItem: DexSearchResultItem = {
			descriptor: "Lcom/example/AuthGate;",
			className: "com.example.AuthGate",
		};
		expect(() => ctx.runHook(generateFridaHook(classItem, "class"))).not.toThrow();

		const fieldItem: DexSearchResultItem = {
			descriptor: "Lcom/example/AuthGate;->token:Ljava/lang/String;",
			className: "com.example.AuthGate",
			name: "token",
			type: "java.lang.String",
		};
		expect(() => ctx.runHook(generateFridaHook(fieldItem, "field"))).not.toThrow();
	});

	it("generates correct JADX navigation hints", () => {
		const methodItem: DexSearchResultItem = {
			descriptor: "Lcom/example/Auth;->login(Ljava/lang/String;)Z",
			className: "com.example.Auth",
			name: "login",
		};
		expect(generateJadxFilter(methodItem)).toBe("Lcom/example/Auth;->login(Ljava/lang/String;)Z");

		const classItem: DexSearchResultItem = {
			descriptor: "Lcom/example/Auth;",
			className: "com.example.Auth",
		};
		expect(generateJadxFilter(classItem)).toBe("Lcom/example/Auth;");
	});

	// ========================================================================
	// 4. Real Engine Execution Against Raw DEX and APK (Gated on Provisioning)
	// ========================================================================

	it("executes real engine queries against raw DEX and APK fixtures when runtime is present", async () => {
		const resolved = resolveProtectionTool("dexkit");
		const requiresLiveTest = process.env.REVERSE_TEST_DEXKIT === "1";

		if (!resolved || !resolved.installed || !resolved.canStart) {
			if (requiresLiveTest) {
				throw new Error(
					"REVERSE_TEST_DEXKIT=1 is set but DexKit engine runtime is not provisioned or canStart is false.",
				);
			}
			// When runtime not provisioned on ambient PATH, verify missing dependency behavior
			const tool = new DexSearchTool(session);
			const res = await tool.execute("call-engine-gate", {
				target: dexFixturePath,
				type: "class",
				className: "com.example.AuthGate",
			});
			expect(res.details).toBeDefined();
			if (!res.details) {
				throw new Error("Expected res.details to be defined");
			}
			expect(res.details.status).toBe("missing_dependency");
			expect(res.details.executed).toBe(false);
			return;
		}

		// When DexKit runtime is actually provisioned:
		const tool = new DexSearchTool(session);

		// 1. Raw DEX class query
		const dexRes = await tool.execute("call-live-raw-dex", {
			target: dexFixturePath,
			type: "class",
			className: "com.example.AuthGate",
		});
		expect(dexRes.details).toBeDefined();
		if (!dexRes.details) {
			throw new Error("Expected dexRes.details to be defined");
		}
		expect(dexRes.details.executed).toBe(true);
		expect(dexRes.details.status).toBe("ok");
		expect(dexRes.details.targetHash).toBeDefined();
		expect(dexRes.details.items?.[0]?.descriptor).toBe("Lcom/example/AuthGate;");

		// 2. APK package class query
		const apkRes = await tool.execute("call-live-apk", {
			target: apkFixturePath,
			type: "class",
			className: "com.example.AuthGate",
		});
		expect(apkRes.details).toBeDefined();
		if (!apkRes.details) {
			throw new Error("Expected apkRes.details to be defined");
		}
		expect(apkRes.details.executed).toBe(true);
		expect(apkRes.details.status).toBe("ok");
		expect(apkRes.details.items?.[0]?.descriptor).toBe("Lcom/example/AuthGate;");

		// 3. String literal query (positive match)
		const strRes = await tool.execute("call-live-strings-hit", {
			target: dexFixturePath,
			type: "method",
			usingStrings: ["LICENSE_ACTIVE"],
		});
		expect(strRes.details).toBeDefined();
		if (!strRes.details) {
			throw new Error("Expected strRes.details to be defined");
		}
		expect(strRes.details.executed).toBe(true);
		expect(strRes.details.status).toBe("ok");
		expect(strRes.details.items?.some(i => i.name === "isLicensed")).toBe(true);

		// 4. String literal query (negative match)
		const strMissRes = await tool.execute("call-live-strings-miss", {
			target: dexFixturePath,
			type: "method",
			usingStrings: ["NONEXISTENT_KEY_XYZ"],
		});
		expect(strMissRes.details).toBeDefined();
		if (!strMissRes.details) {
			throw new Error("Expected strMissRes.details to be defined");
		}
		expect(strMissRes.details.executed).toBe(true);
		expect(strMissRes.details.total).toBe(0);
		expect(strMissRes.details.items?.length).toBe(0);

		// 5. Numeric constant query (compute returns 2)
		const numRes = await tool.execute("call-live-num-hit", {
			target: dexFixturePath,
			type: "method",
			usingNumbers: [2],
		});
		expect(numRes.details).toBeDefined();
		if (!numRes.details) {
			throw new Error("Expected numRes.details to be defined");
		}
		expect(numRes.details.executed).toBe(true);
		expect(numRes.details.items?.some(i => i.name === "compute")).toBe(true);

		// 6. Callers query (verifyToken calls isLicensed)
		const callersRes = await tool.execute("call-live-callers", {
			target: dexFixturePath,
			type: "callers",
			method: "Lcom/example/AuthGate;->isLicensed()Z",
		});
		expect(callersRes.details).toBeDefined();
		if (!callersRes.details) {
			throw new Error("Expected callersRes.details to be defined");
		}
		expect(callersRes.details.executed).toBe(true);
		expect(callersRes.details.status).toBe("ok");
		expect(callersRes.details.items?.some(i => i.descriptor.includes("verifyToken"))).toBe(true);

		// Callers negative control: compute has no callers
		const callersMissRes = await tool.execute("call-live-callers-miss", {
			target: dexFixturePath,
			type: "callers",
			method: "Lcom/example/AuthGate;->compute()I",
		});
		expect(callersMissRes.details).toBeDefined();
		if (!callersMissRes.details) {
			throw new Error("Expected callersMissRes.details to be defined");
		}
		expect(callersMissRes.details.executed).toBe(true);
		expect(callersMissRes.details.total).toBe(0);
		expect(callersMissRes.details.items?.length).toBe(0);

		// 7. Callees query (verifyToken calls isLicensed)
		const calleesRes = await tool.execute("call-live-callees", {
			target: dexFixturePath,
			type: "callees",
			method: "Lcom/example/AuthGate;->verifyToken(Ljava/lang/String;)Z",
		});
		expect(calleesRes.details).toBeDefined();
		if (!calleesRes.details) {
			throw new Error("Expected calleesRes.details to be defined");
		}
		expect(calleesRes.details.executed).toBe(true);
		expect(calleesRes.details.status).toBe("ok");
		expect(calleesRes.details.items?.some(i => i.descriptor.includes("isLicensed"))).toBe(true);

		// 8. Field uses query (verifyToken reads token, writeToken writes token)
		const fieldUsesRes = await tool.execute("call-live-field-uses", {
			target: dexFixturePath,
			type: "field_uses",
			field: "Lcom/example/AuthGate;->token:Ljava/lang/String;",
		});
		expect(fieldUsesRes.details).toBeDefined();
		if (!fieldUsesRes.details) {
			throw new Error("Expected fieldUsesRes.details to be defined");
		}
		expect(fieldUsesRes.details.executed).toBe(true);
		expect(fieldUsesRes.details.status).toBe("ok");
		expect(fieldUsesRes.details.readers?.some(i => i.descriptor.includes("verifyToken"))).toBe(true);
		expect(fieldUsesRes.details.writers?.some(i => i.descriptor.includes("writeToken"))).toBe(true);

		// 9. Batch strings query (auth group hits isLicensed, crypto group misses)
		const batchRes = await tool.execute("call-live-batch-strings", {
			target: dexFixturePath,
			type: "batch_strings",
			groups: {
				auth: ["LICENSE_ACTIVE"],
				crypto: ["NONEXISTENT_KEY_XYZ"],
			},
		});
		expect(batchRes.details).toBeDefined();
		if (!batchRes.details) {
			throw new Error("Expected batchRes.details to be defined");
		}
		expect(batchRes.details.executed).toBe(true);
		expect(batchRes.details.status).toBe("ok");
		expect(batchRes.details.groups?.auth?.some(i => i.name === "isLicensed")).toBe(true);
		expect(batchRes.details.groups?.crypto?.length).toBe(0);
	});
});

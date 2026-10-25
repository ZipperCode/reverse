/**
 * Deterministic synthetic DEX and FART dump fixture generator for tests and smoke validation.
 */

import * as crypto from "node:crypto";

function adler32(buf: Buffer | Uint8Array): number {
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

function p16(n: number): Buffer {
	const b = Buffer.alloc(2);
	b.writeUInt16LE(n, 0);
	return b;
}

function p32(n: number): Buffer {
	const b = Buffer.alloc(4);
	b.writeUInt32LE(n, 0);
	return b;
}

export interface SyntheticDexOptions {
	/**
	 * When true, sets method `isLicensed` code_off to 0 to simulate packer stripping.
	 */
	stripLicensed?: boolean;
	/**
	 * When true, sets method `compute` code_off to 0 to simulate packer stripping.
	 */
	stripCompute?: boolean;
	/**
	 * When true and stripped, retains the physical CodeItem in the data section and map_list
	 * while setting method code_off to 0 in class_data_item (simulates packer stripping in place).
	 */
	retainPhysicalCodeItem?: boolean;
}

export function makeCodeItem(registers: number, insns: number[]): Buffer {
	const body = Buffer.concat(insns.map(p16));
	return Buffer.concat([
		p16(registers), // registers_size
		p16(0), // ins_size
		p16(0), // outs_size
		p16(0), // tries_size
		p32(0), // debug_info_off
		p32(insns.length), // insns_size
		body,
	]);
}

export const SYNTHETIC_INSNS_LICENSED = [0x0012, 0x0039, 0x0004, 0x1012, 0x000f, 0x0012, 0x000f]; // 7 units
export const SYNTHETIC_INSNS_COMPUTE = [0x2012, 0x000f]; // 2 units

/**
 * Builds a deterministic synthetic Dalvik executable (.dex) with class Lcom/example/TestGate;
 * and methods `compute()I` (idx 0) and `isLicensed()Z` (idx 1).
 */
export function buildSyntheticDexFixture(options: SyntheticDexOptions = {}): Buffer {
	const CALLER = "Lcom/example/TestGate;";
	const OBJECT = "Ljava/lang/Object;";
	const strings = [CALLER, OBJECT, "I", "V", "Z", "compute", "isLicensed"].sort();
	const sidx: Record<string, number> = {};
	strings.forEach((s, i) => {
		sidx[s] = i;
	});

	const types = [CALLER, OBJECT, "I", "V", "Z"].sort((a, b) => sidx[a]! - sidx[b]!);
	const tidx: Record<string, number> = {};
	types.forEach((t, i) => {
		tidx[t] = i;
	});

	const protos = [
		{ shorty: "I", ret: "I" },
		{ shorty: "V", ret: "V" },
		{ shorty: "Z", ret: "Z" },
	].sort((a, b) => tidx[a.ret]! - tidx[b.ret]!);
	const pidx: Record<string, number> = {};
	protos.forEach((p, i) => {
		pidx[p.ret] = i;
	});

	const methods = [
		{ cls: CALLER, name: "compute", ret: "I" },
		{ cls: CALLER, name: "isLicensed", ret: "Z" },
	].sort((a, b) => {
		if (tidx[a.cls] !== tidx[b.cls]) return tidx[a.cls]! - tidx[b.cls]!;
		if (sidx[a.name] !== sidx[b.name]) return sidx[a.name]! - sidx[b.name]!;
		return pidx[a.ret]! - pidx[b.ret]!;
	});
	const midx: Record<string, number> = {};
	methods.forEach((m, i) => {
		midx[m.name] = i;
	});

	let off = 0x70;
	const string_ids_off = off;
	off += 4 * strings.length;
	const type_ids_off = off;
	off += 4 * types.length;
	const proto_ids_off = off;
	off += 12 * protos.length;
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
		const raw = Buffer.from(s, "utf-8");
		const strData = Buffer.concat([uleb128(raw.length), raw, Buffer.from([0])]);
		dataParts.push(strData);
		dataLen += strData.length;
	}

	align4();
	let codeLicensedOff = 0;
	let physicalLicensedOff = 0;
	if (!options.stripLicensed || options.retainPhysicalCodeItem) {
		physicalLicensedOff = data_off + dataLen;
		const codeLicensedBuf = makeCodeItem(1, SYNTHETIC_INSNS_LICENSED);
		dataParts.push(codeLicensedBuf);
		dataLen += codeLicensedBuf.length;
		if (!options.stripLicensed) {
			codeLicensedOff = physicalLicensedOff;
		}
	}
	align4();
	let codeComputeOff = 0;
	if (!options.stripCompute) {
		codeComputeOff = data_off + dataLen;
		const codeComputeBuf = makeCodeItem(1, SYNTHETIC_INSNS_COMPUTE);
		dataParts.push(codeComputeBuf);
		dataLen += codeComputeBuf.length;
	}

	align4();
	const classDataOff = data_off + dataLen;
	const classDataEntries = [
		{ midx: midx["compute"]!, acc: 0x0009, codeOff: codeComputeOff },
		{ midx: midx["isLicensed"]!, acc: 0x0009, codeOff: codeLicensedOff },
	].sort((a, b) => a.midx - b.midx);

	let cdBuf = Buffer.concat([
		uleb128(0), // static fields
		uleb128(0), // instance fields
		uleb128(classDataEntries.length), // direct methods
		uleb128(0), // virtual methods
	]);
	let lastMidx = 0;
	for (const entry of classDataEntries) {
		cdBuf = Buffer.concat([cdBuf, uleb128(entry.midx - lastMidx), uleb128(entry.acc), uleb128(entry.codeOff)]);
		lastMidx = entry.midx;
	}
	dataParts.push(cdBuf);
	dataLen += cdBuf.length;

	align4();
	const mapOff = data_off + dataLen;
	const mapItems = [
		{ type: 0x0000, size: 1, offset: 0 },
		{ type: 0x0001, size: strings.length, offset: string_ids_off },
		{ type: 0x0002, size: types.length, offset: type_ids_off },
		{ type: 0x0003, size: protos.length, offset: proto_ids_off },
		{ type: 0x0005, size: methods.length, offset: method_ids_off },
		{ type: 0x0006, size: 1, offset: class_defs_off },
		{ type: 0x2002, size: strings.length, offset: strOffs[0]! },
		{ type: 0x2000, size: 1, offset: classDataOff },
		{ type: 0x1000, size: 1, offset: mapOff },
	];
	const firstCodeOff = [physicalLicensedOff, codeComputeOff].filter(o => o > 0).sort((a, b) => a - b)[0];
	const activeCodeCount = (physicalLicensedOff > 0 ? 1 : 0) + (codeComputeOff > 0 ? 1 : 0);
	if (firstCodeOff && activeCodeCount > 0) {
		mapItems.push({ type: 0x2001, size: activeCodeCount, offset: firstCodeOff });
	}
	mapItems.sort((a, b) => a.offset - b.offset);

	let mapListBuf = p32(mapItems.length);
	for (const item of mapItems) {
		mapListBuf = Buffer.concat([mapListBuf, p16(item.type), p16(0), p32(item.size), p32(item.offset)]);
	}
	dataParts.push(mapListBuf);
	dataLen += mapListBuf.length;

	const stringIdsBuf = Buffer.concat(strOffs.map(p32));
	const typeIdsBuf = Buffer.concat(types.map(t => p32(sidx[t]!)));
	const protoIdsBuf = Buffer.concat(protos.map(p => Buffer.concat([p32(sidx[p.shorty]!), p32(tidx[p.ret]!), p32(0)])));
	const methodIdsBuf = Buffer.concat(
		methods.map(m => Buffer.concat([p16(tidx[m.cls]!), p16(pidx[m.ret]!), p32(sidx[m.name]!)])),
	);

	const classDefBuf = Buffer.concat([
		p32(tidx[CALLER]!),
		p32(0x0001), // public
		p32(tidx[OBJECT]!),
		p32(0),
		p32(0xffffffff),
		p32(0),
		p32(classDataOff),
		p32(0),
	]);

	const dataSection = Buffer.concat(dataParts);
	const fileSize = data_off + dataSection.length;

	const headerBuf = Buffer.alloc(0x70);
	headerBuf.write("dex\n035\0", 0, 8, "ascii");
	headerBuf.writeUInt32LE(fileSize, 0x20);
	headerBuf.writeUInt32LE(0x70, 0x24);
	headerBuf.writeUInt32LE(0x12345678, 0x28); // endian_tag
	headerBuf.writeUInt32LE(mapOff, 0x34);
	headerBuf.writeUInt32LE(strings.length, 0x38);
	headerBuf.writeUInt32LE(string_ids_off, 0x3c);
	headerBuf.writeUInt32LE(types.length, 0x40);
	headerBuf.writeUInt32LE(type_ids_off, 0x44);
	headerBuf.writeUInt32LE(protos.length, 0x48);
	headerBuf.writeUInt32LE(proto_ids_off, 0x4c);
	headerBuf.writeUInt32LE(0, 0x50);
	headerBuf.writeUInt32LE(0, 0x54);
	headerBuf.writeUInt32LE(methods.length, 0x58);
	headerBuf.writeUInt32LE(method_ids_off, 0x5c);
	headerBuf.writeUInt32LE(1, 0x60);
	headerBuf.writeUInt32LE(class_defs_off, 0x64);
	headerBuf.writeUInt32LE(dataSection.length, 0x68);
	headerBuf.writeUInt32LE(data_off, 0x6c);

	const dexBlob = Buffer.concat([
		headerBuf,
		stringIdsBuf,
		typeIdsBuf,
		protoIdsBuf,
		methodIdsBuf,
		classDefBuf,
		dataSection,
	]);

	const sha1 = crypto.createHash("sha1").update(dexBlob.subarray(32)).digest();
	sha1.copy(dexBlob, 12);

	const adler = adler32(dexBlob.subarray(12));
	dexBlob.writeUInt32LE(adler, 8);

	return dexBlob;
}

export function buildFartRecord(params: {
	name: string;
	method_idx: number;
	offset?: number;
	code_item: Buffer;
}): string {
	const b64 = params.code_item.toString("base64");
	return `{name:${params.name},method_idx:${params.method_idx},offset:${params.offset ?? 0},code_item_len:${params.code_item.length},ins:${b64}}`;
}

export function buildFartInsBinFile(
	records: Array<{
		name: string;
		method_idx: number;
		offset?: number;
		code_item: Buffer;
	}>,
): string {
	return records.map(buildFartRecord).join("\n");
}

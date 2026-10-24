/**
 * Test fixture generator script for cross-runtime testing (Flutter, React Native/Hermes, Unity IL2CPP).
 *
 * Can be imported by tests or executed via `bun run` to generate sample directories
 * and mock APKs for manual offline inventory smoke testing.
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as zlib from "node:zlib";
import { HERMES_MAGIC_BYTES, UNITY_METADATA_MAGIC, ELF_MACHINE_AARCH64 } from "../../src/tools/runtime-analyze";

export function createHermesBytecodeBuffer(
	version: number,
	sourceHashHex = "0123456789abcdef0123456789abcdef01234567",
): Buffer {
	const buf = Buffer.alloc(64, 0);
	HERMES_MAGIC_BYTES.copy(buf, 0);
	buf.writeUInt32LE(version, 8);
	const hashBuf = Buffer.from(sourceHashHex, "hex");
	hashBuf.copy(buf, 12);
	buf.writeUInt32LE(64, 32);
	return buf;
}

export function createPlainJsBundleBuffer(): Buffer {
	return Buffer.from(
		'__d(function(g,r,i,a,m,e,d){"use strict";var x=r(d[0]);console.log("App startup", x);},0,[1]);\n' +
			'__d(function(g,r,i,a,m,e,d){"use strict";m.exports={name:"SampleApp"};},1,[]);\n' +
			"require(0);\n",
		"utf8",
	);
}

export function createUnityMetadataBuffer(version: number, sanity = UNITY_METADATA_MAGIC): Buffer {
	const buf = Buffer.alloc(128, 0);
	buf.writeUInt32LE(sanity, 0);
	buf.writeInt32LE(version, 4);
	buf.writeInt32LE(16, 8);
	buf.writeInt32LE(64, 12);
	return buf;
}

export function createSyntheticElfBuffer(options: {
	machine: number;
	is64?: boolean;
	dartAot?: boolean;
	flutterEngine?: boolean;
	il2cpp?: boolean;
	snapshotHash?: string;
	dartVersion?: string;
}): Buffer {
	const buf = Buffer.alloc(512, 0);
	buf[0] = 0x7f;
	buf[1] = 0x45;
	buf[2] = 0x4c;
	buf[3] = 0x46;
	buf[4] = options.is64 !== false ? 2 : 1;
	buf[5] = 1;
	buf[6] = 1;
	buf.writeUInt16LE(2, 16);
	buf.writeUInt16LE(options.machine, 18);

	let markerStr = "ELF_BODY_DATA:";
	if (options.dartAot) {
		markerStr += " _kDartVmSnapshotData _kDartVmSnapshotInstructions _kDartIsolateSnapshotInstructions";
	}
	if (options.flutterEngine) {
		markerStr += " FlutterEngine Dart_Initialize io.flutter";
	}
	if (options.il2cpp) {
		markerStr += " il2cpp_init il2cpp_runtime_invoke Il2CppCodeGen";
	}
	if (options.snapshotHash) {
		markerStr += ` Snapshot: ${options.snapshotHash} snapshot_hash\0${options.snapshotHash}`;
	}
	if (options.dartVersion) {
		markerStr += ` \0${options.dartVersion} (stable)\0`;
	}

	Buffer.from(markerStr, "latin1").copy(buf, 64);
	return buf;
}

function crc32(buf: Buffer): number {
	let c = 0xffffffff;
	for (let i = 0; i < buf.length; i++) {
		c = (c >>> 8) ^ CRC_TABLE[(c ^ buf[i]!) & 0xff]!;
	}
	return (c ^ 0xffffffff) >>> 0;
}

const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
	let c = i;
	for (let k = 0; k < 8; k++) {
		c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
	}
	CRC_TABLE[i] = c >>> 0;
}

export function createSyntheticZip(entries: Array<{ path: string; data: Buffer }>): Buffer {
	const localParts: Buffer[] = [];
	const centralParts: Buffer[] = [];
	let localOffset = 0;

	for (const entry of entries) {
		const nameBuf = Buffer.from(entry.path, "utf8");
		const raw = entry.data;
		const compressed = zlib.deflateRawSync(raw);
		const checksum = crc32(raw);

		const localHeader = Buffer.alloc(30, 0);
		localHeader.writeUInt32LE(0x04034b50, 0);
		localHeader.writeUInt16LE(20, 4);
		localHeader.writeUInt16LE(0, 6);
		localHeader.writeUInt16LE(8, 8);
		localHeader.writeUInt32LE(checksum, 14);
		localHeader.writeUInt32LE(compressed.length, 18);
		localHeader.writeUInt32LE(raw.length, 22);
		localHeader.writeUInt16LE(nameBuf.length, 26);

		localParts.push(localHeader, nameBuf, compressed);

		const centralHeader = Buffer.alloc(46, 0);
		centralHeader.writeUInt32LE(0x02014b50, 0);
		centralHeader.writeUInt16LE(20, 4);
		centralHeader.writeUInt16LE(20, 6);
		centralHeader.writeUInt16LE(0, 8);
		centralHeader.writeUInt16LE(8, 10);
		centralHeader.writeUInt32LE(checksum, 16);
		centralHeader.writeUInt32LE(compressed.length, 20);
		centralHeader.writeUInt32LE(raw.length, 24);
		centralHeader.writeUInt16LE(nameBuf.length, 28);
		centralHeader.writeUInt32LE(localOffset, 42);

		centralParts.push(centralHeader, nameBuf);
		localOffset += localHeader.length + nameBuf.length + compressed.length;
	}

	const centralDirectory = Buffer.concat(centralParts);
	const eocd = Buffer.alloc(22, 0);
	eocd.writeUInt32LE(0x06054b50, 0);
	eocd.writeUInt16LE(entries.length, 8);
	eocd.writeUInt16LE(entries.length, 10);
	eocd.writeUInt32LE(centralDirectory.length, 12);
	eocd.writeUInt32LE(localOffset, 16);

	return Buffer.concat([...localParts, centralDirectory, eocd]);
}

/** 写入样本目录以供手动离线测试 */
export async function writeSampleFixturesToDisk(targetDir: string): Promise<void> {
	await fs.mkdir(targetDir, { recursive: true });

	// 1. Hermes Bytecode sample
	await fs.writeFile(path.join(targetDir, "sample-rn-hbc.hbc"), createHermesBytecodeBuffer(74));

	// 2. Plain JS bundle sample
	await fs.writeFile(path.join(targetDir, "sample-rn-plain.js"), createPlainJsBundleBuffer());

	// 3. Unity global-metadata.dat sample
	await fs.writeFile(path.join(targetDir, "global-metadata.dat"), createUnityMetadataBuffer(24));

	// 4. Flutter arm64 libapp.so & libflutter.so sample
	const libDir = path.join(targetDir, "lib", "arm64-v8a");
	await fs.mkdir(libDir, { recursive: true });
	await fs.writeFile(
		path.join(libDir, "libapp.so"),
		createSyntheticElfBuffer({
			machine: ELF_MACHINE_AARCH64,
			dartAot: true,
			snapshotHash: "8c4749f10a8d795b59740523abcd1234",
			dartVersion: "3.2.0",
		}),
	);
	await fs.writeFile(
		path.join(libDir, "libflutter.so"),
		createSyntheticElfBuffer({
			machine: ELF_MACHINE_AARCH64,
			flutterEngine: true,
			snapshotHash: "8c4749f10a8d795b59740523abcd1234",
			dartVersion: "3.2.0",
		}),
	);

	// 5. Combined sample APK
	const apkBuf = createSyntheticZip([
		{ path: "assets/index.android.bundle", data: createHermesBytecodeBuffer(76) },
		{
			path: "lib/arm64-v8a/libapp.so",
			data: createSyntheticElfBuffer({
				machine: ELF_MACHINE_AARCH64,
				dartAot: true,
				snapshotHash: "aabbccddeeff00112233445566778899",
			}),
		},
		{
			path: "lib/arm64-v8a/libflutter.so",
			data: createSyntheticElfBuffer({ machine: ELF_MACHINE_AARCH64, flutterEngine: true }),
		},
		{
			path: "lib/arm64-v8a/libil2cpp.so",
			data: createSyntheticElfBuffer({ machine: ELF_MACHINE_AARCH64, il2cpp: true }),
		},
		{ path: "assets/bin/Data/Managed/Metadata/global-metadata.dat", data: createUnityMetadataBuffer(29) },
	]);
	await fs.writeFile(path.join(targetDir, "sample-app.apk"), apkBuf);
}

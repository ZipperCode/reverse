/**
 * Controlled runtime process module memory dumper via Frida.
 *
 * Attaches to target process, locates module, safely enumerates readable memory ranges,
 * zero-fills inaccessible memory holes to preserve virtual address mapping for reconstructors,
 * and streams bounded memory chunks to produce an immutable original dump artifact with SHA-256 provenance.
 */

import * as crypto from "node:crypto";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { defaultFridaRunner, fridaDependency, type FridaRunner } from "./frida";

export const DEFAULT_DUMP_MAX_BYTES = 64 * 1024 * 1024; // 64 MB
export const HARD_DUMP_MAX_BYTES = 256 * 1024 * 1024; // 256 MB
export const DEFAULT_CHUNK_SIZE = 64 * 1024; // 64 KB
export const MAX_CHUNK_SIZE = 1024 * 1024; // 1 MB

export interface MemoryRangeInfo {
	offset: number;
	length: number;
	protection: string;
}

export interface UnmappedGapInfo {
	offset: number;
	length: number;
}

export interface ModuleDumpMetadata {
	module: string;
	base: string;
	size: number;
	path?: string;
	totalReadable: number;
	unmappedBytes: number;
	ranges: MemoryRangeInfo[];
	unmappedGaps: UnmappedGapInfo[];
}

export interface ModuleDumpResult {
	success: boolean;
	module: string;
	baseAddress: string;
	moduleSize: number;
	totalReadable: number;
	unmappedBytes: number;
	ranges: MemoryRangeInfo[];
	unmappedGaps: UnmappedGapInfo[];
	sha256: string;
	dumpBuffer: Uint8Array;
	artifactPath?: string;
	error?: string;
}

export interface ModuleDumpOptions {
	pid: number | string;
	module: string;
	device?: string;
	usb?: boolean;
	host?: string;
	maxBytes?: number;
	chunkSize?: number;
	timeoutSeconds?: number;
	cwd: string;
	signal?: AbortSignal;
	runner?: FridaRunner;
}

/**
 * Builds Frida script that enumerates module memory, preserves virtual layout with zero-filled gaps,
 * uses modern NativePointer.readByteArray, and emits structured metadata and base64-encoded chunks over stdout.
 */
export function buildModuleDumpScript(options: { module: string; maxBytes?: number; chunkSize?: number }): string {
	const safeModule = JSON.stringify(options.module.trim());
	const maxBytes = Math.min(Math.max(options.maxBytes ?? DEFAULT_DUMP_MAX_BYTES, 1024), HARD_DUMP_MAX_BYTES);
	const chunkSize = Math.min(Math.max(options.chunkSize ?? DEFAULT_CHUNK_SIZE, 1024), MAX_CHUNK_SIZE);

	return `(function() {
try {
	var targetName = ${safeModule};
	var m = Process.findModuleByName(targetName);
	if (!m) {
		var all = Process.enumerateModules();
		for (var i = 0; i < all.length; i++) {
			if (all[i].name.toLowerCase() === targetName.toLowerCase()) {
				m = all[i];
				break;
			}
		}
	}
	if (!m) {
		console.log('__FRIDA_DUMP_ERROR__' + JSON.stringify({ error: 'module_not_found', target: targetName }) + '__FRIDA_DUMP_ERROR_END__');
		return;
	}

	var base = m.base;
	var size = m.size;
	var end = base.add(size);
	var maxAllowed = ${maxBytes};

	if (size > maxAllowed) {
		console.log('__FRIDA_DUMP_ERROR__' + JSON.stringify({
			error: 'module_exceeds_max_bytes',
			target: m.name,
			size: size,
			maxBytes: maxAllowed
		}) + '__FRIDA_DUMP_ERROR_END__');
		return;
	}

	var ranges = Process.enumerateRanges({ protection: 'r--', coalesce: false }).filter(function(r) {
		return r.base.compare(end) < 0 && r.base.add(r.size).compare(base) > 0;
	});

	// Sort ranges by base address
	ranges.sort(function(a, b) {
		return a.base.compare(b.base);
	});

	var readableList = [];
	var totalReadable = 0;
	var unmappedGaps = [];
	var unmappedBytes = 0;
	var lastEnd = base;

	for (var i = 0; i < ranges.length; i++) {
		var r = ranges[i];
		var rStart = r.base.compare(base) < 0 ? base : r.base;
		var rEnd = r.base.add(r.size).compare(end) > 0 ? end : r.base.add(r.size);

		if (rStart.compare(lastEnd) > 0) {
			var gapLen = rStart.sub(lastEnd).toInt32();
			unmappedGaps.push({ offset: lastEnd.sub(base).toInt32(), length: gapLen });
			unmappedBytes += gapLen;
		}

		var rLen = rEnd.sub(rStart).toInt32();
		var rOffset = rStart.sub(base).toInt32();
		readableList.push({ offset: rOffset, length: rLen, protection: r.protection });
		totalReadable += rLen;

		if (rEnd.compare(lastEnd) > 0) {
			lastEnd = rEnd;
		}
	}

	if (lastEnd.compare(end) < 0) {
		var trailingGap = end.sub(lastEnd).toInt32();
		unmappedGaps.push({ offset: lastEnd.sub(base).toInt32(), length: trailingGap });
		unmappedBytes += trailingGap;
	}

	console.log('__FRIDA_DUMP_META__' + JSON.stringify({
		module: m.name,
		base: m.base.toString(),
		size: m.size,
		path: m.path,
		totalReadable: totalReadable,
		unmappedBytes: unmappedBytes,
		ranges: readableList,
		unmappedGaps: unmappedGaps
	}) + '__FRIDA_DUMP_META_END__');

	var CHUNK_SIZE = ${chunkSize};
	var b64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

	for (var i = 0; i < ranges.length; i++) {
		var r = ranges[i];
		var rStart = r.base.compare(base) < 0 ? base : r.base;
		var rEnd = r.base.add(r.size).compare(end) > 0 ? end : r.base.add(r.size);
		var cur = rStart;

		while (cur.compare(rEnd) < 0) {
			var rem = rEnd.sub(cur).toInt32();
			var toRead = rem > CHUNK_SIZE ? CHUNK_SIZE : rem;
			// Modern Frida 17 NativePointer.readByteArray with legacy fallback
			var buf = (typeof cur.readByteArray === 'function') ? cur.readByteArray(toRead) : Memory.readByteArray(cur, toRead);
			var curOffset = cur.sub(base).toInt32();

			var u8 = new Uint8Array(buf);
			var b64 = '';
			for (var j = 0; j < u8.length; j += 3) {
				var b0 = u8[j];
				var b1 = j + 1 < u8.length ? u8[j + 1] : 0;
				var b2 = j + 2 < u8.length ? u8[j + 2] : 0;
				b64 += b64Chars[(b0 >> 2) & 63];
				b64 += b64Chars[((b0 & 3) << 4) | ((b1 >> 4) & 15)];
				b64 += j + 1 < u8.length ? b64Chars[((b1 & 15) << 2) | ((b2 >> 6) & 3)] : '=';
				b64 += j + 2 < u8.length ? b64Chars[b2 & 63] : '=';
			}

			console.log('__FRIDA_DUMP_CHUNK__' + curOffset + ':' + b64 + '__FRIDA_DUMP_CHUNK_END__');
			cur = cur.add(toRead);
		}
	}

	console.log('__FRIDA_DUMP_DONE__' + JSON.stringify({ success: true, base: m.base.toString(), size: m.size }) + '__FRIDA_DUMP_DONE_END__');
} catch(e) {
	console.log('__FRIDA_DUMP_ERROR__' + JSON.stringify({ error: e.message || String(e) }) + '__FRIDA_DUMP_ERROR_END__');
}
})();`;
}

/**
 * Executes memory dump via Frida CLI runner.
 */
export async function executeModuleDump(options: ModuleDumpOptions): Promise<ModuleDumpResult> {
	if (options.signal?.aborted) {
		throw new ToolError("Operation cancelled before memory dump execution");
	}

	const dep = fridaDependency();
	if (!dep.available || !dep.path) {
		throw new ToolError(
			`Frida executable not found. Memory dumping requires Frida on PATH or managed runtime. (${dep.installHint ?? "Not installed"})`,
		);
	}

	const pidStr = String(options.pid).trim();
	if (!pidStr) {
		throw new ToolError("Target PID must not be empty for memory dump");
	}

	const maxBytes = Math.min(Math.max(options.maxBytes ?? DEFAULT_DUMP_MAX_BYTES, 1024), HARD_DUMP_MAX_BYTES);
	const scriptSource = buildModuleDumpScript({
		module: options.module,
		maxBytes,
		chunkSize: options.chunkSize,
	});

	const cliArgs: string[] = [];
	if (options.usb) {
		cliArgs.push("-U");
	} else if (options.device) {
		cliArgs.push("-D", options.device.trim());
	} else if (options.host) {
		cliArgs.push("-H", options.host.trim());
	}

	cliArgs.push("-p", pidStr, "-q", "-e", scriptSource);

	const runner = options.runner ?? defaultFridaRunner;
	const timeoutMs = (options.timeoutSeconds ?? 60) * 1000;

	// Output buffer budget: base64 expansion is ~1.37x + framing markers + metadata
	const maxCaptureBytes = Math.min(Math.ceil(maxBytes * 1.45) + 1024 * 1024, 384 * 1024 * 1024);

	const runResult = await runner(dep.path, cliArgs, {
		cwd: options.cwd,
		timeoutMs,
		maxBytes: maxCaptureBytes,
		signal: options.signal,
	});

	if (runResult.timedOut) {
		throw new ToolError(`Frida memory dump execution timed out after ${options.timeoutSeconds ?? 60} seconds`);
	}

	if (runResult.truncated) {
		throw new ToolError(
			`Frida memory dump output exceeded maximum capture buffer (${maxCaptureBytes} bytes). Output was truncated before completion.`,
		);
	}

	if (runResult.exitCode !== null && runResult.exitCode !== 0) {
		throw new ToolError(
			`Frida process exited with error code ${runResult.exitCode}: ${runResult.stderr || "No stderr output"}`,
		);
	}

	const stdoutText = new TextDecoder().decode(runResult.stdout);

	// Line-by-line processing of output to prevent quadratic string allocations
	let meta: ModuleDumpMetadata | null = null;
	let dumpBuffer: Uint8Array | null = null;
	let coveredMap: Uint8Array | null = null;
	let totalChunkBytes = 0;
	let doneReceived = false;
	let dumpError: string | null = null;

	const lines = stdoutText.split("\n");
	for (const rawLine of lines) {
		const line = rawLine.trim();
		if (!line) continue;

		if (line.includes("__FRIDA_DUMP_ERROR__")) {
			const startIdx = line.indexOf("__FRIDA_DUMP_ERROR__") + "__FRIDA_DUMP_ERROR__".length;
			const endIdx = line.indexOf("__FRIDA_DUMP_ERROR_END__", startIdx);
			const errPayload = endIdx !== -1 ? line.slice(startIdx, endIdx) : line.slice(startIdx);
			try {
				const parsed = JSON.parse(errPayload);
				if (parsed.error === "module_not_found") {
					dumpError = `Target module '${options.module}' not found in process PID ${pidStr}`;
				} else if (parsed.error === "module_exceeds_max_bytes") {
					dumpError = `Module size (${parsed.size} bytes) exceeds maximum permitted dump size (${parsed.maxBytes} bytes)`;
				} else {
					dumpError = `Frida memory dump error: ${parsed.error || errPayload}`;
				}
			} catch {
				dumpError = `Frida memory dump error: ${errPayload}`;
			}
			break;
		}

		if (line.includes("__FRIDA_DUMP_META__")) {
			const startIdx = line.indexOf("__FRIDA_DUMP_META__") + "__FRIDA_DUMP_META__".length;
			const endIdx = line.indexOf("__FRIDA_DUMP_META_END__", startIdx);
			if (endIdx !== -1) {
				try {
					meta = JSON.parse(line.slice(startIdx, endIdx));
					if (meta && (meta.size <= 0 || meta.size > maxBytes)) {
						throw new ToolError(`Invalid module size reported in metadata: ${meta.size} bytes`);
					}
					if (meta) {
						dumpBuffer = new Uint8Array(meta.size);
						coveredMap = new Uint8Array(meta.size);
					}
				} catch (e) {
					if (e instanceof ToolError) throw e;
					throw new ToolError("Failed to parse memory dump metadata emitted by Frida worker");
				}
			}
			continue;
		}

		if (line.includes("__FRIDA_DUMP_CHUNK__")) {
			if (!meta || !dumpBuffer || !coveredMap) {
				throw new ToolError("Received memory dump chunk before metadata declaration");
			}

			const startIdx = line.indexOf("__FRIDA_DUMP_CHUNK__") + "__FRIDA_DUMP_CHUNK__".length;
			const endIdx = line.indexOf("__FRIDA_DUMP_CHUNK_END__", startIdx);
			if (endIdx === -1) continue;

			const chunkContent = line.slice(startIdx, endIdx);
			const colonIdx = chunkContent.indexOf(":");
			if (colonIdx === -1) continue;

			const offset = Number.parseInt(chunkContent.slice(0, colonIdx), 10);
			if (Number.isNaN(offset) || offset < 0) {
				throw new ToolError(`Malformed chunk offset received: ${chunkContent.slice(0, colonIdx)}`);
			}

			const b64 = chunkContent.slice(colonIdx + 1);
			const chunkBuf = Buffer.from(b64, "base64");

			if (offset + chunkBuf.length > dumpBuffer.length) {
				throw new ToolError(
					`Memory dump chunk exceeds declared module bounds (offset ${offset} + ${chunkBuf.length} > ${dumpBuffer.length})`,
				);
			}

			// Verify no chunk overlap
			for (let k = 0; k < chunkBuf.length; k++) {
				if (coveredMap[offset + k] !== 0) {
					throw new ToolError(`Overlapping memory dump chunk detected at offset ${offset + k}`);
				}
				coveredMap[offset + k] = 1;
			}

			dumpBuffer.set(chunkBuf, offset);
			totalChunkBytes += chunkBuf.length;
			continue;
		}

		if (line.includes("__FRIDA_DUMP_DONE__")) {
			doneReceived = true;
			break;
		}
	}

	if (dumpError) {
		throw new ToolError(dumpError);
	}

	if (!meta || !dumpBuffer || !coveredMap) {
		throw new ToolError(
			`Failed to capture memory dump metadata. Frida output was: ${stdoutText.slice(0, 500) || runResult.stderr.slice(0, 500)}`,
		);
	}

	if (!doneReceived) {
		throw new ToolError("Memory dump stream was interrupted before completion (missing done marker)");
	}

	// Verify exact coverage of all declared readable ranges
	if (totalChunkBytes !== meta.totalReadable) {
		throw new ToolError(
			`Incomplete readable memory capture: captured ${totalChunkBytes} bytes, expected ${meta.totalReadable} bytes declared by runtime`,
		);
	}

	for (const r of meta.ranges) {
		for (let idx = r.offset; idx < r.offset + r.length; idx++) {
			if (coveredMap[idx] === 0) {
				throw new ToolError(
					`Missing memory byte coverage in declared readable range at relative offset ${idx} (range: offset ${r.offset}, length ${r.length})`,
				);
			}
		}
	}

	// Compute SHA-256 over entire memory-aligned image
	const hasher = crypto.createHash("sha256");
	hasher.update(dumpBuffer);
	const sha256 = hasher.digest("hex");

	return {
		success: true,
		module: meta.module,
		baseAddress: meta.base,
		moduleSize: meta.size,
		totalReadable: meta.totalReadable,
		unmappedBytes: meta.unmappedBytes,
		ranges: meta.ranges,
		unmappedGaps: meta.unmappedGaps,
		sha256,
		dumpBuffer,
	};
}

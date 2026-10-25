/**
 * Runtime DEX memory extraction and post-dump structural census using external frida-dexdump.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { getAgentDir, prompt } from "@reverse/utils";
import { resolveProtectionTool } from "../extensibility/protection-toolchain";
import dexUnpackDescription from "../prompts/tools/dex-unpack.md" with { type: "text" };
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import { runSafeSubprocess } from "./vmp-common";

// ============================================================================
// Parameter Schema
// ============================================================================

export const dexUnpackSchema = type({
	action: type
		.enumerated("status", "dump")
		.describe("Operation: 'status' (readiness and backend status) or 'dump' (runtime memory DEX extraction)"),
	"backend?": type
		.enumerated("frida-dexdump")
		.describe("Runtime memory extraction engine ('frida-dexdump' via Frida, default)"),
	"device?": type("string").describe(
		"Explicit Android device serial/ID or 'local' (required for 'dump'; device-implicit dumping is disallowed)",
	),
	"serial?": type("string").describe("Alias for device"),
	"package?": type("string").describe(
		"Target application package name (e.g. 'com.example.app'; required unless pid is specified)",
	),
	"package_name?": type("string").describe("Alias for package"),
	"pid?": type("number.integer >= 1").describe("Target process ID (alternative to package name)"),
	"spawn?": type("boolean").describe(
		"Whether to spawn the target application via Frida (-f) instead of attaching to running process (default false)",
	),
	"deep_search?": type("boolean").describe(
		"Enable deep memory search mode (-d) to discover DEX structures outside registered classloaders (default false)",
	),
	"sleep?": type("number.integer >= 0").describe(
		"Waiting time in seconds for process startup in spawn mode (passed to frida-dexdump)",
	),
	"out_dir?": type("string").describe(
		"Target directory to receive extracted DEX files (defaults to private session artifact staging)",
	),
	"out?": type("string").describe("Alias for out_dir"),
	"timeout_ms?": type("number.integer >= 1000").describe(
		"Subprocess execution timeout in milliseconds (default 60000)",
	),
	"max_files?": type("number.integer >= 1").describe(
		"Maximum number of dumped DEX files to retain and census (default 50)",
	),
	"max_bytes?": type("number.integer >= 1024").describe(
		"Maximum cumulative dumped bytes allowed across all files (default 134217728 = 128 MiB)",
	),
});

export type DexUnpackParams = typeof dexUnpackSchema.infer;

// ============================================================================
// Output Types
// ============================================================================

export interface DexDumpedFileCensus {
	path: string;
	staged_path: string;
	filename: string;
	size: number;
	sha256: string;
	valid_header: boolean;
	magic: string;
	declared_file_size: number;
	file_size_matches: boolean;
	checksum_valid: boolean;
	signature_valid: boolean;
	class_defs_size: number;
	method_ids_size: number;
	methods_with_code: number;
	methods_empty_or_stripped: number;
	methods_stub: number;
	needs_repair: boolean;
}

export interface IncompleteMethodBoundary {
	total_methods: number;
	methods_with_code: number;
	methods_without_code: number;
	stub_methods: number;
	needs_repair: boolean;
	diagnosis: string;
}

export interface DexUnpackDependencyStatus {
	id: string;
	installed: boolean;
	path?: string;
	resolution: string;
}

export interface DexUnpackDetails {
	action: "status" | "dump";
	status: "ok" | "missing_dependency" | "error";
	backend: string;
	device?: string;
	package?: string;
	pid?: number;
	spawn?: boolean;
	deep_search?: boolean;
	dex_files?: DexDumpedFileCensus[];
	total_files_dumped?: number;
	total_bytes_dumped?: number;
	file_limit_reached?: boolean;
	byte_limit_reached?: boolean;
	is_partial?: boolean;
	manifest_errors?: string[];
	incomplete_method_boundary?: IncompleteMethodBoundary;
	handoff?: string[];
	dependency?: DexUnpackDependencyStatus;
	tool_info?: Record<string, unknown>;
	out_dir?: string;
	error?: string;
}

// ============================================================================
// Internal Helpers
// ============================================================================

function computeAdler32(buf: Uint8Array): number {
	let a = 1;
	let b = 0;
	const MOD = 65521;
	for (let i = 0; i < buf.length; i++) {
		a = (a + buf[i]!) % MOD;
		b = (b + a) % MOD;
	}
	return ((b << 16) | a) >>> 0;
}

/**
 * Decode unsigned LEB128 with strict Dalvik 5-byte boundary enforcement.
 * Returns [-1, pos] if malformed or exceeds 5 bytes.
 */
function readUleb128(buf: Uint8Array, offset: number): [number, number] {
	let result = 0;
	let shift = 0;
	let pos = offset;
	let count = 0;
	while (pos < buf.length && count < 5) {
		const b = buf[pos]!;
		pos++;
		count++;
		if (count === 5 && (b & 0xf0) !== 0) {
			return [-1, pos];
		}
		result |= (b & 0x7f) << shift;
		if ((b & 0x80) === 0) return [result, pos];
		shift += 7;
	}
	return [-1, pos];
}

function censusDexBuffer(filePath: string, stagedPath: string, buf: Buffer): DexDumpedFileCensus {
	const filename = path.basename(filePath);
	const sha256 = crypto.createHash("sha256").update(buf).digest("hex");

	if (buf.length < 0x70) {
		return {
			path: filePath,
			staged_path: stagedPath,
			filename,
			size: buf.length,
			sha256,
			valid_header: false,
			magic: "",
			declared_file_size: 0,
			file_size_matches: false,
			checksum_valid: false,
			signature_valid: false,
			class_defs_size: 0,
			method_ids_size: 0,
			methods_with_code: 0,
			methods_empty_or_stripped: 0,
			methods_stub: 0,
			needs_repair: false,
		};
	}

	const magic = buf.subarray(0, 8).toString("ascii").replace(/\0.*$/, "");
	const isMagicValid = magic.startsWith("dex\n");
	const declaredChecksum = buf.readUInt32LE(8);
	const computedChecksum = computeAdler32(buf.subarray(12));
	const declaredSig = buf.subarray(12, 32).toString("hex");
	const computedSig = crypto.createHash("sha1").update(buf.subarray(32)).digest("hex");
	const declaredFileSize = buf.readUInt32LE(0x20);

	const classDefsSize = buf.readUInt32LE(0x60);
	const classDefsOff = buf.readUInt32LE(0x64);
	const methodIdsSize = buf.readUInt32LE(0x58);

	let methodsWithCode = 0;
	let methodsEmptyOrStripped = 0;
	let methodsStub = 0;

	if (classDefsOff > 0 && classDefsOff < buf.length) {
		for (let i = 0; i < classDefsSize; i++) {
			const cOff = classDefsOff + i * 32;
			if (cOff + 28 > buf.length) break;
			const cdOff = buf.readUInt32LE(cOff + 24);
			if (cdOff === 0 || cdOff >= buf.length) continue;

			let p = cdOff;
			let sf: number, inf: number, dm: number, vm: number;
			[sf, p] = readUleb128(buf, p);
			if (sf < 0) break;
			[inf, p] = readUleb128(buf, p);
			if (inf < 0) break;
			[dm, p] = readUleb128(buf, p);
			if (dm < 0) break;
			[vm, p] = readUleb128(buf, p);
			if (vm < 0) break;

			// Skip fields
			let fieldsOk = true;
			for (let j = 0; j < sf + inf; j++) {
				let fDiff: number, fFlags: number;
				[fDiff, p] = readUleb128(buf, p);
				[fFlags, p] = readUleb128(buf, p);
				if (fDiff < 0 || fFlags < 0) {
					fieldsOk = false;
					break;
				}
			}
			if (!fieldsOk) break;

			// Direct methods
			let directOk = true;
			for (let j = 0; j < dm; j++) {
				let mDiff: number, mFlags: number, codeOff: number;
				[mDiff, p] = readUleb128(buf, p);
				[mFlags, p] = readUleb128(buf, p);
				[codeOff, p] = readUleb128(buf, p);
				if (mDiff < 0 || mFlags < 0 || codeOff < 0) {
					directOk = false;
					break;
				}
				if (codeOff === 0) {
					const isNativeOrAbstract = (mFlags & 0x0500) !== 0;
					if (!isNativeOrAbstract) {
						methodsEmptyOrStripped++;
					}
				} else {
					methodsWithCode++;
					if (codeOff + 16 <= buf.length) {
						const insnsSize = buf.readUInt32LE(codeOff + 12);
						if (insnsSize <= 2) methodsStub++;
					}
				}
			}
			if (!directOk) break;

			// Virtual methods
			let virtualOk = true;
			for (let j = 0; j < vm; j++) {
				let mDiff: number, mFlags: number, codeOff: number;
				[mDiff, p] = readUleb128(buf, p);
				[mFlags, p] = readUleb128(buf, p);
				[codeOff, p] = readUleb128(buf, p);
				if (mDiff < 0 || mFlags < 0 || codeOff < 0) {
					virtualOk = false;
					break;
				}
				if (codeOff === 0) {
					const isNativeOrAbstract = (mFlags & 0x0500) !== 0;
					if (!isNativeOrAbstract) {
						methodsEmptyOrStripped++;
					}
				} else {
					methodsWithCode++;
					if (codeOff + 16 <= buf.length) {
						const insnsSize = buf.readUInt32LE(codeOff + 12);
						if (insnsSize <= 2) methodsStub++;
					}
				}
			}
			if (!virtualOk) break;
		}
	}

	const isChecksumValid = declaredChecksum === computedChecksum;
	const isSignatureValid = declaredSig === computedSig;
	const isSizeMatch = declaredFileSize === buf.length;
	const isCorruptHeader = !isMagicValid || !isChecksumValid || !isSignatureValid || !isSizeMatch;

	const needsRepair = isCorruptHeader || methodsEmptyOrStripped > 0 || (methodsWithCode === 0 && methodIdsSize > 0);

	return {
		path: filePath,
		staged_path: stagedPath,
		filename,
		size: buf.length,
		sha256,
		valid_header: isMagicValid,
		magic,
		declared_file_size: declaredFileSize,
		file_size_matches: declaredFileSize === buf.length,
		checksum_valid: declaredChecksum === computedChecksum,
		signature_valid: declaredSig === computedSig,
		class_defs_size: classDefsSize,
		method_ids_size: methodIdsSize,
		methods_with_code: methodsWithCode,
		methods_empty_or_stripped: methodsEmptyOrStripped,
		methods_stub: methodsStub,
		needs_repair: needsRepair,
	};
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class DexUnpackTool implements AgentTool<typeof dexUnpackSchema, DexUnpackDetails> {
	readonly name = "dex_unpack";
	readonly label = "DEX Unpack";
	readonly summary = "Runtime memory DEX extraction via external frida-dexdump and post-dump structural census.";
	readonly description: string;
	readonly parameters = dexUnpackSchema;
	readonly strict = true;
	readonly loadMode = "discoverable" as const;

	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = String(args.action);
			if (action === "status") {
				return "read";
			}
			if (action === "dump") {
				return "exec";
			}
		}
		return "exec";
	};

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(dexUnpackDescription);
	}

	async execute(
		_toolCallId: string,
		params: DexUnpackParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DexUnpackDetails> & { details: DexUnpackDetails }> {
		throwIfAborted(signal);

		const action = params.action ?? "dump";
		const backend = params.backend ?? "frida-dexdump";

		const agentDir = getAgentDir();
		const resolvedTool = resolveProtectionTool("frida-dexdump", { agentDir });

		if (action === "status") {
			const isInstalled = resolvedTool !== null && resolvedTool.installed;
			const canStart = resolvedTool !== null && Boolean(resolvedTool.canStart);
			const isReady = isInstalled && canStart;
			const status = isReady ? "ok" : "missing_dependency";
			const lines = [
				"// frida-dexdump Toolchain Status",
				`Status: ${status}`,
				`Backend: ${backend}`,
				`Executable: ${resolvedTool?.metadata.executablePath ?? resolvedTool?.path ?? "not found"}`,
				`Version: ${resolvedTool?.version ?? "unknown"}`,
				`Can Start: ${canStart ? "yes" : "no"}`,
				`License: GPL-3.0 (external execution; no copied GPL scripts)`,
				"",
				"Note: For on-device virtual container unpacking using BlackDex (Apache-2.0),",
				'use the deobfuscate tool (`backend: "blackdex"`) which orchestrates APK installation, intent trigger, and retrieval.',
			];

			if (!isReady) {
				lines.push("");
				lines.push("### Missing Dependency / Readiness Gap");
				if (!isInstalled) {
					lines.push("frida-dexdump is not installed on PATH or in the managed environment.");
				} else if (!canStart) {
					lines.push("frida-dexdump executable is present but cannot start in the current environment.");
				}
				lines.push("Resolution: Run `reverse setup reverse frida-dexdump --execute` to install.");
			}

			const details: DexUnpackDetails = {
				action: "status",
				status,
				backend: "frida-dexdump",
				tool_info: {
					installed: isInstalled,
					canStart,
					path: resolvedTool?.path,
					executablePath: resolvedTool?.metadata.executablePath,
					version: resolvedTool?.version,
				},
				dependency: {
					id: "frida-dexdump",
					installed: isInstalled,
					path: resolvedTool?.path,
					resolution: "reverse setup reverse frida-dexdump --execute",
				},
				handoff: [
					"deobfuscate: For on-device APK virtual container dumping, invoke deobfuscate with backend='blackdex'.",
				],
			};

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details,
			};
		}

		// Action === "dump"
		// Policy enforcement: explicit device ID AND package or pid (never foreground implicit)
		const device = params.device ?? params.serial;
		if (!device || !device.trim()) {
			throw new ToolError(
				"Explicit device ID (serial or 'local') is required for dex_unpack (device-implicit dumping is disallowed to prevent accidental target ambiguity).",
			);
		}

		const targetPackage = params.package ?? params.package_name;
		const targetPid = params.pid;

		if ((!targetPackage || !targetPackage.trim()) && !targetPid) {
			throw new ToolError(
				"Explicit target package name or PID is required for dex_unpack (foreground-implicit dumping via -FU is disallowed).",
			);
		}

		// Check tool availability and readiness
		if (!resolvedTool || !resolvedTool.installed || !resolvedTool.canStart || !resolvedTool.metadata.executablePath) {
			const details: DexUnpackDetails = {
				action: "dump",
				status: "missing_dependency",
				backend: "frida-dexdump",
				device,
				package: targetPackage,
				pid: targetPid,
				dependency: {
					id: "frida-dexdump",
					installed: Boolean(resolvedTool?.installed),
					path: resolvedTool?.path,
					resolution: "reverse setup reverse frida-dexdump --execute",
				},
				error: "frida-dexdump CLI not found on host or cannot start. Install it via 'reverse setup reverse frida-dexdump --execute'.",
			};
			return {
				content: [
					{
						type: "text",
						text: `// DEX Unpack Error\nMissing dependency 'frida-dexdump'. Run 'reverse setup reverse frida-dexdump --execute' to install.`,
					},
				],
				details,
			};
		}

		const executablePath = resolvedTool.metadata.executablePath;

		// Setup isolated staging directory
		const sessionArtifact = await this.session.allocateOutputArtifact?.("dex_unpack");
		let stagingDir: string;
		if (sessionArtifact?.path) {
			stagingDir = sessionArtifact.path;
			fs.mkdirSync(stagingDir, { recursive: true });
		} else {
			const tmpParent = path.join(getAgentDir(), "tmp");
			fs.mkdirSync(tmpParent, { recursive: true });
			stagingDir = fs.mkdtempSync(path.join(tmpParent, "rev_dexdump_"));
		}

		const isSpawn = params.spawn === true;
		const isDeepSearch = params.deep_search === true;
		const timeoutMs = Math.min(300_000, Math.max(5000, params.timeout_ms ?? 60_000));
		const maxFiles = Math.min(200, Math.max(1, params.max_files ?? 50));
		const maxBytes = Math.min(512 * 1024 * 1024, Math.max(1024, params.max_bytes ?? 128 * 1024 * 1024));

		const args: string[] = [];

		// Device argument: supports "local" for local processes (-D local), "usb" (-U), or explicit serial (-D <serial>)
		const devTrim = device.trim();
		if (devTrim.toLowerCase() === "usb") {
			args.push("-U");
		} else {
			args.push("-D", devTrim);
		}

		// Target selection (spawn vs attach)
		if (isSpawn) {
			if (!targetPackage) {
				throw new ToolError("Spawn mode (spawn: true) requires an explicit package name.");
			}
			args.push("-f", targetPackage.trim());
			if (params.sleep !== undefined && params.sleep >= 0) {
				args.push("--sleep", String(params.sleep));
			}
		} else if (targetPid) {
			args.push("-p", String(targetPid));
		} else if (targetPackage) {
			args.push("-n", targetPackage.trim());
		}

		// Private staging output directory
		args.push("-o", stagingDir);

		// Deep search
		if (isDeepSearch) {
			args.push("-d");
		}

		// Active disk watchdog to abort subprocess if it exceeds file or byte limits during execution
		const internalAbort = new AbortController();
		const onParentAbort = () => internalAbort.abort();
		signal?.addEventListener("abort", onParentAbort, { once: true });

		let watchdogKilled = false;
		let watchdogReason = "";
		const watchdogInterval = setInterval(() => {
			try {
				if (!fs.existsSync(stagingDir)) return;
				let count = 0;
				let bytes = 0;
				const walkWatch = (dirPath: string) => {
					const items = fs.readdirSync(dirPath, { withFileTypes: true });
					for (const item of items) {
						const cur = path.join(dirPath, item.name);
						if (item.isDirectory()) {
							walkWatch(cur);
						} else if (item.isFile()) {
							count++;
							try {
								const st = fs.statSync(cur);
								bytes += st.size;
							} catch {}
						}
					}
				};
				walkWatch(stagingDir);

				if (count > maxFiles || bytes > maxBytes) {
					watchdogKilled = true;
					watchdogReason =
						count > maxFiles
							? `frida-dexdump exceeded file count limit (${count} > ${maxFiles}) during execution`
							: `frida-dexdump exceeded byte limit (${bytes} > ${maxBytes}) during execution`;
					internalAbort.abort();
				}
			} catch {}
		}, 150);

		// Execute frida-dexdump with verified subprocess lifecycle
		let subResult;
		try {
			subResult = await runSafeSubprocess({
				binary: executablePath,
				args,
				cwd: this.session.cwd,
				env: {
					FRIDA_DEXDUMP_MAX_FILES: String(maxFiles),
					FRIDA_DEXDUMP_MAX_BYTES: String(maxBytes),
					FRIDA_DEXDUMP_MAX_TOTAL_BYTES: String(maxBytes),
				},
				timeoutMs,
				signal: internalAbort.signal,
				maxBytes: 8 * 1024 * 1024, // 8 MiB stdout limit
			});
		} catch (err: unknown) {
			clearInterval(watchdogInterval);
			signal?.removeEventListener("abort", onParentAbort);
			if (watchdogKilled) {
				throw new ToolError(watchdogReason);
			}
			const msg = err instanceof Error ? err.message : String(err);
			throw new ToolError(`frida-dexdump execution failed: ${msg}`);
		} finally {
			clearInterval(watchdogInterval);
			signal?.removeEventListener("abort", onParentAbort);
		}

		if (watchdogKilled) {
			throw new ToolError(watchdogReason);
		}
		if (subResult.timedOut) {
			throw new ToolError(`frida-dexdump execution timed out after ${timeoutMs / 1000} seconds`);
		}
		if (subResult.killedOnOverflow) {
			throw new ToolError("frida-dexdump output exceeded stream quota (8 MiB) and was terminated");
		}
		if (subResult.exitCode !== 0) {
			const errDetail = subResult.stderr.trim() || subResult.stdout.trim() || `exit code ${subResult.exitCode}`;
			throw new ToolError(`frida-dexdump exited with error: ${errDetail}`);
		}

		// Census outputs in stagingDir with strict bound tracking
		const dumpedFiles: DexDumpedFileCensus[] = [];
		let totalDumpedBytes = 0;
		let fileLimitHit = false;
		let byteLimitHit = false;

		const walkDir = (dir: string) => {
			if (!fs.existsSync(dir)) return;
			const entries = fs.readdirSync(dir, { withFileTypes: true });
			for (const ent of entries) {
				const fullPath = path.join(dir, ent.name);
				if (ent.isDirectory()) {
					walkDir(fullPath);
				} else if (ent.isFile() && (ent.name.endsWith(".dex") || ent.name.includes("classes"))) {
					if (dumpedFiles.length >= maxFiles) {
						fileLimitHit = true;
						return;
					}
					const stat = fs.statSync(fullPath);
					if (totalDumpedBytes + stat.size > maxBytes) {
						byteLimitHit = true;
						continue;
					}
					try {
						const buf = fs.readFileSync(fullPath);
						const census = censusDexBuffer(fullPath, fullPath, buf);
						dumpedFiles.push(census);
						totalDumpedBytes += stat.size;
					} catch {
						// Skip unreadable file
					}
				}
			}
		};

		walkDir(stagingDir);

		// Inspect real controller dump_manifest.json for errors and partial classification
		let manifestErrors: string[] = [];
		let isPartial = fileLimitHit || byteLimitHit;
		const manifestPath = path.join(stagingDir, "dump_manifest.json");
		if (fs.existsSync(manifestPath)) {
			try {
				const manifestJson = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
				if (Array.isArray(manifestJson.errors) && manifestJson.errors.length > 0) {
					manifestErrors = manifestJson.errors.map(String);
					isPartial = true;
				}
				if (manifestJson.partial === true) {
					isPartial = true;
				}
			} catch {}
		}

		// Publish to requested out_dir if specified, with exclusive creation and anti-aliasing
		const rawOutDir = params.out_dir ?? params.out;
		let finalOutDir = stagingDir;

		if (rawOutDir && rawOutDir.trim()) {
			finalOutDir = resolveReadPath(rawOutDir.trim(), this.session.cwd);

			// Symlink safety check: out_dir must not resolve to stagingDir or root
			if (fs.existsSync(finalOutDir)) {
				const realOut = fs.realpathSync(finalOutDir);
				const realStaging = fs.realpathSync(stagingDir);
				if (realOut === realStaging) {
					throw new ToolError("Target out_dir cannot point to the temporary staging directory.");
				}
			} else {
				fs.mkdirSync(finalOutDir, { recursive: true });
			}

			// Copy files with collision avoidance and record published paths
			for (const df of dumpedFiles) {
				let destFilename = df.filename;
				let destPath = path.join(finalOutDir, destFilename);
				let counter = 1;
				while (fs.existsSync(destPath)) {
					const ext = path.extname(df.filename);
					const base = path.basename(df.filename, ext);
					destFilename = `${base}_${counter}${ext}`;
					destPath = path.join(finalOutDir, destFilename);
					counter++;
				}

				try {
					fs.copyFileSync(df.staged_path, destPath, fs.constants.COPYFILE_EXCL);
					df.path = destPath;
					df.filename = destFilename;
				} catch {
					// Fall back to staging path if copy encounters error
					df.path = df.staged_path;
				}
			}
		}

		// Compute aggregate method boundary
		let aggTotalMethods = 0;
		let aggWithCode = 0;
		let aggWithoutCode = 0;
		let aggStubs = 0;

		for (const df of dumpedFiles) {
			aggTotalMethods += df.method_ids_size;
			aggWithCode += df.methods_with_code;
			aggWithoutCode += df.methods_empty_or_stripped;
			aggStubs += df.methods_stub;
		}

		const overallNeedsRepair = aggWithoutCode > 0 || (aggWithCode === 0 && aggTotalMethods > 0);

		const diagnosis =
			dumpedFiles.length === 0
				? "No DEX files dumped. The process memory may not contain loaded Dalvik structures or deep-search may be needed."
				: overallNeedsRepair
					? `${aggWithoutCode} methods have empty/stripped code items (packer instruction erasure detected). Offline repair required.`
					: "All dumped DEX files possess intact code items and valid Dalvik headers.";

		const incompleteBoundary: IncompleteMethodBoundary = {
			total_methods: aggTotalMethods,
			methods_with_code: aggWithCode,
			methods_without_code: aggWithoutCode,
			stub_methods: aggStubs,
			needs_repair: overallNeedsRepair,
			diagnosis,
		};

		const handoffs: string[] = [];
		if (overallNeedsRepair) {
			handoffs.push(
				"dex_repair: Methods have stripped/empty code items. Ingest FART active call dumps (*_ins.bin) to relocate and restore code items.",
			);
		}
		handoffs.push("dex_patch: Inspect method bytecode and apply guarded instruction patches.");
		handoffs.push(
			"android_package_inspect: Inspect APK container structure, AndroidManifest components, and signatures.",
		);

		const lines = [
			"// Runtime DEX Memory Dump Report",
			`Backend: frida-dexdump (GPL-3.0)`,
			`Device: ${device}`,
			`Target: ${targetPackage ?? `PID ${targetPid}`}`,
			`Mode: ${isSpawn ? "spawn (-f)" : "attach (-n / -p)"} | Deep Search: ${isDeepSearch}`,
			`Output Directory: ${finalOutDir}`,
			`Files Dumped: ${dumpedFiles.length} (${(totalDumpedBytes / 1024 / 1024).toFixed(2)} MiB)`,
		];

		if (fileLimitHit) {
			lines.push(`[Notice] Dump reached max_files bound (${maxFiles} files). Extra files omitted.`);
		}
		if (byteLimitHit) {
			lines.push(`[Notice] Dump reached max_bytes bound (${(maxBytes / 1024 / 1024).toFixed(1)} MiB).`);
		}

		if (manifestErrors.length > 0) {
			lines.push("");
			lines.push("### Controller Diagnostics / Manifest Errors");
			for (const err of manifestErrors) {
				lines.push(`- ${err}`);
			}
		}

		lines.push("");
		lines.push("### Dumped DEX Census");

		if (dumpedFiles.length === 0) {
			lines.push("- None (no DEX files recovered from memory ranges).");
		} else {
			for (const df of dumpedFiles) {
				lines.push(`- **${df.filename}** (${df.size} bytes, sha256:${df.sha256.slice(0, 12)}...):`);
				lines.push(
					`  * Header: magic='${df.magic}', size_match=${df.file_size_matches}, checksum=${df.checksum_valid ? "VALID" : "INVALID"}, sig=${df.signature_valid ? "VALID" : "INVALID"}`,
				);
				lines.push(
					`  * Methods: ${df.method_ids_size} total, ${df.methods_with_code} with code, ${df.methods_empty_or_stripped} empty/stripped, ${df.methods_stub} stubs`,
				);
				lines.push(`  * Needs Repair: ${df.needs_repair ? "YES" : "no"}`);
			}
		}

		lines.push("");
		lines.push("### Method Body Boundary");
		lines.push(`- Total Methods: ${aggTotalMethods}`);
		lines.push(`- Methods with Code: ${aggWithCode}`);
		lines.push(`- Methods Stripped/Empty: ${aggWithoutCode}`);
		lines.push(`- Stub Methods: ${aggStubs}`);
		lines.push(`- Repair Required: ${overallNeedsRepair ? "YES" : "no"}`);
		lines.push(`- Diagnosis: ${diagnosis}`);

		lines.push("");
		lines.push("### Recommended Handoffs");
		for (const h of handoffs) {
			lines.push(`- ${h}`);
		}

		const details: DexUnpackDetails = {
			action: "dump",
			status: "ok",
			backend: "frida-dexdump",
			device,
			package: targetPackage,
			pid: targetPid,
			spawn: isSpawn,
			deep_search: isDeepSearch,
			dex_files: dumpedFiles,
			total_files_dumped: dumpedFiles.length,
			total_bytes_dumped: totalDumpedBytes,
			file_limit_reached: fileLimitHit,
			byte_limit_reached: byteLimitHit,
			is_partial: isPartial,
			manifest_errors: manifestErrors.length > 0 ? manifestErrors : undefined,
			incomplete_method_boundary: incompleteBoundary,
			handoff: handoffs,
			out_dir: finalOutDir,
		};

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details,
		};
	}
}

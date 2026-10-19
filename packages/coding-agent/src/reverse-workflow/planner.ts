import * as path from "node:path";
import { type TargetFormat, type WorkflowStepRecord, DEFAULT_MAX_ATTEMPTS, normalizeTargetFormat } from "./contracts";

/** Sniff binary header or file contents to determine target classification format. */
export function sniffTargetFormat(targetPath: string, buffer?: Uint8Array, _fileSize?: number): TargetFormat {
	const ext = path.extname(targetPath).toLowerCase();

	if (buffer && buffer.length >= 4) {
		const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

		// 1. SQLite: "SQLite format 3\0"
		if (buffer.length >= 16) {
			const sqliteMagic = "SQLite format 3\0";
			let isSqlite = true;
			for (let i = 0; i < 16; i++) {
				if (buffer[i] !== sqliteMagic.charCodeAt(i)) {
					isSqlite = false;
					break;
				}
			}
			if (isSqlite) return "SQLite";
		}

		// 2. PCAP and PCAPNG
		const magic32 = view.getUint32(0, false);
		if (
			magic32 === 0xa1b2c3d4 ||
			magic32 === 0xd4c3b2a1 ||
			magic32 === 0xa1b23c4d ||
			magic32 === 0x4d3c2ba1 ||
			magic32 === 0x0a0d0d0a
		) {
			return "PCAP";
		}

		// 3. WebAssembly: \0asm
		if (buffer[0] === 0x00 && buffer[1] === 0x61 && buffer[2] === 0x73 && buffer[3] === 0x6d) {
			return "WASM";
		}

		// 4. ELF: \x7fELF
		if (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
			return "ELF";
		}

		// 5. Mach-O: thin (32/64 bit, LE/BE) and Universal fat
		if (
			magic32 === 0xfeedface ||
			magic32 === 0xcefaedfe ||
			magic32 === 0xfeedfacf ||
			magic32 === 0xcffaedfe ||
			magic32 === 0xbebafeca ||
			magic32 === 0xcafebabf
		) {
			return "Mach-O";
		}
		if (magic32 === 0xcafebabe) {
			// Distinguish Mach-O Universal fat from Java class file (count vs major/minor)
			if (buffer.length >= 8) {
				const count = view.getUint32(4, false);
				// Mach-O fat headers have arch count 1..64; Java class major versions are >= 45 (0x002d)
				if (count > 0 && count < 64) {
					return "Mach-O";
				}
			}
		}

		// 6. PE: MZ header followed by PE signature
		if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
			if (buffer.length >= 64) {
				const peOffset = view.getUint32(0x3c, true);
				if (
					peOffset >= 64 &&
					peOffset + 4 <= buffer.length &&
					buffer[peOffset] === 0x50 &&
					buffer[peOffset + 1] === 0x45 &&
					buffer[peOffset + 2] === 0x00 &&
					buffer[peOffset + 3] === 0x00
				) {
					return "PE";
				}
			}
			// If buffer too short to reach PE header, rely on common extensions
			if (ext === ".exe" || ext === ".dll" || ext === ".sys" || ext === ".node" || ext === ".ocx") {
				return "PE";
			}
		}

		// 7. APK / DEX:
		// Dalvik DEX header: "dex\n"
		if (buffer[0] === 0x64 && buffer[1] === 0x65 && buffer[2] === 0x78 && buffer[3] === 0x0a) {
			return "APK";
		}
		// ZIP header: PK\x03\x04 or PK\x05\x06
		if (
			(buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04) ||
			(buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x05 && buffer[3] === 0x06)
		) {
			if (ext === ".apk" || ext === ".aab") {
				return "APK";
			}
			// Scan first 64KB for AndroidManifest.xml or classes.dex
			const textSample = new TextDecoder("latin1").decode(buffer.subarray(0, Math.min(buffer.length, 65536)));
			if (textSample.includes("AndroidManifest.xml") || textSample.includes("classes.dex")) {
				return "APK";
			}
		}

		// 8. JS / Hermes Bytecode:
		// Hermes HBC magic: 0xC6 0x1F 0xBC 0x03
		if (buffer[0] === 0xc6 && buffer[1] === 0x1f && buffer[2] === 0xbc && buffer[3] === 0x03) {
			return "JS";
		}

		// SourceMap JSON / JavaScript text
		if (ext === ".map" || ext === ".js" || ext === ".mjs" || ext === ".cjs" || ext === ".ts" || ext === ".tsx") {
			return "JS";
		}
	}

	// Extension-based classification fallback
	if (ext === ".exe" || ext === ".dll" || ext === ".sys" || ext === ".ocx") return "PE";
	if (ext === ".so" || ext === ".elf" || ext === ".o") return "ELF";
	if (ext === ".dylib" || ext === ".macho") return "Mach-O";
	if (ext === ".apk" || ext === ".aab" || ext === ".dex") return "APK";
	if (ext === ".js" || ext === ".mjs" || ext === ".cjs" || ext === ".map" || ext === ".bundle" || ext === ".hbc")
		return "JS";
	if (ext === ".wasm" || ext === ".wat") return "WASM";
	if (ext === ".pcap" || ext === ".pcapng" || ext === ".cap") return "PCAP";
	if (ext === ".sqlite" || ext === ".sqlite3" || ext === ".db") return "SQLite";

	return "unknown";
}

export interface PlanGenerationOptions {
	goal?: string;
	maxAttempts?: number;
	formatOverride?: string;
}

/**
 * Generate a deterministic, gate-aligned step plan for a reverse engineering target.
 * Routes PE/ELF/Mach-O/APK/JS/WASM/PCAP/SQLite to existing native tools.
 */
export function generateDeterministicPlan(
	targetPath: string,
	detectedFormat: TargetFormat,
	options: PlanGenerationOptions = {},
): { format: TargetFormat; steps: WorkflowStepRecord[] } {
	const effectiveFormat =
		normalizeTargetFormat(options.formatOverride) ?? (detectedFormat !== "unknown" ? detectedFormat : "unknown");

	const maxAttempts =
		typeof options.maxAttempts === "number" && options.maxAttempts > 0
			? Math.min(options.maxAttempts, 10)
			: DEFAULT_MAX_ATTEMPTS;

	const now = new Date().toISOString();

	let stepDefinitions: Array<{
		id: string;
		title: string;
		tool: string;
		gate: "G0" | "G1" | "G2" | "G3" | "G4";
		params_summary: Record<string, unknown>;
	}>;

	switch (effectiveFormat) {
		case "PE":
			stepDefinitions = [
				{
					id: "pe_step_1",
					title: "G0/G1: PE Binary & Entropy Triage",
					tool: "triage",
					gate: "G0",
					params_summary: { path: targetPath, strings: true, limit: 30 },
				},
				{
					id: "pe_step_2",
					title: "G1: Compiler & Runtime Metadata Check",
					tool: "binary_metadata_inspect",
					gate: "G1",
					params_summary: { path: targetPath, action: "info" },
				},
				{
					id: "pe_step_3",
					title: "G2/G3: Imports, Exports & Disassembly Analysis",
					tool: "r2_inspect",
					gate: "G2",
					params_summary: { path: targetPath, action: "functions" },
				},
				{
					id: "pe_step_4",
					title: "G4: Evidence Ledger & Hypothesis Recording",
					tool: "evidence",
					gate: "G4",
					params_summary: {
						action: "add",
						kind: "fact",
						target: targetPath,
						sourceTool: "r2_inspect",
						locator: "entrypoint",
					},
				},
			];
			break;

		case "ELF":
			stepDefinitions = [
				{
					id: "elf_step_1",
					title: "G0/G1: ELF Architecture & Section Triage",
					tool: "triage",
					gate: "G0",
					params_summary: { path: targetPath, strings: true, limit: 30 },
				},
				{
					id: "elf_step_2",
					title: "G1: Go/Rust Build & Auditable Metadata Extraction",
					tool: "binary_metadata_inspect",
					gate: "G1",
					params_summary: { path: targetPath, action: "info" },
				},
				{
					id: "elf_step_3",
					title: "G2/G3: Dynamic Symbols & Relocations Analysis",
					tool: "r2_inspect",
					gate: "G2",
					params_summary: { path: targetPath, action: "functions" },
				},
				{
					id: "elf_step_4",
					title: "G4: Evidence Ledger Findings Recording",
					tool: "evidence",
					gate: "G4",
					params_summary: {
						action: "add",
						kind: "fact",
						target: targetPath,
						sourceTool: "r2_inspect",
						locator: "main",
					},
				},
			];
			break;

		case "Mach-O":
			stepDefinitions = [
				{
					id: "macho_step_1",
					title: "G0/G1: Mach-O Slices & Load Commands Triage",
					tool: "triage",
					gate: "G0",
					params_summary: { path: targetPath, strings: true, limit: 30 },
				},
				{
					id: "macho_step_2",
					title: "G1: Binary Metadata & Toolchain Inspection",
					tool: "binary_metadata_inspect",
					gate: "G1",
					params_summary: { path: targetPath, action: "info" },
				},
				{
					id: "macho_step_3",
					title: "G2/G3: Symbols, Entrypoint & Section Disassembly",
					tool: "r2_inspect",
					gate: "G2",
					params_summary: { path: targetPath, action: "functions" },
				},
				{
					id: "macho_step_4",
					title: "G4: Architecture & Evidence Verification Recording",
					tool: "evidence",
					gate: "G4",
					params_summary: {
						action: "add",
						kind: "fact",
						target: targetPath,
						sourceTool: "r2_inspect",
						locator: "_main",
					},
				},
			];
			break;

		case "APK":
			stepDefinitions = [
				{
					id: "apk_step_1",
					title: "G0/G1: APK Container, Native Libraries & Signing Audit",
					tool: "android_package_inspect",
					gate: "G0",
					params_summary: { path: targetPath, action: "info" },
				},
				{
					id: "apk_step_2",
					title: "G1/G2: AndroidManifest Component & Permission Analysis",
					tool: "android_package_inspect",
					gate: "G1",
					params_summary: { path: targetPath, action: "manifest" },
				},
				{
					id: "apk_step_3",
					title: "G2/G3: Dalvik Bytecode & Smali Class Query",
					tool: "droidasc",
					gate: "G2",
					params_summary: { target: targetPath, op: "listclass", limit: 30 },
				},
				{
					id: "apk_step_4",
					title: "G4: Attack Surface & Component Evidence Recording",
					tool: "evidence",
					gate: "G4",
					params_summary: {
						action: "add",
						kind: "fact",
						target: targetPath,
						sourceTool: "android_package_inspect",
						locator: "AndroidManifest.xml",
					},
				},
			];
			break;

		case "JS":
			stepDefinitions = [
				{
					id: "js_step_1",
					title: "G0/G1: SourceMap Audit & Original Source Extraction",
					tool: "sourcemap_inspect",
					gate: "G0",
					params_summary: { path: targetPath, action: "info" },
				},
				{
					id: "js_step_2",
					title: "G1/G2: Application Structure, IPC & Dependency Inventory",
					tool: "javascript_application",
					gate: "G1",
					params_summary: { target: targetPath, limit: 30 },
				},
				{
					id: "js_step_3",
					title: "G2/G3: Sensitive Endpoint & Credential Pattern Search",
					tool: "grep",
					gate: "G2",
					params_summary: {
						path: targetPath,
						pattern: "(api[_-]?key|secret|token|bearer|password)",
					},
				},
				{
					id: "js_step_4",
					title: "G4: Reconstructed Logic & Protocol Evidence Recording",
					tool: "evidence",
					gate: "G4",
					params_summary: {
						action: "add",
						kind: "fact",
						target: targetPath,
						sourceTool: "javascript_application",
						locator: "routes",
					},
				},
			];
			break;

		case "WASM":
			stepDefinitions = [
				{
					id: "wasm_step_1",
					title: "G0/G1: WebAssembly Section Breakdown & Header Triage",
					tool: "wasm_inspect",
					gate: "G0",
					params_summary: { path: targetPath, action: "info" },
				},
				{
					id: "wasm_step_2",
					title: "G1/G2: Data Segment String & Symbol Extraction",
					tool: "wasm_inspect",
					gate: "G1",
					params_summary: { path: targetPath, action: "strings", min_length: 5 },
				},
				{
					id: "wasm_step_3",
					title: "G2/G3: Disassembled WAT Instruction & Export Analysis",
					tool: "wasm_inspect",
					gate: "G2",
					params_summary: { path: targetPath, action: "wat", limit: 50 },
				},
				{
					id: "wasm_step_4",
					title: "G4: Memory Layout & Functional Evidence Recording",
					tool: "evidence",
					gate: "G4",
					params_summary: {
						action: "add",
						kind: "fact",
						target: targetPath,
						sourceTool: "wasm_inspect",
						locator: "imports",
					},
				},
			];
			break;

		case "PCAP":
			stepDefinitions = [
				{
					id: "pcap_step_1",
					title: "G0/G1: Packet Capture Header & Protocol Distribution Triage",
					tool: "pcap_inspect",
					gate: "G0",
					params_summary: { path: targetPath, action: "info" },
				},
				{
					id: "pcap_step_2",
					title: "G1/G2: Network Endpoint & Port Inventory",
					tool: "pcap_inspect",
					gate: "G1",
					params_summary: { path: targetPath, action: "endpoints", limit: 50 },
				},
				{
					id: "pcap_step_3",
					title: "G2/G3: Bidirectional Conversation & DNS/TLS Inspection",
					tool: "pcap_inspect",
					gate: "G2",
					params_summary: { path: targetPath, action: "conversations", limit: 30 },
				},
				{
					id: "pcap_step_4",
					title: "G4: Suspicious Traffic & Protocol Evidence Recording",
					tool: "evidence",
					gate: "G4",
					params_summary: {
						action: "add",
						kind: "fact",
						target: targetPath,
						sourceTool: "pcap_inspect",
						locator: "conversations",
					},
				},
			];
			break;

		case "SQLite":
			stepDefinitions = [
				{
					id: "sqlite_step_1",
					title: "G0/G1: SQLite Database Header, WAL & Pragma Triage",
					tool: "sqlite_inspect",
					gate: "G0",
					params_summary: { path: targetPath, action: "info" },
				},
				{
					id: "sqlite_step_2",
					title: "G1/G2: Database Schema & Table Inventory",
					tool: "sqlite_inspect",
					gate: "G1",
					params_summary: { path: targetPath, action: "tables" },
				},
				{
					id: "sqlite_step_3",
					title: "G2/G3: DDL Inspection & Sample Row Audit",
					tool: "sqlite_inspect",
					gate: "G2",
					params_summary: { path: targetPath, action: "schema" },
				},
				{
					id: "sqlite_step_4",
					title: "G4: Forensic Artifacts & Schema Evidence Recording",
					tool: "evidence",
					gate: "G4",
					params_summary: {
						action: "add",
						kind: "fact",
						target: targetPath,
						sourceTool: "sqlite_inspect",
						locator: "schema",
					},
				},
			];
			break;

		default:
			stepDefinitions = [
				{
					id: "unknown_step_1",
					title: "G0/G1: General Binary Header & Printable String Triage",
					tool: "triage",
					gate: "G0",
					params_summary: { path: targetPath, strings: true, limit: 30 },
				},
				{
					id: "unknown_step_2",
					title: "G4: Evidence Ledger Observation Recording",
					tool: "evidence",
					gate: "G4",
					params_summary: {
						action: "add",
						kind: "fact",
						target: targetPath,
						sourceTool: "triage",
						locator: "0x0",
					},
				},
			];
			break;
	}

	const steps: WorkflowStepRecord[] = stepDefinitions.map(def => ({
		id: def.id,
		title: def.title,
		tool: def.tool,
		gate: def.gate,
		params_summary: def.params_summary,
		status: "pending",
		attempts: 0,
		max_attempts: maxAttempts,
		evidence_ids: [],
		artifact_refs: [],
		created_at: now,
		updated_at: now,
	}));

	return { format: effectiveFormat, steps };
}

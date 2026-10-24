/**
 * VMPDump process memory dumper and Import Address Table (IAT) reconstruction tool.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import vmpDumpDescription from "../prompts/tools/vmp-dump.md" with { type: "text" };
import {
	getVmpToolUnsupportedReason,
	isVmpToolSupportedOnPlatform,
	resolveVmpTool,
} from "../extensibility/vmp-toolchain";
import type { ToolSession } from "./index";
import { throwIfAborted } from "./tool-errors";
import {
	formatHexAddress,
	getFileMetadata,
	parseAddress,
	parseAndValidatePe64,
	runSafeSubprocess,
	safePublishArtifact,
	type ArtifactMetadata,
} from "./vmp-common";

// ============================================================================
// Parameter Schema
// ============================================================================

const vmpDumpSchema = type({
	action: type
		.enumerated("status", "dump")
		.describe(
			"Action to perform: 'status' to probe VMPDump binary availability, platform support, and prerequisites; 'dump' to dump a live process memory image and rebuild IAT",
		),
	"pid?": type("string | number").describe(
		"Target process ID (positive 32-bit integer or hex string e.g. 1234 or '0x4d2'). Required for 'dump'",
	),
	"module?": type("string").describe(
		"Target module name to dump (e.g. 'sample.exe', 'target.dll'). Empty string '' dumps the main process image module. Defaults to ''",
	),
	"module_path?": type("string").describe("Path to target module on disk. Required for 'dump'"),
	"process_image_path?": type("string").describe(
		"Path to main process executable on disk if target module is a loaded DLL. Defaults to module_path",
	),
	"entry_point?": type("string | number").describe(
		"Optional Original Entry Point (OEP) RVA in hex form (e.g. '0x1000'). Must be an RVA (< SizeOfImage), not a virtual address. Overwrites OptionalHeader.AddressOfEntryPoint",
	),
	"disable_reloc?": type("boolean").describe(
		"Optional: mark relocations as stripped in output PE headers, forcing image to load at dumped ImageBase",
	),
	"observed_oep?": type("boolean").describe(
		"Explicit user acknowledgement that unpacking is complete and the process has reached the Original Entry Point (OEP). Required true for 'dump'",
	),
	"output_path?": type("string").describe("Optional destination path to safely copy the verified dumped PE artifact"),
	"timeout?": type("number").describe("Execution timeout in seconds (default 60, max 300)"),
});

export type VmpDumpParams = typeof vmpDumpSchema.infer;

export interface VmpDumpStatusDetails {
	action: "status";
	available: boolean;
	platform: NodeJS.Platform;
	supported: boolean;
	binaryPath: string | null;
	setupCommand: string;
	unsupportedReason: string | null;
}

export interface VmpDumpExecutionDetails {
	action: "dump";
	success: boolean;
	pid: string;
	module: string;
	modulePath: string;
	processImagePath: string;
	dumpedArtifact: ArtifactMetadata;
	publishedArtifact?: ArtifactMetadata;
	entryPointRva?: string;
	relocationsDisabled: boolean;
	durationMs: number;
	exitCode: number | null;
}

export type VmpDumpDetails = VmpDumpStatusDetails | VmpDumpExecutionDetails;

function parseTargetPid(pidInput: string | number): number {
	if (typeof pidInput === "number") {
		if (!Number.isSafeInteger(pidInput) || pidInput <= 0 || pidInput > 0xffffffff) {
			throw new ToolError(`Target PID must be a positive 32-bit integer (1 ~ 4294967295), got: ${pidInput}`);
		}
		return pidInput;
	}
	if (typeof pidInput === "string") {
		const trimmed = pidInput.trim();
		if (!/^(?:0x[0-9a-fA-F]+|[1-9][0-9]*)$/.test(trimmed)) {
			throw new ToolError(`Invalid target PID format (must be positive decimal integer or 0x hex): '${pidInput}'`);
		}
		const parsed = Number(trimmed);
		if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > 0xffffffff) {
			throw new ToolError(`Target PID out of range (1 ~ 4294967295): '${pidInput}'`);
		}
		return parsed;
	}
	throw new ToolError("Target PID must be a number or string");
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class VmpDumpTool implements AgentTool<typeof vmpDumpSchema, VmpDumpDetails> {
	readonly name = "vmp_dump";
	readonly label = "VMP Dump";
	readonly description: string;
	readonly parameters = vmpDumpSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = (args as { action?: unknown }).action;
			if (action === "dump") {
				return "exec";
			}
		}
		return "read";
	};

	private readonly sessionAbort = new AbortController();

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(vmpDumpDescription);
		session.registerDisposeCallback?.(() => {
			this.sessionAbort.abort();
		});
	}

	async execute(
		callId: string,
		params: VmpDumpParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<VmpDumpDetails>> {
		if (this.sessionAbort.signal.aborted) {
			throw new ToolError("Session is already disposed.");
		}

		const effectiveSignal = signal ? AbortSignal.any([signal, this.sessionAbort.signal]) : this.sessionAbort.signal;
		throwIfAborted(effectiveSignal);

		const cwd = this.session.cwd ?? process.cwd();

		// ------------------------------------------------------------------------
		// Action: status
		// ------------------------------------------------------------------------
		if (params.action === "status") {
			const binaryPath = resolveVmpTool("vmpdump");
			const available = binaryPath !== null;
			const platformSupported = isVmpToolSupportedOnPlatform("vmpdump", process.platform);
			const supported = platformSupported || available;
			const unsupportedReason = supported ? null : getVmpToolUnsupportedReason("vmpdump", process.platform);

			const textLines = [
				"### VMPDump Environment Status",
				`- Platform: ${process.platform}`,
				`- Supported: ${supported ? (available && !platformSupported ? "true (via custom binary)" : "true (Windows x64)") : `false (${unsupportedReason ?? "Non-Windows platform"})`}`,
				`- Binary Status: ${available ? `ready (\`${binaryPath}\`)` : "missing"}`,
				`- Setup Command: \`reverse setup reverse vmpdump --execute\``,
				"",
				"Note: VMPDump attaches to live Windows x64 processes to rebuild import tables. Dumping requires reaching the Original Entry Point (OEP).",
			];

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "status",
					available,
					platform: process.platform,
					supported,
					binaryPath,
					setupCommand: "reverse setup reverse vmpdump --execute",
					unsupportedReason,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: dump (safety checks & execution)
		// ------------------------------------------------------------------------
		if (this.session.getPlanModeState?.()?.enabled) {
			throw new ToolError(
				"Plan mode is read-only. Process dumping modifies files and accesses live memory; exit plan mode first.",
			);
		}

		if (params.pid === undefined || params.pid === null) {
			throw new ToolError("Action 'dump' requires target process ID (pid)");
		}
		const validatedPid = parseTargetPid(params.pid);

		if (!params.module_path) {
			throw new ToolError("Action 'dump' requires path to the target module on disk (module_path)");
		}

		if (params.observed_oep !== true) {
			throw new ToolError(
				"VMPDump requires confirmed user evidence that unpacking is complete and execution is at or past the Original Entry Point (OEP). Please pass observed_oep: true after verifying OEP.",
			);
		}

		const resolvedModulePath = path.isAbsolute(params.module_path)
			? params.module_path
			: path.resolve(cwd, params.module_path);
		if (params.module && params.module.trim()) {
			if (!params.process_image_path) {
				throw new ToolError(
					`When dumping a secondary module ('${params.module}'), 'process_image_path' pointing to the host process executable is required to locate the output dump directory.`,
				);
			}
		}

		const resolvedProcessPath = params.process_image_path
			? path.isAbsolute(params.process_image_path)
				? params.process_image_path
				: path.resolve(cwd, params.process_image_path)
			: resolvedModulePath;
		// Validate disk image is valid x64 PE
		const targetModulePeInfo = await parseAndValidatePe64(resolvedModulePath);
		const origLstat = await fs.promises.lstat(resolvedModulePath);
		const forbiddenInodes = new Set<string>([`${origLstat.dev}:${origLstat.ino}`]);

		if (resolvedProcessPath !== resolvedModulePath) {
			const procLstat = await fs.promises.lstat(resolvedProcessPath);
			forbiddenInodes.add(`${procLstat.dev}:${procLstat.ino}`);
		}

		// VMPDump writes output dump into the process image directory
		const processDir = path.dirname(resolvedProcessPath);
		const targetModuleName =
			params.module && params.module.trim() ? params.module.trim() : path.basename(resolvedModulePath);

		const targetExt = path.extname(targetModuleName) || path.extname(resolvedModulePath);
		const targetBase = path.basename(targetModuleName, targetExt);
		const expectedDumpPath = path.join(processDir, `${targetBase}.VMPDump${targetExt}`);

		// Prevent pre-existing links or silent overwriting of prior analysis
		const preLstat = await fs.promises.lstat(expectedDumpPath).catch(() => null);
		if (preLstat) {
			const preKey = `${preLstat.dev}:${preLstat.ino}`;
			if (preLstat.isSymbolicLink() || forbiddenInodes.has(preKey)) {
				throw new ToolError(
					`Dump output destination has an existing link pointing to a protected file: ${expectedDumpPath}`,
				);
			}
			throw new ToolError(
				`Dump output file already exists: ${expectedDumpPath}. Move or rename the existing file before dumping.`,
			);
		}

		let entryPointHex: string | undefined;
		if (params.entry_point !== undefined && params.entry_point !== null) {
			const ep = parseAddress(params.entry_point, "entry_point");
			if (ep >= targetModulePeInfo.imageBase) {
				const suggestedRva = ep - targetModulePeInfo.imageBase;
				throw new ToolError(
					`entry_point must be a Relative Virtual Address (RVA < SizeOfImage). Address ${formatHexAddress(ep)} is >= ImageBase ${formatHexAddress(targetModulePeInfo.imageBase)}. Provide RVA instead: ${formatHexAddress(suggestedRva)} (VA - ImageBase).`,
				);
			}
			if (ep >= targetModulePeInfo.sizeOfImage || ep > 0xffffffffn) {
				throw new ToolError(
					`entry_point RVA ${formatHexAddress(ep)} exceeds module SizeOfImage ${formatHexAddress(targetModulePeInfo.sizeOfImage)} (or 32-bit limit).`,
				);
			}
			entryPointHex = formatHexAddress(ep);
		}

		const binaryPath = resolveVmpTool("vmpdump");
		if (!binaryPath) {
			const unsupported = getVmpToolUnsupportedReason("vmpdump", process.platform);
			throw new ToolError(
				unsupported
					? `VMPDump is not supported on this platform: ${unsupported}`
					: "vmpdump executable not found. Install it via 'reverse setup reverse vmpdump --execute'.",
			);
		}

		const pidStr = String(validatedPid);
		const moduleStr = params.module ?? "";
		const args = [pidStr, moduleStr];
		if (entryPointHex) {
			args.push(`-ep=${entryPointHex}`);
		}
		if (params.disable_reloc) {
			args.push("-disable-reloc");
		}

		const timeoutSeconds = Math.min(300, Math.max(5, params.timeout ?? 60));

		const runResult = await runSafeSubprocess({
			binary: binaryPath,
			args,
			cwd: processDir,
			timeoutMs: timeoutSeconds * 1000,
			signal: effectiveSignal,
		});

		// 仅接受运行前已检查为空的目标；日志中的其他路径缺少新鲜性证据。
		const actualDumpPath = expectedDumpPath;
		const writtenMatch = runResult.stdout.match(/\*\* File written to:\s*([^\r\n]+)/);
		if (writtenMatch?.[1]) {
			const reportedPath = path.resolve(processDir, writtenMatch[1].trim());
			if (reportedPath.toLowerCase() !== path.resolve(expectedDumpPath).toLowerCase()) {
				throw new ToolError(
					`VMPDump reported an unexpected output path: ${reportedPath}. Expected: ${expectedDumpPath}`,
				);
			}
		}
		if (runResult.exitCode !== 0) {
			throw new ToolError(
				`VMPDump failed with exit code ${runResult.exitCode}: ${runResult.stderr || runResult.stdout}`,
			);
		}

		const postStat = await fs.promises.stat(actualDumpPath).catch(() => null);
		if (!postStat || postStat.size === 0) {
			throw new ToolError(
				`VMPDump finished with exit code ${runResult.exitCode}, but expected output dump was not produced at: ${actualDumpPath}\n` +
					`STDOUT:\n${runResult.stdout}\n` +
					`STDERR:\n${runResult.stderr}`,
			);
		}

		// Validate generated dump is valid x64 PE
		const dumpPeInfo = await parseAndValidatePe64(actualDumpPath);
		const relocsStripped = (dumpPeInfo.characteristics & 0x0001) !== 0;

		const dumpedArtifact = await getFileMetadata(actualDumpPath);
		if (!dumpedArtifact) {
			throw new ToolError(`Failed to read metadata of produced dump: ${actualDumpPath}`);
		}

		let publishedArtifact: ArtifactMetadata | undefined;
		if (params.output_path) {
			const resolvedOutputPath = path.isAbsolute(params.output_path)
				? params.output_path
				: path.resolve(cwd, params.output_path);

			publishedArtifact = await safePublishArtifact(actualDumpPath, resolvedOutputPath, forbiddenInodes);
		}

		const textSummary = [
			"### VMPDump Completed",
			`- Target PID: ${pidStr}`,
			`- Target Module: ${moduleStr || "<main process image>"} (\`${targetModuleName}\`)`,
			`- Process Image Path: \`${resolvedProcessPath}\``,
			`- Original ImageBase: ${formatHexAddress(targetModulePeInfo.imageBase)}`,
			`- Dumped Entry Point RVA: ${formatHexAddress(dumpPeInfo.entryPointRva)}`,
			`- Relocations Stripped: ${relocsStripped ? "true (IMAGE_FILE_RELOCS_STRIPPED observed in output PE)" : "false"}`,
			`- Dumped Artifact: \`${dumpedArtifact.path}\` (${dumpedArtifact.bytes} bytes, SHA-256: ${dumpedArtifact.sha256.slice(0, 16)}...)`,
			publishedArtifact ? `- Published Copy: \`${publishedArtifact.path}\`` : "",
			`- Duration: ${runResult.durationMs}ms`,
		]
			.filter(Boolean)
			.join("\n");

		return {
			content: [{ type: "text", text: textSummary }],
			details: {
				action: "dump",
				success: true,
				pid: pidStr,
				module: moduleStr,
				modulePath: resolvedModulePath,
				processImagePath: resolvedProcessPath,
				dumpedArtifact,
				publishedArtifact,
				entryPointRva: formatHexAddress(dumpPeInfo.entryPointRva),
				relocationsDisabled: relocsStripped,
				durationMs: runResult.durationMs,
				exitCode: runResult.exitCode,
			},
		};
	}
}

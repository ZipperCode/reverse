import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { Stats } from "node:fs";
import { type } from "@reverse/reversetype";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import ghidraInspectDescription from "../prompts/tools/ghidra-inspect.md" with { type: "text" };
import reverseGhidraScriptSource from "./reverse-ghidra-inspect.java" with { type: "text" };
import {
	checkToolRequirements,
	type SkillRequirementWhich,
	type ToolRequirement,
} from "../extensibility/skill-requirements";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";

const ghidraInspectSchema = type({
	action: type
		.enumerated("info", "analyze", "decompile", "export")
		.describe(
			"Read-only Ghidra headless action: info (dependency and environment status), analyze (headless auto-analysis), decompile (decompile function to C pseudocode), or export (export analysis/decompilation)",
		),
	path: type("string").describe("Path to target binary"),
	"target?": type("string").describe("Function name or address to decompile (alias for symbol)"),
	"symbol?": type("string").describe("Function name or symbol to decompile"),
	"address?": type("string").describe("Virtual address in hex (e.g. 0x401000)"),
	"script?": type("string").describe("Optional name of existing Ghidra post-script to execute"),
	"script_args?": type("string[]").describe("Arguments to pass to the script"),
	"project_dir?": type("string").describe("Optional directory for Ghidra project; defaults to temporary directory"),
	"timeout?": type("number").describe("Execution timeout in seconds (default 60, max 300)"),
	"max_bytes?": type("number").describe("Maximum stdout/export bytes captured (default 262144, max 4194304)"),
	"limit?": type("number").describe("Maximum lines returned (default 100, max 2000)"),
	"offset?": type("number").describe("Zero-based line pagination offset"),
	"mode?": type
		.enumerated("full", "fold", "summary")
		.describe("Rendering mode: full (default), fold (deduplicate blank/repeated lines), or summary"),
});

export type GhidraInspectParams = typeof ghidraInspectSchema.infer;
export type GhidraInspectAction = GhidraInspectParams["action"];
export type GhidraInspectMode = "full" | "fold" | "summary";

export interface GhidraDependencyStatus {
	id: "ghidra";
	binary: "analyzeHeadless" | "ghidra";
	available: boolean;
	path?: string;
	installHint?: string;
}

export interface GhidraFallbackInfo {
	primary: "ghidra";
	operation: GhidraInspectAction;
	suggestedFallback: string;
	activeFallback: string;
	alternatives: string[];
	executed: false;
}

export interface GhidraInspectDetails {
	action: GhidraInspectAction;
	path: string;
	status: "ok" | "missing_dependency" | "error";
	mode: GhidraInspectMode;
	dependency?: GhidraDependencyStatus;
	fallback?: GhidraFallbackInfo;
	engine?: string;
	command?: string[];
	target?: string;
	address?: string;
	signature?: string;
	outputBytes?: number;
	truncated?: boolean;
	timedOut?: boolean;
	totalLines?: number;
	returnedLines?: number;
	offset?: number;
	hasMore?: boolean;
	error?: string;
}

export interface GhidraRunResult {
	stdout: string;
	stderr: string;
	exitCode: number;
	outputBytes: number;
	truncated: boolean;
	timedOut: boolean;
}

export type GhidraRunner = (
	binary: string,
	args: string[],
	options: {
		cwd: string;
		timeoutMs: number;
		maxBytes: number;
		signal?: AbortSignal;
	},
) => Promise<GhidraRunResult>;

export interface GhidraInspectToolOptions {
	which?: SkillRequirementWhich;
	runner?: GhidraRunner;
	ghidraInstallDir?: string;
}

const DEFAULT_LINE_LIMIT = 100;
const MAX_LINE_LIMIT = 2000;
const DEFAULT_TIMEOUT_SECONDS = 60;
const MAX_TIMEOUT_SECONDS = 300;
const DEFAULT_MAX_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_FILE_BYTES = 1024 * 1024 * 1024; // 1 GiB
const STDERR_BYTES = 32 * 1024;
const MAX_FOLD_LINE = 400;

const ADDRESS_PATTERN = /^(?:0[xX])?[0-9a-fA-F]{1,16}$/;
const SYMBOL_PATTERN = /^[A-Za-z0-9_.:<>-]{1,256}$/;
const SAFE_SCRIPT_NAME_PATTERN = /^[A-Za-z0-9_.-]{1,128}$/;
const ANSI_PATTERN = /\u001b\[[0-9;]*[A-Za-z]/g;

interface CappedRead {
	text: string;
	bytes: number;
	truncated: boolean;
}

const START_TOKEN = "<<<REVERSE_GHIDRA_OUTPUT_START>>>";
const END_TOKEN = "<<<REVERSE_GHIDRA_OUTPUT_END>>>";
const BUNDLED_SCRIPT_FILENAME = "ReverseGhidraInspect.java";

interface ReverseGhidraOutputPayload {
	status: "ok" | "error";
	action?: string;
	target?: string;
	address?: string;
	signature?: string;
	output?: string;
	code?: string;
	error?: string;
}

async function readCapped(
	stream: ReadableStream<Uint8Array>,
	cap: number,
	onOverflow?: () => void,
): Promise<CappedRead> {
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let bytes = 0;
	let truncated = false;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			const remaining = cap - bytes;
			if (value.byteLength >= remaining) {
				if (remaining > 0) chunks.push(value.subarray(0, remaining));
				bytes += Math.max(0, remaining);
				truncated = true;
				onOverflow?.();
				break;
			}
			chunks.push(value);
			bytes += value.byteLength;
		}
	} finally {
		if (truncated) await reader.cancel().catch(() => {});
	}
	return {
		text: Buffer.concat(chunks.map(chunk => Buffer.from(chunk))).toString("utf8"),
		bytes,
		truncated,
	};
}

export async function defaultGhidraRunner(
	binary: string,
	args: string[],
	options: {
		cwd: string;
		timeoutMs: number;
		maxBytes: number;
		signal?: AbortSignal;
	},
): Promise<GhidraRunResult> {
	const child = Bun.spawn([binary, ...args], {
		cwd: options.cwd,
		stdout: "pipe",
		stderr: "pipe",
		stdin: "ignore",
	});
	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		child.kill();
	}, options.timeoutMs);
	const onAbort = () => {
		child.kill();
	};
	options.signal?.addEventListener("abort", onAbort, { once: true });
	try {
		const [stdout, stderr, exitCode] = await Promise.all([
			readCapped(child.stdout, options.maxBytes, () => {
				child.kill();
			}),
			readCapped(child.stderr, STDERR_BYTES),
			child.exited,
		]);
		return {
			stdout: stdout.text,
			stderr: stderr.text,
			exitCode,
			outputBytes: stdout.bytes,
			truncated: stdout.truncated,
			timedOut,
		};
	} finally {
		clearTimeout(timer);
		options.signal?.removeEventListener("abort", onAbort);
	}
}

export function ghidraDependency(options: GhidraInspectToolOptions = {}): GhidraDependencyStatus {
	// 1. Check configured or environment GHIDRA_INSTALL_DIR
	const envDir = options.ghidraInstallDir ?? process.env.GHIDRA_INSTALL_DIR ?? process.env.GHIDRA_HOME;
	if (envDir && envDir.trim().length > 0) {
		const isWin = process.platform === "win32";
		const binaryName = isWin ? "analyzeHeadless.bat" : "analyzeHeadless";
		const candidates = [path.join(envDir, "support", binaryName), path.join(envDir, binaryName)];
		for (const cand of candidates) {
			try {
				const s = Bun.file(cand);
				if (s.size !== undefined && s.size > 0) {
					return {
						id: "ghidra",
						binary: "analyzeHeadless",
						available: true,
						path: cand,
					};
				}
			} catch {
				// Continue search
			}
		}
	}

	// 2. Check skill catalog / which
	const requirements: ToolRequirement[] = [{ id: "ghidra" }];
	const [status] = checkToolRequirements(requirements, options.which ? { which: options.which } : undefined);
	const found = status?.foundPath ?? null;
	if (found) {
		// If found points to support/analyzeHeadless or a wrapper
		return {
			id: "ghidra",
			binary: "analyzeHeadless",
			available: true,
			path: found,
		};
	}

	return {
		id: "ghidra",
		binary: "analyzeHeadless",
		available: false,
		installHint:
			status?.hint ??
			"brew install --cask ghidra (macOS), apt install ghidra (Linux), choco install ghidra (Windows), or extract release from https://ghidra-sre.org/ and set GHIDRA_INSTALL_DIR.",
	};
}

export function resolveGhidraFallback(
	action: GhidraInspectAction,
	targetPath: string,
	options: { symbol?: string; address?: string } = {},
): GhidraFallbackInfo {
	const ref = options.address ?? options.symbol;
	const refStr = ref ? ` with target ${ref}` : "";
	const quoted = `"${targetPath.replace(/(["\\$`])/g, "\\$1")}"`;

	switch (action) {
		case "info":
			return {
				primary: "ghidra",
				operation: action,
				suggestedFallback: `r2_inspect(action: "info", path: ${quoted})`,
				activeFallback: "r2_inspect",
				alternatives: [`triage(path: ${quoted})`, `r2 -qc "iI" ${quoted}`, `file ${quoted}`],
				executed: false,
			};
		case "analyze":
			return {
				primary: "ghidra",
				operation: action,
				suggestedFallback: `r2_inspect(action: "functions", path: ${quoted})`,
				activeFallback: "r2_inspect",
				alternatives: [
					`r2_inspect(action: "sections", path: ${quoted})`,
					`triage(path: ${quoted})`,
					`objdump -d ${quoted}`,
				],
				executed: false,
			};
		case "decompile":
			return {
				primary: "ghidra",
				operation: action,
				suggestedFallback: ref
					? `r2_inspect(action: "decompile", path: ${quoted}, symbol: "${ref}")`
					: `r2_inspect(action: "decompile", path: ${quoted})`,
				activeFallback: "r2_inspect",
				alternatives: [
					`read path: "${targetPath}:${ref ?? "main"}" (when IDA Pro is active)`,
					`r2 -qc "aaa; pdg @ ${ref ?? "main"}" ${quoted}`,
					`r2_inspect(action: "disasm", path: ${quoted}${refStr})`,
				],
				executed: false,
			};
		case "export":
			return {
				primary: "ghidra",
				operation: action,
				suggestedFallback: `r2_inspect(action: "disasm", path: ${quoted})`,
				activeFallback: "r2_inspect",
				alternatives: [`objdump -d ${quoted}`, `triage(path: ${quoted})`],
				executed: false,
			};
	}
}

export function foldGhidraText(text: string): string {
	const lines: string[] = [];
	let previous: string | undefined;
	for (const rawLine of text.replace(ANSI_PATTERN, "").split(/\r?\n/)) {
		const line = rawLine.replace(/[ \t]+$/g, "").replace(/\t/g, "    ");
		if (line.trim().length === 0) continue;
		if (line === previous) continue;
		const bounded = line.length > MAX_FOLD_LINE ? `${line.slice(0, MAX_FOLD_LINE)}…` : line;
		lines.push(bounded);
		previous = line;
	}
	return lines.join("\n");
}

export class GhidraInspectTool implements AgentTool<typeof ghidraInspectSchema, GhidraInspectDetails> {
	readonly name = "ghidra_inspect";
	readonly approval: ToolTier = "read";
	readonly label = "Ghidra Inspect";
	readonly summary =
		"Read-only headless binary analysis and function decompilation via Ghidra (analyzeHeadless) without arbitrary shell execution";
	readonly description: string;
	readonly parameters = ghidraInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	private readonly whichSeam?: SkillRequirementWhich;
	private readonly runnerSeam?: GhidraRunner;
	private readonly ghidraInstallDirSeam?: string;

	constructor(
		private readonly session: ToolSession,
		options: GhidraInspectToolOptions = {},
	) {
		this.description = prompt.render(ghidraInspectDescription);
		this.whichSeam = options.which;
		this.runnerSeam = options.runner;
		this.ghidraInstallDirSeam = options.ghidraInstallDir;
	}

	async execute(
		_toolCallId: string,
		params: GhidraInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<GhidraInspectDetails> & { details: GhidraInspectDetails }> {
		throwIfAborted(signal);

		const resolvedPath = resolveReadPath(params.path, this.session.cwd);

		let fileStat: Stats;
		try {
			fileStat = await fs.stat(resolvedPath);
		} catch (err) {
			throw new ToolError(
				`Target file not found: ${resolvedPath} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		if (fileStat.isDirectory()) {
			throw new ToolError(`Target path is a directory, not a file: ${resolvedPath}`);
		}

		if (fileStat.size > MAX_FILE_BYTES) {
			throw new ToolError(`File size (${fileStat.size} bytes) exceeds 1 GiB limit`);
		}

		// Validate symbol / address / script parameters
		const rawSymbol = (params.symbol?.trim() || params.target?.trim()) ?? undefined;
		if (rawSymbol && !SYMBOL_PATTERN.test(rawSymbol) && !ADDRESS_PATTERN.test(rawSymbol)) {
			throw new ToolError(`Invalid symbol or function identifier: '${rawSymbol}'`);
		}

		const rawAddress = params.address?.trim();
		if (rawAddress && !ADDRESS_PATTERN.test(rawAddress)) {
			throw new ToolError(`Invalid virtual address format: '${rawAddress}' (expected hex e.g. 0x401000)`);
		}

		if (params.script && !SAFE_SCRIPT_NAME_PATTERN.test(params.script.trim())) {
			throw new ToolError(`Invalid script name: '${params.script}' (alphanumeric, dot, dash only)`);
		}

		const targetIdentifier = rawAddress ?? rawSymbol;

		// Check Ghidra dependency
		const depStatus = ghidraDependency({
			which: this.whichSeam,
			ghidraInstallDir: this.ghidraInstallDirSeam,
		});

		const fallback = resolveGhidraFallback(params.action, params.path, {
			symbol: rawSymbol,
			address: rawAddress,
		});

		if (!depStatus.available || !depStatus.path) {
			const notice = [
				"[Notice] Primary tool 'ghidra' (analyzeHeadless) not found on PATH or via GHIDRA_INSTALL_DIR.",
				"  -> Recommended setup: run 'reverse setup reverse ghidra' or launch interactive setup ('reverse setup').",
				`  -> Catalog install hint: ${depStatus.installHint ?? "brew install --cask ghidra (macOS) or download from https://ghidra-sre.org/"}`,
				`  -> Suggested fallback: ${fallback.suggestedFallback}`,
				"  -> Alternative options:",
				...fallback.alternatives.map(a => `     • ${a}`),
				"  (Note: Ghidra decompilation was not faked. The fallback command was not run automatically; run it if appropriate.)",
			].join("\n");

			return {
				content: [{ type: "text", text: notice }],
				details: {
					action: params.action,
					path: params.path,
					status: "missing_dependency",
					mode: params.mode ?? "full",
					dependency: depStatus,
					fallback,
				},
			};
		}

		// When action is 'info', report environment and target binary status without spawning headless project
		if (params.action === "info") {
			const infoLines = [
				`Ghidra Headless Bridge Status:`,
				`  Status: Available`,
				`  analyzeHeadless: ${depStatus.path}`,
				`  Target File: ${resolvedPath} (${fileStat.size} bytes)`,
				`  Read-Only Mode: Enforced`,
			];
			return {
				content: [{ type: "text", text: infoLines.join("\n") }],
				details: {
					action: "info",
					path: params.path,
					status: "ok",
					mode: params.mode ?? "full",
					dependency: depStatus,
					engine: depStatus.path,
				},
			};
		}

		// Construct headless command arguments
		const isTempProject = !params.project_dir;
		const projectName = "reverse_headless_proj";
		const ghidraBinary = depStatus.path;

		const timeoutSeconds = Math.min(Math.max(1, params.timeout ?? DEFAULT_TIMEOUT_SECONDS), MAX_TIMEOUT_SECONDS);
		const maxBytes = Math.min(Math.max(1024, params.max_bytes ?? DEFAULT_MAX_BYTES), MAX_OUTPUT_BYTES);

		let tempDir: string | undefined;
		let scriptsDir: string | undefined;
		let runResult: GhidraRunResult;
		const args: string[] = [];
		const useBundledScript = !params.script && (params.action === "decompile" || params.action === "export");

		try {
			tempDir = isTempProject
				? await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-headless-"))
				: path.resolve(this.session.cwd, params.project_dir!);

			if (!isTempProject) {
				await fs.mkdir(tempDir, { recursive: true });
			}

			args.push(tempDir, projectName, "-import", resolvedPath, "-readOnly");
			if (isTempProject) {
				args.push("-deleteProject");
			}

			if (params.script) {
				args.push("-postScript", params.script);
				if (params.script_args && params.script_args.length > 0) {
					args.push(...params.script_args);
				} else if (targetIdentifier) {
					args.push(targetIdentifier);
				}
			} else if (useBundledScript) {
				scriptsDir = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-ghidra-scripts-"));
				const scriptPath = path.join(scriptsDir, BUNDLED_SCRIPT_FILENAME);
				await fs.writeFile(scriptPath, reverseGhidraScriptSource, "utf8");
				args.push(
					"-scriptPath",
					scriptsDir,
					"-postScript",
					BUNDLED_SCRIPT_FILENAME,
					params.action,
					targetIdentifier ?? "",
					String(timeoutSeconds),
					String(maxBytes),
				);
			}

			const runner = this.runnerSeam ?? defaultGhidraRunner;
			runResult = await runner(ghidraBinary, args, {
				cwd: this.session.cwd,
				timeoutMs: timeoutSeconds * 1000,
				maxBytes,
				signal,
			});
		} finally {
			if (scriptsDir) {
				await fs.rm(scriptsDir, { recursive: true, force: true }).catch(() => {});
			}
			if (isTempProject && tempDir) {
				await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
			}
		}

		let rawText = "";
		let outcomeStatus: "ok" | "error" = "ok";
		let outcomeError: string | undefined;
		let resolvedTarget: string | undefined = targetIdentifier;
		let resolvedAddress: string | undefined = rawAddress;
		let resolvedSignature: string | undefined;

		if (useBundledScript) {
			if (runResult.timedOut) {
				outcomeStatus = "error";
				outcomeError = `Execution timed out after ${timeoutSeconds} seconds`;
				rawText = outcomeError;
			} else if (runResult.exitCode !== 0) {
				outcomeStatus = "error";
				const errDetail = runResult.stderr.trim() || runResult.stdout.trim().slice(-500);
				outcomeError = `Process exited with code ${runResult.exitCode}${errDetail ? `: ${errDetail}` : ""}`;
				rawText = outcomeError;
			} else if (runResult.truncated) {
				outcomeStatus = "error";
				outcomeError = "Output was truncated due to byte limit; incomplete decompiler result";
				rawText = outcomeError;
			} else {
				// Parse compact single-line frame from stdout, with stderr fallback
				let jsonText: string | undefined;
				for (const streamText of [runResult.stdout, runResult.stderr]) {
					for (const line of streamText.split(/\r?\n/)) {
						const startIdx = line.indexOf(START_TOKEN);
						if (startIdx !== -1) {
							const endIdx = line.lastIndexOf(END_TOKEN);
							if (endIdx > startIdx) {
								jsonText = line.slice(startIdx + START_TOKEN.length, endIdx).trim();
								break;
							}
						}
					}
					if (jsonText) break;
				}

				let payload: ReverseGhidraOutputPayload | undefined;
				if (jsonText) {
					try {
						const parsed = JSON.parse(jsonText);
						if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
							payload = parsed as ReverseGhidraOutputPayload;
						}
					} catch {
						// JSON parse failed
					}
				}

				if (payload) {
					if (payload.status === "ok") {
						if (payload.action !== params.action) {
							outcomeStatus = "error";
							outcomeError = `Script action mismatch: expected '${params.action}', received '${String(payload.action)}'`;
							rawText = outcomeError;
						} else if (typeof payload.output !== "string" || payload.output.trim().length === 0) {
							outcomeStatus = "error";
							outcomeError = "Ghidra decompiler produced empty output for target";
							rawText = outcomeError;
						} else {
							rawText = payload.output;
							outcomeStatus = "ok";
							if (typeof payload.target === "string") resolvedTarget = payload.target;
							if (typeof payload.address === "string") resolvedAddress = payload.address;
							if (typeof payload.signature === "string") resolvedSignature = payload.signature;
						}
					} else {
						outcomeStatus = "error";
						const errStr =
							typeof payload.error === "string" && payload.error.trim().length > 0
								? payload.error.trim()
								: "Ghidra decompiler script reported an error";
						outcomeError = errStr;
						rawText = errStr;
					}
				} else {
					outcomeStatus = "error";
					outcomeError = "Ghidra headless completed without producing decompiler script output";
					rawText = outcomeError;
				}
			}
		} else {
			rawText = runResult.stdout.length > 0 ? runResult.stdout : runResult.stderr;
			outcomeStatus = runResult.exitCode === 0 ? "ok" : "error";
			outcomeError = runResult.exitCode !== 0 ? `Process exited with code ${runResult.exitCode}` : undefined;
		}

		const mode = params.mode ?? "full";
		let processedText = rawText;
		if (mode === "fold") {
			processedText = foldGhidraText(rawText);
		}

		const lines = processedText.split(/\r?\n/);
		const totalLines = lines.length;
		const offset = Math.max(0, params.offset ?? 0);
		const limit = Math.min(Math.max(1, params.limit ?? DEFAULT_LINE_LIMIT), MAX_LINE_LIMIT);
		const pagedLines = lines.slice(offset, offset + limit);

		let outputText = pagedLines.join("\n");
		if (mode === "summary") {
			const preview = pagedLines.slice(0, 15);
			outputText = [
				`Summary for Ghidra ${params.action} on ${params.path}:`,
				`  Total lines: ${totalLines}`,
				`  Exit code: ${runResult.exitCode}`,
				`  Bytes: ${runResult.outputBytes}${runResult.truncated ? " (truncated)" : ""}`,
				`  Preview (${preview.length} lines):`,
				...preview.map(l => `    ${l}`),
			].join("\n");
		}

		return {
			content: [{ type: "text", text: outputText }],
			details: {
				action: params.action,
				path: params.path,
				status: outcomeStatus,
				mode,
				dependency: depStatus,
				engine: depStatus.path,
				command: [ghidraBinary, ...args],
				target: resolvedTarget,
				address: resolvedAddress,
				signature: resolvedSignature,
				outputBytes: runResult.outputBytes,
				truncated: runResult.truncated,
				timedOut: runResult.timedOut,
				totalLines,
				returnedLines: pagedLines.length,
				offset,
				hasMore: offset + pagedLines.length < totalLines,
				error: outcomeError,
			},
		};
	}
}

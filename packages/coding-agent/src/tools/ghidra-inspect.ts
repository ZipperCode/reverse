import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Stats } from "node:fs";
import { type } from "@reverse/reversetype";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import ghidraInspectDescription from "../prompts/tools/ghidra-inspect.md" with { type: "text" };
import reverseGhidraScriptSource from "./reverse-ghidra-inspect.java" with { type: "text" };
import jniApiMetadataSource from "./jni-api-metadata.json" with { type: "text" };
import {
	checkToolRequirements,
	type SkillRequirementWhich,
	type ToolRequirement,
} from "../extensibility/skill-requirements";
import { resolveGhidraFindCrypt, type GhidraFindCryptStatus } from "../extensibility/findcrypt-install";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import { getActiveGhidraProjectLock } from "./native-mcp-session";
import {
	type CanonicalJniMethodRecord,
	type JniEnrichSummary,
	type JniEnrichPreviewItem,
	canonicalizeRegisterNativesEvent,
	previewJniEnrichment,
	parseElfMetadataForJni,
} from "./jni-enrichment";
export * from "./jni-enrichment";

const ghidraInspectSchema = type({
	action: type
		.enumerated("info", "analyze", "decompile", "export", "jni_enrich", "findcrypt")
		.describe(
			"Ghidra headless action: info (dependency and environment status), analyze (headless auto-analysis), decompile (decompile function to C pseudocode), export (export analysis/decompilation), jni_enrich (apply dynamic RegisterNatives JNI symbols and prototypes), or findcrypt (run external FindCrypt cryptographic constants analyzer)",
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
	"records?": type("unknown[]").describe("Array of CanonicalJniMethodRecord objects to enrich"),
	"events?": type("unknown").describe("Raw RegisterNatives event or array of events from dynamic tracing"),
	"events_path?": type("string").describe(
		"Path to an on-disk JSON artifact containing RegisterNatives events (e.g. from Frida or Unidbg)",
	),
	"preview?": type("boolean").describe(
		"When true (default), previews JNI enrichment without modifying project. Set false to apply changes to project",
	),
	"load_bias?": type("string").describe("Runtime module load bias in hex (e.g. '0x7f000000') for address re-basing"),
	"is_static_map?": type("unknown").describe(
		"Optional mapping from method key to boolean indicating static DEX declaration",
	),
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
	dependency?: GhidraDependencyStatus | GhidraFindCryptStatus;
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
	enrichment?: JniEnrichSummary;
	cryptoCandidates?: Array<{ address: string; algorithm: string; matchType: string; category?: string }>;
	cryptoNotice?: string;
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
	findCryptStatus?: GhidraFindCryptStatus;
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
export function ghidraFindCryptDependency(
	options: {
		ghidraInstallDir?: string;
		findCryptStatus?: GhidraFindCryptStatus;
		which?: SkillRequirementWhich;
	} = {},
): GhidraFindCryptStatus {
	if (options.findCryptStatus) {
		return options.findCryptStatus;
	}
	return resolveGhidraFindCrypt({
		ghidraPath: options.ghidraInstallDir,
		which: options.which,
	});
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
		case "jni_enrich":
			return {
				primary: "ghidra",
				operation: action,
				suggestedFallback: `android_native_workflow(action: "inspect", path: ${quoted})`,
				activeFallback: "android_native_workflow",
				alternatives: [
					`r2_inspect(action: "functions", path: ${quoted})`,
					`frida_session(template: "jni_register")`,
				],
				executed: false,
			};
		case "findcrypt":
			return {
				primary: "ghidra",
				operation: action,
				suggestedFallback: `r2_inspect(action: "info", path: ${quoted})`,
				activeFallback: "r2_inspect",
				alternatives: [`strings ${quoted} | grep -iE "aes|sha|md5|rsa|des"`, `triage(path: ${quoted})`],
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
async function computeFileSha256(filePath: string): Promise<string> {
	const hash = crypto.createHash("sha256");
	const stream = fsSync.createReadStream(filePath);
	for await (const chunk of stream) {
		hash.update(chunk);
	}
	return hash.digest("hex");
}

function formatJniEnrichPreviewText(summary: JniEnrichSummary, targetPath: string, sha256: string): string {
	const lines = [
		`### JNI Registration Enrichment Preview for ${path.basename(targetPath)}`,
		`- **Binary SHA-256**: \`${sha256}\``,
		`- **Total JNI Methods**: ${summary.total}`,
		`- **Eligible**: ${summary.eligible}`,
		`- **Rejected / Out of Bounds**: ${summary.rejected}`,
		"",
		"| Class | Method | JVM Signature | Receiver | Static Address | Target Symbol | Status |",
		"|---|---|---|---|---|---|---|",
		...summary.items.map(
			it =>
				`| \`${it.className}\` | \`${it.methodName}\` | \`${it.signature}\` | ${it.isStatic === true ? "static" : it.isStatic === false ? "virtual" : "unverified"} | \`${it.staticAddress}\` | \`${it.targetFunctionName}\` | ${it.status} |`,
		),
		"",
		"> Note: Preview only (dry-run). Set `preview: false` and specify `project_dir` to apply changes to Ghidra project.",
	];
	return lines.join("\n");
}

function formatJniEnrichAppliedText(
	summary: JniEnrichSummary,
	appliedItems: Array<{ address: string; name: string; prototype: string; code: string }>,
	targetPath: string,
	projectDir: string,
): string {
	const lines = [
		`### JNI Registration Enrichment Applied to Ghidra Project (${path.basename(projectDir)})`,
		`- **Target Binary**: \`${targetPath}\``,
		`- **Applied Methods**: ${appliedItems.length}`,
		"",
		"| Target Symbol | Address | Prototype | Decompiled |",
		"|---|---|---|---|",
		...appliedItems.map(
			it => `| \`${it.name}\` | \`${it.address}\` | \`${it.prototype}\` | ${it.code ? "Yes" : "No"} |`,
		),
	];
	if (appliedItems.length > 0) {
		lines.push("", "#### Decompiled Pseudocode Previews:");
		for (const it of appliedItems.slice(0, 5)) {
			lines.push(`\n**${it.name}** (\`${it.address}\`):`, "```c", it.code.slice(0, 1000), "```");
		}
	}
	return lines.join("\n");
}

function formatFindCryptCandidatesText(
	candidates: Array<{ address: string; algorithm: string; matchType: string; category?: string }>,
	targetPath: string,
): string {
	const lines = [
		`### Ghidra FindCrypt Candidates for ${path.basename(targetPath)}`,
		`- **Candidate Constant Matches**: ${candidates.length}`,
		"",
	];
	if (candidates.length === 0) {
		lines.push("No known cryptographic constants identified by byte signature matching.");
	} else {
		lines.push(
			"| Address | Algorithm / Constant | Match Type | Category |",
			"|---|---|---|---|",
			...candidates.map(c => `| \`${c.address}\` | \`${c.algorithm}\` | ${c.matchType} | ${c.category ?? "-"} |`),
		);
	}
	lines.push(
		"",
		"> Note: Findings represent candidate heuristic byte pattern matches from FindCrypt; they do not prove active cryptographic execution or algorithmic security.",
	);
	return lines.join("\n");
}

export class GhidraInspectTool implements AgentTool<typeof ghidraInspectSchema, GhidraInspectDetails> {
	readonly name = "ghidra_inspect";
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = args.action;
			const preview = "preview" in args ? args.preview : undefined;
			if (action === "jni_enrich" && preview === false) {
				return "exec";
			}
		}
		return "read";
	};
	readonly label = "Ghidra Inspect";
	readonly summary =
		"Headless binary analysis, decompilation, JNI dynamic registration enrichment, and FindCrypt constants analysis via Ghidra (analyzeHeadless)";
	readonly description: string;
	readonly parameters = ghidraInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	private readonly whichSeam?: SkillRequirementWhich;
	private readonly runnerSeam?: GhidraRunner;
	private readonly ghidraInstallDirSeam?: string;
	private readonly findCryptStatusSeam?: GhidraFindCryptStatus;

	constructor(
		private readonly session: ToolSession,
		options: GhidraInspectToolOptions = {},
	) {
		this.description = prompt.render(ghidraInspectDescription);
		this.whichSeam = options.which;
		this.runnerSeam = options.runner;
		this.ghidraInstallDirSeam = options.ghidraInstallDir;
		this.findCryptStatusSeam = options.findCryptStatus;
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

		// Construct headless command arguments
		let previewSummary: JniEnrichSummary | undefined;
		let eligibleItems: JniEnrichPreviewItem[] | undefined;

		if (params.action === "jni_enrich") {
			const targetSha256 = await computeFileSha256(resolvedPath);
			const targetBuf = await fs.readFile(resolvedPath);
			const elfMeta = parseElfMetadataForJni(targetBuf);

			let rawEvents: unknown = params.events;
			if (!rawEvents && params.events_path) {
				const resolvedEventsPath = resolveReadPath(params.events_path, this.session.cwd);
				try {
					const eventsJson = await fs.readFile(resolvedEventsPath, "utf8");
					rawEvents = JSON.parse(eventsJson);
				} catch (err) {
					throw new ToolError(
						`Failed to read events_path '${resolvedEventsPath}': ${err instanceof Error ? err.message : String(err)}`,
					);
				}
			}

			let records: CanonicalJniMethodRecord[] = [];
			if (Array.isArray(params.records) && params.records.length > 0) {
				records = params.records as CanonicalJniMethodRecord[];
			} else if (rawEvents) {
				let eventsList: unknown[] = [];
				if (Array.isArray(rawEvents)) {
					eventsList = rawEvents;
				} else if (typeof rawEvents === "object" && rawEvents !== null) {
					if ("events" in rawEvents && Array.isArray((rawEvents as { events: unknown[] }).events)) {
						eventsList = (rawEvents as { events: unknown[] }).events;
					} else {
						eventsList = [rawEvents];
					}
				}
				for (const ev of eventsList) {
					const canon = canonicalizeRegisterNativesEvent(ev, {
						expectedSha256: targetSha256,
					});
					records.push(...canon);
				}
			} else {
				throw new ToolError(
					"Either 'events', 'events_path', or 'records' parameter is required for action 'jni_enrich'",
				);
			}

			// Merge is_static_map across both events and records
			if (params.is_static_map && typeof params.is_static_map === "object") {
				const map = params.is_static_map as Record<string, boolean>;
				for (const rec of records) {
					if (typeof rec.isStatic !== "boolean") {
						const key1 = `${rec.className}->${rec.methodName}${rec.signature}`;
						const key2 = `${rec.methodName}${rec.signature}`;
						const key3 = rec.methodName;
						if (typeof map[key1] === "boolean") rec.isStatic = map[key1];
						else if (typeof map[key2] === "boolean") rec.isStatic = map[key2];
						else if (typeof map[key3] === "boolean") rec.isStatic = map[key3];
					}
				}
			}

			for (const rec of records) {
				if (rec.status !== "confirmed") {
					throw new ToolError(
						`Cannot enrich unconfirmed JNI method record for '${rec.className}->${rec.methodName}': status is '${rec.status}'`,
					);
				}
			}

			previewSummary = previewJniEnrichment(records, {
				staticImageBase: params.address ?? elfMeta.minLoadVaddr,
				loadBias: params.load_bias,
				arch: elfMeta.arch,
				bitness: elfMeta.bitness,
				executableRanges: elfMeta.executableRanges,
				minLoadVaddr: elfMeta.minLoadVaddr,
			});

			if (params.preview !== false) {
				const previewText = formatJniEnrichPreviewText(previewSummary, resolvedPath, targetSha256);
				return {
					content: [{ type: "text", text: previewText }],
					details: {
						action: "jni_enrich",
						path: params.path,
						status: "ok",
						mode: params.mode ?? "full",
						dependency: depStatus,
						engine: depStatus.path,
						enrichment: previewSummary,
					},
				};
			}

			// preview === false (mutating designated project)
			if (!params.project_dir) {
				throw new ToolError(
					"Applying JNI enrichment (preview: false) requires an explicit 'project_dir' parameter to persist modifications. Omit preview: false for dry-run preview, or specify 'project_dir'.",
				);
			}

			const resolvedProjDir = path.resolve(this.session.cwd, params.project_dir);
			const projectLock = getActiveGhidraProjectLock(resolvedProjDir, this.session.cwd);
			if (projectLock) {
				throw new ToolError(
					`Ghidra project directory '${params.project_dir}' is currently locked by active native MCP session '${projectLock.sessionId}'. ` +
						`Cannot mutate project simultaneously from headless analyzeHeadless. ` +
						`Use native_mcp_session(action: 'jni_enrich', session_id: '${projectLock.sessionId}') instead or disconnect the session first.`,
				);
			}

			for (const rec of records) {
				if (rec.sampleSha256 && rec.sampleSha256.toLowerCase() !== targetSha256.toLowerCase()) {
					throw new ToolError(
						`Sample SHA256 mismatch for method '${rec.methodName}': record has '${rec.sampleSha256}', but target binary has '${targetSha256}'. Refusing writeback.`,
					);
				}
				if (typeof rec.isStatic !== "boolean") {
					throw new ToolError(
						`Receiver kind for method '${rec.className}->${rec.methodName}' is unverified (must be boolean true for static or false for virtual). ` +
							"Provide explicit DEX ACC_STATIC declaration in is_static_map before writeback.",
					);
				}
			}

			eligibleItems = previewSummary.items.filter(it => it.status === "eligible");
			if (eligibleItems.length === 0) {
				throw new ToolError("No eligible confirmed JNI records to apply (all records rejected or out of bounds).");
			}
		}

		if (params.action === "findcrypt") {
			const findCryptStatus = ghidraFindCryptDependency({
				ghidraInstallDir: this.ghidraInstallDirSeam,
				findCryptStatus: this.findCryptStatusSeam,
			});
			if (!findCryptStatus.available) {
				const notice = [
					"[Notice] External Ghidra FindCrypt analyzer extension ('ghidra-findcrypt') not found on host.",
					"  -> Recommended setup: run 'reverse setup reverse ghidra-findcrypt' to install the TorgoTorgo/ghidra-findcrypt analyzer extension into Ghidra.",
					`  -> Catalog install hint: ${findCryptStatus.installHint ?? "Install ghidra-findcrypt extension"}`,
					`  -> Suggested fallback: ${fallback.suggestedFallback}`,
					"  -> Alternative options:",
					...fallback.alternatives.map(a => `     • ${a}`),
					"  (Note: Cryptographic constant analysis was not faked.)",
				].join("\n");

				return {
					content: [{ type: "text", text: notice }],
					details: {
						action: "findcrypt",
						path: params.path,
						status: "missing_dependency",
						mode: params.mode ?? "full",
						dependency: findCryptStatus,
						fallback,
					},
				};
			}
		}
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

		const isTempProject = !params.project_dir;
		const projectName = "reverse_headless_proj";
		const ghidraBinary = depStatus.path;

		const timeoutSeconds = Math.min(Math.max(1, params.timeout ?? DEFAULT_TIMEOUT_SECONDS), MAX_TIMEOUT_SECONDS);
		const maxBytes = Math.min(Math.max(1024, params.max_bytes ?? DEFAULT_MAX_BYTES), MAX_OUTPUT_BYTES);

		let tempDir: string | undefined;
		let scriptsDir: string | undefined;
		let runResult: GhidraRunResult;
		const args: string[] = [];
		const useBundledScript =
			!params.script &&
			(params.action === "decompile" ||
				params.action === "export" ||
				params.action === "jni_enrich" ||
				params.action === "findcrypt");

		try {
			tempDir = isTempProject
				? await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-headless-"))
				: path.resolve(this.session.cwd, params.project_dir!);

			if (!isTempProject) {
				await fs.mkdir(tempDir, { recursive: true });
			}

			const projectRepDir = path.join(tempDir, `${projectName}.rep`);
			const projectExists = fsSync.existsSync(projectRepDir);
			const programName = path.basename(resolvedPath);

			if (params.action === "jni_enrich") {
				if (projectExists) {
					args.push(tempDir, projectName, "-process", programName);
				} else {
					args.push(tempDir, projectName, "-import", resolvedPath);
				}
			} else {
				if (projectExists && !isTempProject) {
					args.push(tempDir, projectName, "-process", programName, "-readOnly");
				} else {
					args.push(tempDir, projectName, "-import", resolvedPath, "-readOnly");
				}
			}
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
				await fs.writeFile(
					path.join(scriptsDir, "jni_env.json"),
					typeof jniApiMetadataSource === "string"
						? jniApiMetadataSource
						: JSON.stringify(jniApiMetadataSource, null, 2),
					"utf8",
				);

				if (params.action === "jni_enrich" && eligibleItems) {
					const enrichJsonPath = path.join(scriptsDir, "enrich_items.json");
					await fs.writeFile(enrichJsonPath, JSON.stringify(eligibleItems), "utf8");
					args.push(
						"-scriptPath",
						scriptsDir,
						"-postScript",
						BUNDLED_SCRIPT_FILENAME,
						params.action,
						targetIdentifier ?? "",
						String(timeoutSeconds),
						String(maxBytes),
						enrichJsonPath,
					);
				} else {
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
		let cryptoCandidates:
			| Array<{ address: string; algorithm: string; matchType: string; category?: string }>
			| undefined;

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
						} else {
							outcomeStatus = "ok";
							if (params.action === "jni_enrich") {
								let appliedItems: Array<{ address: string; name: string; prototype: string; code: string }> =
									[];
								try {
									appliedItems = JSON.parse(payload.output || "[]");
								} catch {}
								rawText = formatJniEnrichAppliedText(
									previewSummary!,
									appliedItems,
									resolvedPath,
									params.project_dir!,
								);
							} else if (params.action === "findcrypt") {
								let candidates: Array<{
									address: string;
									algorithm: string;
									matchType: string;
									category?: string;
								}> = [];
								try {
									candidates = JSON.parse(payload.output || "[]");
								} catch {}
								cryptoCandidates = candidates;
								rawText = formatFindCryptCandidatesText(candidates, resolvedPath);
							} else if (typeof payload.output !== "string" || payload.output.trim().length === 0) {
								outcomeStatus = "error";
								outcomeError = "Ghidra decompiler produced empty output for target";
								rawText = outcomeError;
							} else {
								rawText = payload.output;
							}
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
				enrichment: previewSummary,
				cryptoCandidates,
				cryptoNotice:
					params.action === "findcrypt"
						? "Heuristic candidate locations only; byte signature match does not prove active cryptographic operations."
						: undefined,
			},
		};
	}
}

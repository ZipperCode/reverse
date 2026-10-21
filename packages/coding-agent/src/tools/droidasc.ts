import { stat } from "node:fs/promises";
import type { Stats } from "node:fs";
import { type } from "@reverse/reversetype";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { prompt } from "@reverse/utils";
import droidascDescription from "../prompts/tools/droidasc.md" with { type: "text" };
import {
	checkToolRequirements,
	type SkillRequirementWhich,
	type ToolRequirement,
} from "../extensibility/skill-requirements";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";

const droidascSchema = type({
	op: type
		.enumerated("manifest", "getmanifest", "findrefs", "getclass", "listclass")
		.describe(
			"Operation to perform: manifest/getmanifest (dump AndroidManifest.xml), findrefs (search code references), getclass (decompile single class), listclass (list all classes in DEX entries)",
		),
	target: type("string").describe("Path to target Android .apk file (droidasc directly queries APK archives)"),
	"kind?": type
		.enumerated("string", "type", "method", "field", "extends", "impl")
		.describe(
			"Reference kind for findrefs: 'string' (default), 'type', 'method', 'field', 'extends' (subclasses of class), or 'impl' (implementations of interface)",
		),
	"query?": type("string").describe("Search keyword, string reference, or symbol name for findrefs"),
	"pattern?": type("string").describe("Alias for query"),
	"name?": type("string").describe("Method or field name for findrefs method/field search (alias for query)"),
	"class?": type("string").describe(
		"Target class name to decompile for getclass, target class/interface for extends/impl, or class filter for method/field",
	),
	"className?": type("string").describe("Alias for class"),
	"fuzzy_class?": type("boolean").describe(
		"Treat class as fuzzy match for findrefs method/field search (--fuzzy-class)",
	),
	"fuzzyClass?": type("boolean").describe("Alias for fuzzy_class"),
	"prefix?": type("string").describe(
		"Optional package or class prefix filter for listclass (e.g. com.poc or Lcom/poc)",
	),
	"timeout?": type("number").describe("Execution timeout in seconds (default 30, max 120)"),
	"max_bytes?": type("number").describe(
		"Maximum stdout bytes to capture before truncation (default 262144, max 4194304)",
	),
});

export type DroidascParams = typeof droidascSchema.infer;
export type DroidascOp = "manifest" | "findrefs" | "getclass" | "listclass";
export type DroidascFindrefsKind = "string" | "type" | "method" | "field" | "extends" | "impl";
export interface DroidascDependencyStatus {
	id: "droidasc";
	available: boolean;
	path?: string;
	installHint?: string;
}

export interface DroidascFallbackInfo {
	primary: "droidasc";
	operation: DroidascOp;
	suggestedFallback: string;
	/** Alias for suggestedFallback */
	activeFallback: string;
	alternatives: string[];
	/** False to explicitly indicate that the fallback command was only suggested, not executed */
	executed: false;
}

export interface DroidascToolDetails {
	op: DroidascOp;
	target: string;
	status: "ok" | "missing_dependency" | "error";
	dependency?: DroidascDependencyStatus;
	fallback?: DroidascFallbackInfo;
	outputBytes?: number;
	truncated?: boolean;
	kind?: DroidascFindrefsKind;
	error?: string;
}

export interface DroidascRunResult {
	stdout: string;
	stderr: string;
	exitCode: number;
	outputBytes: number;
	truncated: boolean;
	timedOut: boolean;
	killedOnOverflow?: boolean;
}

export type DroidascRunner = (
	binary: string,
	args: string[],
	options: {
		cwd: string;
		timeoutMs: number;
		maxBytes: number;
		signal?: AbortSignal;
	},
) => Promise<DroidascRunResult>;

export interface DroidascToolOptions {
	which?: SkillRequirementWhich;
	runner?: DroidascRunner;
}

const DEFAULT_TIMEOUT_SECONDS = 30;
const MAX_TIMEOUT_SECONDS = 120;
const DEFAULT_MAX_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_FILE_BYTES = 1024 * 1024 * 1024; // 1 GiB

interface CappedRead {
	text: string;
	bytes: number;
	truncated: boolean;
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

export async function defaultDroidascRunner(
	binary: string,
	args: string[],
	options: {
		cwd: string;
		timeoutMs: number;
		maxBytes: number;
		signal?: AbortSignal;
	},
): Promise<DroidascRunResult> {
	const child = Bun.spawn([binary, ...args], {
		cwd: options.cwd,
		stdout: "pipe",
		stderr: "pipe",
		stdin: "ignore",
	});
	let timedOut = false;
	let killedOnOverflow = false;
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
				killedOnOverflow = true;
				child.kill();
			}),
			readCapped(child.stderr, 16 * 1024),
			child.exited,
		]);
		return {
			stdout: stdout.text,
			stderr: stderr.text,
			exitCode,
			outputBytes: stdout.bytes,
			truncated: stdout.truncated,
			timedOut,
			killedOnOverflow,
		};
	} finally {
		clearTimeout(timer);
		options.signal?.removeEventListener("abort", onAbort);
	}
}

export function droidascDependency(which?: SkillRequirementWhich): DroidascDependencyStatus {
	const requirements: ToolRequirement[] = [{ id: "droidasc" }];
	const [status] = checkToolRequirements(requirements, which ? { which } : undefined);
	const found = status?.foundPath ?? null;
	const available = found !== null;
	return {
		id: "droidasc",
		available,
		...(available && found ? { path: found } : {}),
		...(status?.hint && !available ? { installHint: status.hint } : {}),
	};
}

export function resolveDroidascFallback(
	op: DroidascOp,
	displayPath: string,
	options: {
		query?: string;
		className?: string;
		kind?: DroidascFindrefsKind;
		prefix?: string;
	} = {},
): DroidascFallbackInfo {
	switch (op) {
		case "manifest": {
			const suggested = `aapt2 dump badging "${displayPath}"`;
			return {
				primary: "droidasc",
				operation: "manifest",
				suggestedFallback: suggested,
				activeFallback: suggested,
				alternatives: [
					suggested,
					`apktool d -s "${displayPath}" -o ./artifacts/apk_manifest`,
					`unzip -p "${displayPath}" AndroidManifest.xml (raw AXML format)`,
				],
				executed: false,
			};
		}
		case "findrefs": {
			const kind = options.kind ?? "string";
			const q = options.query ?? options.className ?? "<pattern>";
			const suggested = `jadx -d ./artifacts/jadx_out "${displayPath}"`;
			return {
				primary: "droidasc",
				operation: "findrefs",
				suggestedFallback: suggested,
				activeFallback: suggested,
				alternatives: [
					`${suggested} then search decompiled sources for ${kind} "${q}"`,
					`apktool d "${displayPath}" -o ./artifacts/apk_smali then search smali files for "${q}"`,
					`dexdump -d "${displayPath}" | grep "${q}"`,
				],
				executed: false,
			};
		}
		case "getclass": {
			const c = options.className ?? "<class>";
			const suggested = `jadx -d ./artifacts/jadx_out --single-class "${c}" "${displayPath}"`;
			return {
				primary: "droidasc",
				operation: "getclass",
				suggestedFallback: suggested,
				activeFallback: suggested,
				alternatives: [
					suggested,
					`apktool d "${displayPath}" -o ./artifacts/apk_smali then inspect smali bytecode for "${c}"`,
				],
				executed: false,
			};
		}
		case "listclass": {
			const filter = options.prefix ? ` | grep "${options.prefix}"` : "";
			const suggested = `dexdump -f "${displayPath}"${filter}`;
			return {
				primary: "droidasc",
				operation: "listclass",
				suggestedFallback: suggested,
				activeFallback: suggested,
				alternatives: [
					suggested,
					`jadx --show-bad-code -d ./artifacts/jadx_out "${displayPath}"`,
					`unzip -l "${displayPath}" "classes*.dex"`,
				],
				executed: false,
			};
		}
	}
}

function formatMissingNotice(dependency: DroidascDependencyStatus, fallback: DroidascFallbackInfo): string {
	const hint = dependency.installHint ?? "pipx install droidasc or python -m pip install droidasc";
	const lines = [
		`[Notice] Primary tool 'droidasc' not found on PATH.`,
		`  -> Install hint: ${hint}`,
		`  -> Suggested fallback command: ${fallback.suggestedFallback}`,
		`  -> Alternative fallback options:`,
		...fallback.alternatives.map(alt => `     • ${alt}`),
		`  (Note: Fallback command was not executed automatically. Please invoke the suggested fallback command to proceed.)`,
	];
	return lines.join("\n");
}

function firstLine(value: string): string {
	const trimmed = value.trim();
	const newline = trimmed.indexOf("\n");
	return newline === -1 ? trimmed : trimmed.slice(0, newline).trim();
}

export class DroidascTool implements AgentTool<typeof droidascSchema, DroidascToolDetails> {
	readonly name = "droidasc";
	readonly approval: ToolTier = "read";
	readonly label = "DroidASC";
	readonly summary =
		"Lightweight Android APK query tool: extract manifest, search cross-references, list classes, and decompile single classes";
	readonly description: string;
	readonly parameters = droidascSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(
		private readonly session: ToolSession,
		private readonly options: DroidascToolOptions = {},
	) {
		this.description = prompt.render(droidascDescription);
	}

	async execute(
		_toolCallId: string,
		params: DroidascParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DroidascToolDetails>> {
		throwIfAborted(signal);
		const requestedTarget = params.target.trim();
		if (requestedTarget.length === 0) {
			throw new ToolError("target is required (path to .apk file)");
		}
		const absolutePath = resolveReadPath(requestedTarget, this.session.cwd);
		let info: Stats;
		try {
			info = await stat(absolutePath);
		} catch {
			throw new ToolError(`Target file not found: ${requestedTarget}`);
		}
		if (!info.isFile()) {
			throw new ToolError(`Not a regular file: ${requestedTarget}`);
		}
		const lowerTarget = requestedTarget.toLowerCase();
		if (lowerTarget.endsWith(".dex")) {
			throw new ToolError(
				`Target "${requestedTarget}" is a raw DEX file. droidasc requires an .apk package. For raw .dex files, use dexdump, or decompile with jadx (e.g. jadx -d ./artifacts/jadx_out "${requestedTarget}").`,
			);
		}
		if (lowerTarget.endsWith(".aab")) {
			throw new ToolError(
				`Target "${requestedTarget}" is an Android App Bundle (.aab). droidasc requires an .apk package. Convert the .aab to universal APK first using bundletool (e.g. bundletool build-apks --bundle="${requestedTarget}" --output=universal.apks --mode=universal) or analyze directly with jadx.`,
			);
		}
		if (!lowerTarget.endsWith(".apk")) {
			throw new ToolError(
				`Target "${requestedTarget}" is not an .apk file. droidasc requires an Android APK package (.apk).`,
			);
		}
		if (info.size > MAX_FILE_BYTES) {
			throw new ToolError(`Target file size (${info.size} bytes) exceeds maximum limit of ${MAX_FILE_BYTES} bytes`);
		}

		const normalizedOp: DroidascOp = params.op === "getmanifest" ? "manifest" : params.op;
		const query = params.query?.trim() || params.pattern?.trim() || params.name?.trim();
		const className = params.class?.trim() || params.className?.trim();
		const kind: DroidascFindrefsKind = params.kind ?? "string";
		const prefix = params.prefix?.trim();

		let findrefsTargetType: string | undefined;
		let findrefsTargetExtends: string | undefined;
		let findrefsTargetImpl: string | undefined;

		if (normalizedOp === "findrefs") {
			switch (kind) {
				case "string":
					if (!query || query.length === 0) {
						throw new ToolError("query is required for findrefs string search");
					}
					break;
				case "type":
					findrefsTargetType = query || className;
					if (!findrefsTargetType || findrefsTargetType.length === 0) {
						throw new ToolError("query (or class) is required for findrefs type search");
					}
					break;
				case "extends":
					findrefsTargetExtends = className || query;
					if (!findrefsTargetExtends || findrefsTargetExtends.length === 0) {
						throw new ToolError(
							"class (or query) is required for findrefs extends search (e.g. android.app.Activity)",
						);
					}
					break;
				case "impl":
					findrefsTargetImpl = className || query;
					if (!findrefsTargetImpl || findrefsTargetImpl.length === 0) {
						throw new ToolError(
							"class (or query) is required for findrefs impl search (e.g. android.os.IInterface)",
						);
					}
					break;
				case "method":
				case "field": {
					const hasMemberName = !!query && query.length > 0;
					const hasClassName = !!className && className.length > 0;
					if (!hasMemberName && !hasClassName) {
						throw new ToolError(
							`findrefs ${kind} search requires at least a member name (via query) or a target class (via class)`,
						);
					}
					break;
				}
			}
		} else if (normalizedOp === "getclass") {
			if (!className || className.length === 0) {
				throw new ToolError("class is required for getclass operation");
			}
		}

		const dependency = droidascDependency(this.options.which);
		const displayPath = requestedTarget;

		if (!dependency.available || !dependency.path) {
			const fallback = resolveDroidascFallback(normalizedOp, displayPath, {
				query,
				className,
				kind: normalizedOp === "findrefs" ? kind : undefined,
				prefix,
			});
			return {
				content: [{ type: "text", text: formatMissingNotice(dependency, fallback) }],
				details: {
					op: normalizedOp,
					target: displayPath,
					status: "missing_dependency",
					dependency,
					fallback,
					...(normalizedOp === "findrefs" ? { kind } : {}),
				},
			};
		}

		const timeoutSeconds = Math.min(
			MAX_TIMEOUT_SECONDS,
			Math.max(1, Math.floor(params.timeout ?? DEFAULT_TIMEOUT_SECONDS)),
		);
		const maxBytes = Math.min(MAX_OUTPUT_BYTES, Math.max(1, Math.floor(params.max_bytes ?? DEFAULT_MAX_BYTES)));

		let cliArgs: string[];
		switch (normalizedOp) {
			case "manifest":
				cliArgs = ["getmanifest", absolutePath];
				break;
			case "listclass":
				cliArgs = ["listclass", absolutePath];
				if (prefix && prefix.length > 0) {
					cliArgs.push("--prefix", prefix);
				}
				break;
			case "getclass":
				cliArgs = ["getclass", absolutePath, className!];
				break;
			case "findrefs": {
				cliArgs = ["findrefs", absolutePath, kind];
				switch (kind) {
					case "string":
						cliArgs.push(query!);
						break;
					case "type":
						cliArgs.push(findrefsTargetType!);
						break;
					case "extends":
						cliArgs.push(findrefsTargetExtends!);
						break;
					case "impl":
						cliArgs.push(findrefsTargetImpl!);
						break;
					case "method":
					case "field": {
						if (query && query.length > 0) {
							cliArgs.push(query);
						}
						if (className && className.length > 0) {
							cliArgs.push("--class", className);
						}
						if (params.fuzzy_class || params.fuzzyClass) {
							cliArgs.push("--fuzzy-class");
						}
						break;
					}
				}
				break;
			}
		}

		throwIfAborted(signal);
		const runner = this.options.runner ?? defaultDroidascRunner;
		let run: DroidascRunResult;
		try {
			run = await runner(dependency.path, cliArgs, {
				cwd: this.session.cwd,
				timeoutMs: timeoutSeconds * 1000,
				maxBytes,
				signal,
			});
		} catch (error) {
			throw new ToolError(`Failed to execute droidasc: ${error instanceof Error ? error.message : String(error)}`);
		}
		throwIfAborted(signal);

		if (run.timedOut) {
			const text = `droidasc timed out after ${timeoutSeconds}s for ${displayPath}. Raise timeout, or use fallback commands.`;
			return {
				content: [{ type: "text", text }],
				details: {
					op: normalizedOp,
					target: displayPath,
					status: "error",
					dependency,
					error: `timed out after ${timeoutSeconds}s`,
					...(normalizedOp === "findrefs" ? { kind } : {}),
				},
			};
		}

		const cappedSuccess = run.truncated && run.stdout.length > 0;
		if (run.exitCode !== 0 && !cappedSuccess) {
			const stderr = firstLine(run.stderr).slice(0, 400);
			const text = `droidasc failed (exit ${run.exitCode}) for ${displayPath}${stderr ? `: ${stderr}` : ""}`;
			return {
				content: [{ type: "text", text }],
				details: {
					op: normalizedOp,
					target: displayPath,
					status: "error",
					dependency,
					outputBytes: run.outputBytes,
					error: `exit ${run.exitCode}${stderr ? `: ${stderr}` : ""}`,
					...(normalizedOp === "findrefs" ? { kind } : {}),
				},
			};
		}

		const body = run.stdout.trim().length > 0 ? run.stdout : "(no output)";
		const header = `droidasc ${normalizedOp}: ${displayPath} (${run.outputBytes} bytes${run.truncated ? ", truncated" : ""})`;
		const footer = run.truncated
			? `\n… output truncated at ${maxBytes} bytes; raise max_bytes (up to ${MAX_OUTPUT_BYTES}) for more.`
			: "";

		return {
			content: [{ type: "text", text: `${header}\n${body}${footer}` }],
			details: {
				op: normalizedOp,
				target: displayPath,
				status: "ok",
				dependency,
				outputBytes: run.outputBytes,
				truncated: run.truncated,
				...(normalizedOp === "findrefs" ? { kind } : {}),
				...(run.stderr.trim().length > 0 && { error: firstLine(run.stderr).slice(0, 400) }),
			},
		};
	}
}

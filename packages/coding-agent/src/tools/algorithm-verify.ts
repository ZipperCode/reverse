import * as fs from "node:fs/promises";
import { existsSync } from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import type { ReadableStreamDefaultReader } from "node:stream/web";
import type { ChildProcess } from "@reverse/utils";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { ptree } from "@reverse/utils";
import {
	assertRealPathWithin,
	deterministicJsonStringify,
	hashFile,
	loadAnalysisExecution,
	resolveAnalysisOutputPath,
	type AnalysisFileRef,
} from "../reverse-workspace";
import type { ToolSession } from "./index";
import { writePrivateRunArtifactFile } from "./network-import";
import { throwIfAborted } from "./tool-errors";
import { approvalTargetKey } from "./approval-targets";

const executableSchema = type({
	argv: type("string[]").describe("Executable followed by literal arguments; never a shell command string"),
	"artifact_paths?": type("string[]").describe(
		"Project-local source/binary/dependency files to hash and bind; include interpreter scripts",
	),
});
const vectorSchema = type({
	id: "string",
	split: type.enumerated("exploration", "holdout"),
	input_hex: type("string").describe(
		"Exact stdin bytes as even-length hexadecimal; empty string means EOF with zero input bytes",
	),
	"context?": type("Record<string, string>").describe(
		"Case-specific reproducibility conditions, merged over common context",
	),
});

export const algorithmVerifySchema = type({
	"action?": type.enumerated("verify"),
	oracle: executableSchema,
	candidate: executableSchema,
	vectors: vectorSchema
		.array()
		.describe("1..100 explicit finite vectors; holdout is a caller label, not a secrecy guarantee"),
	context: type("Record<string, string>").describe(
		"Explicit time/randomness/session/seed assumptions; JSON is supplied identically in REVERSE_VERIFY_CONTEXT",
	),
	"cwd?": type("string").describe("Common execution directory within the project (default project root)"),
	"env?": type("Record<string, string>").describe(
		"Explicit common environment additions; inherited credentials are not forwarded",
	),
	"timeout_ms?": type("number.integer >= 10").describe(
		"Deadline per process, default 5000, maximum 30000 milliseconds",
	),
	"total_timeout_ms?": type("number.integer >= 10").describe(
		"Execution-loop deadline excluding preparation/hashing/report I/O, default 60000, maximum 120000 milliseconds",
	),
	"max_output_bytes?": type("number.integer >= 1").describe(
		"Per-stream capture limit, default 65536, maximum 1048576; overflow is incomplete, never a match",
	),
	"workflow_id?": "string",
	"step_id?": "string",
	"run_id?": "string",
	"workspace_path?": "string",
	"output_path?": type("string").describe(
		"Optional unique report path within the active analysis run; requires workflow_id, step_id, run_id",
	),
});
export type AlgorithmVerifyParams = typeof algorithmVerifySchema.infer;
type Executable = AlgorithmVerifyParams["oracle"];

export interface AlgorithmVerifyStream {
	size_bytes: number;
	observed_bytes: number;
	sha256: string;
	hash_scope: "complete" | "captured_prefix";
	preview_hex: string;
}
export interface AlgorithmVerifyProcess {
	status: "completed" | "timeout" | "cancelled" | "output_limit" | "error" | "not_run";
	exit_code: number | null;
	signal: string | null;
	stdout: AlgorithmVerifyStream;
	stderr: AlgorithmVerifyStream;
	error?: string;
}
export interface AlgorithmVerifyCase {
	id: string;
	split: "exploration" | "holdout";
	input: { size_bytes: number; sha256: string };
	context_sha256: string;
	oracle: AlgorithmVerifyProcess;
	candidate: AlgorithmVerifyProcess;
	status: "matched" | "mismatch" | "incomplete";
	exit_equal: boolean | null;
	stdout_equal: boolean | null;
	stderr_equal: boolean | null;
	first_mismatch?: {
		stream: "stdout" | "stderr";
		offset: number;
		oracle_byte: number | null;
		candidate_byte: number | null;
	};
}
interface Provenance {
	argv: string[];
	executable: { path: string; sha256: string; size_bytes: number };
	artifacts: AnalysisFileRef[];
}
export interface AlgorithmVerifyDetails {
	action: "verify";
	proof_label: "finite_vectors";
	all_vectors_matched: boolean;
	successful_output_matches: number;
	matching_error_cases: number;
	formal_equivalence_certified: false;
	independent_reproduction_certified: false;
	cases: AlgorithmVerifyCase[];
	splits: Record<"exploration" | "holdout", { total: number; matched: number; mismatch: number; incomplete: number }>;
	provenance: { oracle: Provenance; candidate: Provenance; shared_artifact_sha256: string[]; drifted_paths: string[] };
	limits: { timeout_ms: number; total_timeout_ms: number; max_output_bytes: number };
	report_path?: string;
	report_sha256?: string;
	artifact_id?: string;
	artifact_error?: string;
	limitations: string[];
}

const digest = (data: Uint8Array | string) => createHash("sha256").update(data).digest("hex");
function boundedInteger(value: number | undefined, fallback: number, max: number, name: string, min = 1): number {
	const n = value ?? fallback;
	if (!Number.isInteger(n) || n < min || n > max) throw new ToolError(`${name} must be ${min}..${max}`);
	return n;
}
function stringMap(value: Record<string, string>, name: string): void {
	if (
		!value ||
		typeof value !== "object" ||
		Array.isArray(value) ||
		Object.entries(value).some(([k, v]) => typeof v !== "string" || k.includes("\0") || v.includes("\0"))
	) {
		throw new ToolError(`${name} must contain string keys and values without NUL`);
	}
	if (Buffer.byteLength(JSON.stringify(value)) > 32768) throw new ToolError(`${name} exceeds 32768 bytes`);
}

async function prepareExecutable(spec: Executable, cwd: string, projectDir: string): Promise<Provenance> {
	if (
		!Array.isArray(spec.argv) ||
		spec.argv.length === 0 ||
		spec.argv.length > 128 ||
		spec.argv.some(a => typeof a !== "string" || a.includes("\0")) ||
		!spec.argv[0]?.trim()
	) {
		throw new ToolError("argv must be a nonempty literal string array (maximum 128 arguments, no NUL)");
	}
	if (Buffer.byteLength(JSON.stringify(spec.argv)) > 32768) throw new ToolError("argv exceeds 32768 bytes");
	const command = spec.argv[0];
	const resolved = path.isAbsolute(command)
		? command
		: command.includes("/") || command.includes("\\")
			? path.resolve(cwd, command)
			: Bun.which(command);
	if (!resolved) throw new ToolError(`Executable not found: ${command}`);
	// 系统解释器可位于项目外；工具管理的工作目录、显式产物和相对可执行文件仍受 realpath 边界约束。这不是 OS 沙箱。
	if (!path.isAbsolute(command) && (command.includes("/") || command.includes("\\"))) {
		await assertRealPathWithin(projectDir, resolved, { requireRegularFile: true });
	}
	const realExecutable = await fs.realpath(resolved);
	const executableHash = await hashFile(realExecutable);
	if (!executableHash) throw new ToolError(`Cannot hash executable: ${resolved}`);
	const shell = path
		.basename(realExecutable)
		.replace(/\.exe$/i, "")
		.toLowerCase();
	if (["sh", "bash", "zsh", "dash", "ksh", "cmd", "powershell", "pwsh"].includes(shell)) {
		throw new ToolError("Supply a local executable/interpreter argv directly, not a shell executable");
	}
	const artifactPaths = new Set(spec.artifact_paths ?? []);
	const executableRelative = path.relative(projectDir, resolved);
	if (
		executableRelative !== ".." &&
		!executableRelative.startsWith(`..${path.sep}`) &&
		!path.isAbsolute(executableRelative)
	) {
		await assertRealPathWithin(projectDir, resolved, { requireRegularFile: true });
		artifactPaths.add(resolved);
	}
	// 仅自动绑定实际存在的项目内文件参数；其他参数保持字面值，不推断参数语法或依赖闭包。
	for (const arg of spec.argv.slice(1)) {
		if (!arg || arg.startsWith("-")) continue;
		const candidate = path.resolve(cwd, arg);
		try {
			if ((await fs.stat(candidate)).isFile() && !path.relative(projectDir, candidate).startsWith(".."))
				artifactPaths.add(candidate);
		} catch {}
	}
	const artifacts: AnalysisFileRef[] = [];
	for (const artifact of artifactPaths) {
		const safe = await assertRealPathWithin(projectDir, artifact, { requireRegularFile: true });
		const hash = await hashFile(safe.realPath);
		if (!hash) throw new ToolError(`Cannot hash artifact: ${artifact}`);
		artifacts.push({ path: safe.relativePath, sha256: hash.sha256, size_bytes: hash.size });
	}
	return {
		argv: [realExecutable, ...spec.argv.slice(1)],
		executable: { path: realExecutable, sha256: executableHash.sha256, size_bytes: executableHash.size },
		artifacts,
	};
}

interface Captured {
	bytes: Buffer;
	observed: number;
	error?: string;
}
interface ProcessCapture {
	report: AlgorithmVerifyProcess;
	stdout: Buffer;
	stderr: Buffer;
}
function streamSummary(capture: Captured, complete: boolean): AlgorithmVerifyStream {
	return {
		size_bytes: capture.bytes.length,
		observed_bytes: capture.observed,
		sha256: digest(capture.bytes),
		hash_scope: complete ? "complete" : "captured_prefix",
		preview_hex: capture.bytes.subarray(0, 32).toString("hex"),
	};
}
function notRun(): ProcessCapture {
	const empty = streamSummary({ bytes: Buffer.alloc(0), observed: 0 }, false);
	return {
		report: { status: "not_run", exit_code: null, signal: null, stdout: empty, stderr: empty },
		stdout: Buffer.alloc(0),
		stderr: Buffer.alloc(0),
	};
}

async function runProcess(
	argv: string[],
	input: Buffer,
	cwd: string,
	env: Record<string, string>,
	timeout: number,
	maxBytes: number,
	signal: AbortSignal,
): Promise<ProcessCapture> {
	if (signal.aborted) return notRun();
	let child: ChildProcess;
	try {
		child = ptree.spawn(argv, {
			cwd,
			env,
			stdin: input,
			stderr: "full",
			detached: true,
			subreaper: true,
			timeout,
			signal,
		});
	} catch (error) {
		const result = notRun();
		result.report.status = "error";
		result.report.error = String(error).slice(0, 1024);
		return result;
	}
	let limited = false;
	const readerDeadline = AbortSignal.timeout(timeout);
	const readerSignal = AbortSignal.any([signal, readerDeadline]);
	const readers = [child.stdout.getReader(), child.stderr!.getReader()];
	// 复用 ptree 的进程树终止、deadline、取消和回收；这里只做有界原始字节采集，不另建 supervisor。
	const exit = child.exited.catch(() => {
		for (const reader of readers) void reader.cancel().catch(() => {});
	});
	const cancelReaders = () => {
		for (const reader of readers) void reader.cancel().catch(() => {});
	};
	readerSignal.addEventListener("abort", cancelReaders, { once: true });
	if (readerSignal.aborted) cancelReaders();
	const capture = async (reader: ReadableStreamDefaultReader<Uint8Array>): Promise<Captured> => {
		const chunks: Buffer[] = [];
		let size = 0;
		let observed = 0;
		let error: string | undefined;
		try {
			while (true) {
				const next = await reader.read();
				if (next.done) break;
				observed += next.value.byteLength;
				const prefix = Buffer.from(next.value.subarray(0, Math.max(0, maxBytes - size)));
				chunks.push(prefix);
				size += prefix.length;
				if (observed > maxBytes) {
					limited = true;
					child.kill(new ptree.AbortError("output limit", ""), -1);
					for (const r of readers) void r.cancel().catch(() => {});
					break;
				}
			}
		} catch (e) {
			error = String(e).slice(0, 1024);
		} finally {
			reader.releaseLock();
		}
		return { bytes: Buffer.concat(chunks), observed, ...(error ? { error } : {}) };
	};
	try {
		const [stdout, stderr] = await Promise.all(readers.map(capture));
		await exit;
		// wait 清除内部 deadline，并等待进程树终止完成；外部 reader 已释放，剩余管道为空。
		const outcome = await child.wait({ allowAbort: true, allowNonZero: true });
		const timedOut =
			readerDeadline.aborted ||
			outcome.exitError instanceof ptree.TimeoutError ||
			(signal.aborted && signal.reason?.name === "TimeoutError");
		const status: AlgorithmVerifyProcess["status"] = limited
			? "output_limit"
			: timedOut
				? "timeout"
				: signal.aborted
					? "cancelled"
					: stdout!.error || stderr!.error || outcome.exitError?.aborted
						? "error"
						: "completed";
		const complete = status === "completed";
		return {
			report: {
				status,
				exit_code: outcome.exitCode,
				signal: child.proc.signalCode === null ? null : String(child.proc.signalCode),
				stdout: streamSummary(stdout!, complete),
				stderr: streamSummary(stderr!, complete),
				...(!complete
					? { error: stdout!.error ?? stderr!.error ?? outcome.exitError?.message?.slice(0, 1024) ?? status }
					: {}),
			},
			stdout: stdout!.bytes,
			stderr: stderr!.bytes,
		};
	} finally {
		readerSignal.removeEventListener("abort", cancelReaders);
		child[Symbol.dispose]();
	}
}

function firstDifference(a: Buffer, b: Buffer): number | undefined {
	for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return i;
	return a.length === b.length ? undefined : Math.min(a.length, b.length);
}

export async function executeAlgorithmVerify(
	session: ToolSession,
	params: AlgorithmVerifyParams,
	signal?: AbortSignal,
): Promise<AlgorithmVerifyDetails> {
	throwIfAborted(signal);
	if (session.getPlanModeState?.()?.enabled)
		throw new ToolError(
			"Plan mode: algorithm_verify executes local programs and writes artifacts; execution requires exec approval outside plan mode.",
		);
	if (params.action !== undefined && params.action !== "verify")
		throw new ToolError("Unsupported algorithm_verify action");
	const timeout = boundedInteger(params.timeout_ms, 5000, 30000, "timeout_ms", 10);
	const totalTimeout = boundedInteger(params.total_timeout_ms, 60000, 120000, "total_timeout_ms", 10);
	const maxBytes = boundedInteger(params.max_output_bytes, 65536, 1048576, "max_output_bytes");
	stringMap(params.context, "context");
	stringMap(params.env ?? {}, "env");
	for (const key of Object.keys(params.env ?? {})) {
		if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || key.startsWith("REVERSE_VERIFY_"))
			throw new ToolError(`Invalid/reserved environment name: ${key}`);
	}
	if (!Array.isArray(params.vectors) || params.vectors.length < 1 || params.vectors.length > 100)
		throw new ToolError("vectors must contain 1..100 explicit cases");
	const ids = new Set<string>();
	let inputBytes = 0;
	const vectors = params.vectors.map(vector => {
		if (!vector.id || vector.id.length > 128 || ids.has(vector.id))
			throw new ToolError("Each vector requires a unique id of 1..128 characters");
		ids.add(vector.id);
		if (!["exploration", "holdout"].includes(vector.split))
			throw new ToolError("Each vector requires exploration or holdout split");
		if (
			typeof vector.input_hex !== "string" ||
			!/^(?:[a-fA-F0-9]{2})*$/.test(vector.input_hex) ||
			vector.input_hex.length > 2 * 1024 * 1024
		)
			throw new ToolError("input_hex must be even-length hex, at most 1 MiB per vector");
		stringMap(vector.context ?? {}, "vector context");
		const bytes = Buffer.from(vector.input_hex, "hex");
		inputBytes += bytes.length;
		return { ...vector, bytes, context: { ...params.context, ...vector.context } };
	});
	if (inputBytes > 4 * 1024 * 1024) throw new ToolError("Total vector input exceeds 4 MiB");
	const projectDir = path.resolve(session.cwd);
	const safeCwd = await assertRealPathWithin(projectDir, params.cwd ?? projectDir);
	if (!(await fs.stat(safeCwd.resolvedPath)).isDirectory())
		throw new ToolError("cwd must be a project-local directory");
	const oracle = await prepareExecutable(params.oracle, safeCwd.resolvedPath, projectDir);
	const candidate = await prepareExecutable(params.candidate, safeCwd.resolvedPath, projectDir);
	const identifiers = [params.workflow_id, params.step_id, params.run_id];
	if (identifiers.some(Boolean) && !identifiers.every(Boolean))
		throw new ToolError("workflow_id, step_id, run_id must be supplied together");
	if (params.output_path && !identifiers.every(Boolean))
		throw new ToolError("output_path requires an active analysis run");
	const execution = identifiers.every(Boolean)
		? await loadAnalysisExecution({
				projectDir,
				workspaceDir: params.workspace_path,
				workflowId: params.workflow_id!,
				stepId: params.step_id!,
				runId: params.run_id!,
				inputPaths: [...new Set([...oracle.artifacts, ...candidate.artifacts].map(a => a.path))],
			})
		: undefined;
	const reportOut = execution
		? await resolveAnalysisOutputPath({
				projectDir,
				runDir: execution.paths.run_dir,
				outputPath:
					params.output_path ??
					path.join(execution.paths.reports_dir, `algorithm_verify_${Bun.randomUUIDv7()}.json`),
			})
		: undefined;
	const executionSignal = AbortSignal.any([...(signal ? [signal] : []), AbortSignal.timeout(totalTimeout)]);
	const inheritedDefaults: Record<string, string> = {
		PATH: process.env.PATH ?? "",
		LANG: "C",
		LC_ALL: "C",
		TZ: "UTC",
	};
	for (const key of ["SystemRoot", "WINDIR", "TMPDIR", "TEMP", "TMP"])
		if (process.env[key] !== undefined) inheritedDefaults[key] = process.env[key]!;
	const env = { ...inheritedDefaults, ...params.env };
	const cases: AlgorithmVerifyCase[] = [];
	for (const vector of vectors) {
		const context = deterministicJsonStringify(vector.context, 0);
		const caseEnv = { ...env, REVERSE_VERIFY_CONTEXT: context };
		const left = await runProcess(
			oracle.argv,
			vector.bytes,
			safeCwd.resolvedPath,
			caseEnv,
			timeout,
			maxBytes,
			executionSignal,
		);
		const right = await runProcess(
			candidate.argv,
			vector.bytes,
			safeCwd.resolvedPath,
			caseEnv,
			timeout,
			maxBytes,
			executionSignal,
		);
		const complete = left.report.status === "completed" && right.report.status === "completed";
		const stdoutOffset = firstDifference(left.stdout, right.stdout);
		const stderrOffset = firstDifference(left.stderr, right.stderr);
		const stream = stdoutOffset !== undefined ? "stdout" : "stderr";
		const offset = stdoutOffset ?? stderrOffset;
		const exitEqual = complete
			? left.report.exit_code === right.report.exit_code && left.report.signal === right.report.signal
			: null;
		cases.push({
			id: vector.id,
			split: vector.split,
			input: { size_bytes: vector.bytes.length, sha256: digest(vector.bytes) },
			context_sha256: digest(context),
			oracle: left.report,
			candidate: right.report,
			status: !complete ? "incomplete" : exitEqual && offset === undefined ? "matched" : "mismatch",
			exit_equal: exitEqual,
			stdout_equal: complete ? stdoutOffset === undefined : null,
			stderr_equal: complete ? stderrOffset === undefined : null,
			...(complete && offset !== undefined
				? {
						first_mismatch: {
							stream,
							offset,
							oracle_byte: left[stream][offset] ?? null,
							candidate_byte: right[stream][offset] ?? null,
						},
					}
				: {}),
		});
	}
	const splits: AlgorithmVerifyDetails["splits"] = {
		exploration: { total: 0, matched: 0, mismatch: 0, incomplete: 0 },
		holdout: { total: 0, matched: 0, mismatch: 0, incomplete: 0 },
	};
	for (const result of cases) {
		splits[result.split].total++;
		splits[result.split][result.status]++;
	}
	const driftedPaths: string[] = [];
	for (const provenance of [oracle, candidate]) {
		for (const file of [
			{ path: provenance.executable.path, sha256: provenance.executable.sha256 },
			...provenance.artifacts,
		]) {
			if ((await hashFile(path.resolve(projectDir, file.path)))?.sha256 !== file.sha256)
				driftedPaths.push(file.path);
		}
	}
	const shared = oracle.artifacts.filter(a => candidate.artifacts.some(b => b.sha256 === a.sha256)).map(a => a.sha256);
	const details: AlgorithmVerifyDetails = {
		action: "verify",
		proof_label: "finite_vectors",
		all_vectors_matched: cases.every(c => c.status === "matched") && driftedPaths.length === 0,
		formal_equivalence_certified: false,
		independent_reproduction_certified: false,
		cases,
		splits,
		successful_output_matches: cases.filter(
			c => c.status === "matched" && c.oracle.exit_code === 0 && c.oracle.signal === null,
		).length,
		matching_error_cases: cases.filter(
			c => c.status === "matched" && (c.oracle.exit_code !== 0 || c.oracle.signal !== null),
		).length,
		provenance: {
			oracle,
			candidate,
			shared_artifact_sha256: [...new Set(shared)],
			drifted_paths: [...new Set(driftedPaths)],
		},
		limits: { timeout_ms: timeout, total_timeout_ms: totalTimeout, max_output_bytes: maxBytes },
		limitations: [
			"Finite supplied vectors only; no formal equivalence, determinism, side-effect equality, or independent reproduction certification.",
			"Holdout is a caller-supplied split label, not hidden-to-agent secrecy. Matching nonzero exits are matching error behavior, not successful algorithm outputs.",
			"Separate bounded processes are not a sandbox or network isolation. Programs may access network/files and invoke the original binary; argv/file hashes do not establish a complete dependency closure.",
			"stdin, stdout and stderr are exact bytes. Context is supplied identically in REVERSE_VERIFY_CONTEXT; programs must actually consume declared time/randomness/session assumptions.",
			"total_timeout_ms bounds only the subprocess execution loop, excluding preparation/provenance hashing and report I/O.",
		],
	};
	const report = `${deterministicJsonStringify({ ...details, cwd: safeCwd.resolvedPath, env, context: params.context, vectors: params.vectors, ...(execution ? { workflow_id: params.workflow_id, step_id: params.step_id, run_id: params.run_id } : {}) })}\n`;
	if (reportOut) {
		const written = await writePrivateRunArtifactFile(reportOut.resolvedPath, report);
		details.report_path = reportOut.relativePath;
		details.report_sha256 = written.sha256;
	} else if (session.allocateOutputArtifact) {
		try {
			const artifact = await session.allocateOutputArtifact("algorithm_verify");
			if (artifact.path) {
				await fs.writeFile(artifact.path, report, { mode: 0o600 });
				await fs.chmod(artifact.path, 0o600);
				details.artifact_id = artifact.id;
				details.report_sha256 = digest(report);
			}
		} catch (error) {
			details.artifact_error = String(error).slice(0, 1024);
		}
	}
	return details;
}

export class AlgorithmVerifyTool implements AgentTool<typeof algorithmVerifySchema, AlgorithmVerifyDetails> {
	readonly name = "algorithm_verify";
	readonly label = "Algorithm Verify";
	readonly summary =
		"Execute a local oracle and candidate on explicit finite input vectors and compare raw output and exit behavior";
	readonly description = `Deterministic finite-vector differential verification via approved local executable argv (not shell strings). Supply oracle/candidate {argv, artifact_paths?}, explicit vectors [{id, split: 'exploration'|'holdout', input_hex, context?}], and common context (time/randomness/session/seed assumptions). Each process receives identical raw stdin bytes, EOF, common cwd/env and REVERSE_VERIFY_CONTEXT JSON. Default environment is PATH plus platform temp/system variables and LANG=C, LC_ALL=C, TZ=UTC; additional env is explicit. Every vector launches oracle then candidate in separate bounded processes; stdout AND stderr bytes, exit codes and signals are compared exactly. Nonzero exit equality is error-behavior equality, not algorithm success. Timeout, cancellation, capture overflow and spawn/read errors are incomplete, never matches. Reports include lengths, SHA-256 digests/prefix scopes, first mismatch byte (zero-based, null byte means EOF), executable/artifact hashes, split totals and drift checks. artifact_paths binds project-local scripts/dependencies; existing local file arguments are also hashed. cwd and managed artifacts remain project-confined, but programs are NOT sandboxed or network-isolated; this tool has no HTTP/live-target feature. Identical outputs never certify formal equivalence or candidate independence (a candidate can call the original binary). Holdout labels do not imply secret unseen-to-agent data. Optional workflow_id/step_id/run_id bind inputs and a private report to an active reverse_workspace run; otherwise a private session report is saved when artifact allocation is available. All invocations require exec approval; plan mode blocks execution.`;
	readonly parameters = algorithmVerifySchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approval = (_args: unknown): ToolTier => "exec";
	readonly approvalCacheTargets = (args: unknown): readonly string[] => {
		const paths = this.approvalRestrictionPaths(args);
		return paths.map(p => approvalTargetKey(this.session.cwd, p)).filter((p): p is string => p !== undefined);
	};
	readonly approvalRestrictionPaths = (args: unknown): readonly string[] => {
		const input = args && typeof args === "object" ? (args as Record<string, unknown>) : {};
		const cwd = path.resolve(this.session.cwd, typeof input.cwd === "string" ? input.cwd : ".");
		const paths = new Set([cwd]);
		if (typeof input.output_path === "string") paths.add(path.resolve(this.session.cwd, input.output_path));
		for (const key of ["oracle", "candidate"]) {
			const spec = input[key];
			if (!spec || typeof spec !== "object") continue;
			const fields = spec as Record<string, unknown>;
			if (Array.isArray(fields.artifact_paths))
				for (const value of fields.artifact_paths) {
					if (typeof value === "string") paths.add(path.resolve(this.session.cwd, value));
				}
			if (!Array.isArray(fields.argv)) continue;
			for (const [index, value] of fields.argv.entries()) {
				if (typeof value !== "string" || !value || value.startsWith("-")) continue;
				const resolved =
					index === 0 && !value.includes("/") && !value.includes("\\")
						? Bun.which(value)
						: path.resolve(cwd, value);
				if (resolved && (index === 0 || existsSync(resolved))) paths.add(resolved);
			}
		}
		return [...paths];
	};
	constructor(private readonly session: ToolSession) {}
	async execute(
		_id: string,
		params: AlgorithmVerifyParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AlgorithmVerifyDetails> & { details: AlgorithmVerifyDetails }> {
		const details = await executeAlgorithmVerify(this.session, params, signal);
		const counts = details.cases.reduce(
			(out, c) => {
				out[c.status]++;
				return out;
			},
			{ matched: 0, mismatch: 0, incomplete: 0 },
		);
		const matchKinds = `${details.successful_output_matches} successful-output matches; ${details.matching_error_cases} matching error cases (not algorithm successes)`;
		return {
			details,
			content: [
				{
					type: "text",
					text: `Finite-vector verification: ${counts.matched}/${details.cases.length} matched; ${counts.mismatch} mismatched; ${counts.incomplete} incomplete.\n${matchKinds}.\nExploration: ${details.splits.exploration.matched}/${details.splits.exploration.total}; holdout: ${details.splits.holdout.matched}/${details.splits.holdout.total}.\nFormal equivalence: not certified. Independent reproduction: not certified.${details.report_path ? `\nReport: ${details.report_path}` : details.artifact_id ? `\nReport: artifact://${details.artifact_id}` : ""}\n${details.cases
						.filter(c => c.status !== "matched")
						.slice(0, 10)
						.map(
							c =>
								`${c.id}: ${c.status} (${c.oracle.status}/${c.candidate.status})${c.first_mismatch ? ` ${c.first_mismatch.stream} byte ${c.first_mismatch.offset}` : ""}`,
						)
						.join("\n")}`,
				},
			],
		};
	}
}

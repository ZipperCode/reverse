/**
 * Bounded Native Recovery and Verification Tool (native_recover).
 *
 * Provides bounded symbolic path exploration (DSE worklist), handler semantic slicing,
 * path-predicate guarded multi-path merge with solver consistency checks, LLVM IR lifting,
 * and dual-execution differential verification using Triton, Z3, and llvmlite.
 *
 * 核心设计约束：
 * 1. 解释器隔离：通过 resolveVmpTool("triton") 解析专用 Python 环境。
 * 2. 审批层与 Plan Mode：status 归为 read 层并在 Plan Mode 开放；explore/handlers/merge/verify 归为 write 层并在 Plan Mode 拦截。
 * 3. 严格有界符号执行：显式机器快照（段地址+字节、初始寄存器、停机地址、符号输入与种子），严禁无界或伪造全函数等价。
 * 4. 严禁伪造输入域：合并时显式校验域重叠一致性与未覆盖域，产物保留 SMT2 守卫，无隐式默认分支。
 * 5. 真实双向验证：独立运行机器码快照与恢复表达式，比对返回值与声明的内存副作用，明确区分有限向量与 SMT 形式证明标签。
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import { filterEnv } from "../eval/py/runtime";
import { resolveVmpTool } from "../extensibility/vmp-toolchain";
import nativeRecoverDescription from "../prompts/tools/native-recover.md" with { type: "text" };
import { saveArtifactText } from "./gh-common";
import type { ToolSession } from "./index";
import { throwIfAborted } from "./tool-errors";

// Staged text assets for Native Recover Python workers
import nativeRecoverWorkerSource from "./native-recover-worker.py" with { type: "text" };
import nativeRecoverVerifySource from "./native-recover-verify.py" with { type: "text" };
// ============================================================================
// Schemas
// ============================================================================

const snapshotSegmentSchema = type({
	address: type("string | number").describe("Segment virtual address in hex string or integer"),
	bytes: type("string").describe("Raw machine code or data bytes as a hex string"),
	"permissions?": type("string").describe("Optional memory permissions (e.g. 'r-x', 'rw-')"),
});

const symbolicInputSchema = type({
	"kind?": type.enumerated("register", "memory").describe("Input kind: 'register' or 'memory' (default: 'register')"),
	"name?": type("string").describe("Register name if kind='register' (e.g. 'rdi', 'x0', 'r0')"),
	"address?": type("string | number").describe("Memory address if kind='memory'"),
	"size?": type("number.integer >= 1").describe("Byte size if kind='memory' (1, 2, 4, 8; default: 4)"),
	"alias?": type("string").describe("Symbolic variable alias for AST formulas (e.g. 'arg0', 'x')"),
	seed: type("string | number").describe("Concrete seed value for concolic execution"),
	"min?": type("string | number").describe("Optional domain minimum bound"),
	"max?": type("string | number").describe("Optional domain maximum bound"),
});

const recoveryOutputSchema = type({
	kind: "'register'",
	target: "string",
}).or({
	kind: "'memory'",
	address: "string | number",
	"size?": "number.integer >= 1",
});

const boundedSnapshotSchema = type({
	arch: type.enumerated("x86", "x86_64", "arm32", "aarch64").describe("Target architecture"),
	entry: type("string | number").describe("Entry instruction address in hex string or integer"),
	stop_addresses: type("string | number")
		.array()
		.describe("Array of stop/exit addresses that terminate path execution"),
	registers: type({
		"[string]": "string | number",
	}).describe("Initial concrete register state (e.g. { rip: '0x401000', rsp: '0x7ffffff0' })"),
	segments: snapshotSegmentSchema.array().describe("Explicit bounded memory segments"),
	symbolic_inputs: symbolicInputSchema.array().describe("Declared symbolic input definitions"),
	output: recoveryOutputSchema.describe("Target output specification"),
	"thumb?": type("boolean").describe("Enable Thumb execution mode for ARM32"),
});

const recoveryBoundsSchema = type({
	"branch_budget?": type("number.integer >= 1").describe(
		"Maximum paths to explore via branch inversion (default: 20)",
	),
	"max_instructions?": type("number.integer >= 1").describe(
		"Maximum instructions per path before halting (default: 5000)",
	),
	"max_depth?": type("number.integer >= 1").describe("Maximum branch depth to invert (default: 50)"),
	"timeout_ms?": type("number.integer >= 1000").describe("Maximum execution timeout in milliseconds (default: 60000)"),
});

// Action schemas
const recoverStatusSchema = type({
	action: "'status'",
});

const recoverExploreSchema = type({
	action: "'explore'",
	snapshot: boundedSnapshotSchema.describe("Bounded machine snapshot for concolic DSE exploration"),
	"bounds?": recoveryBoundsSchema,
});

const recoverHandlersSchema = type({
	action: "'handlers'",
	snapshot: boundedSnapshotSchema.describe("Bounded machine snapshot or base environment"),
	"arch?": type.enumerated("x86", "x86_64", "arm32", "aarch64"),
	range: type({
		start: type("string | number").describe("Starting address of handler"),
		stop: type("string | number").describe("Stop address of handler"),
	}).describe("Explicit address range of the handler routine"),
	inputs: symbolicInputSchema.array().describe("Declared symbolic inputs"),
	output: recoveryOutputSchema.describe("Target output specification"),
	"bounds?": type({
		"max_instructions?": type("number.integer >= 1"),
	}),
	"synthesize?": type("boolean").describe("Attempt formula simplification via Triton AST synthesizer (default: true)"),
});

const recoverMergeSchema = type({
	action: "'merge'",
	paths: type({
		"path_id?": type("string | number"),
		predicate: type("string").describe("Path predicate condition formula (SMT2 or AST string)"),
		output_ast: type("string").describe("Output expression formula (SMT2 or AST string)"),
		"status?": type("string"),
	})
		.array()
		.describe("Array of path conditions and output formulas to merge"),
	inputs: type({
		name: type("string"),
		size_bits: type("number.integer >= 1"),
	})
		.array()
		.describe("Input variable signatures with bitwidths"),
	"output_size_bits?": type("number.integer >= 1").describe("Output bitwidth (default: 32)"),
	"arch?": type.enumerated("x86", "x86_64", "arm32", "aarch64"),
});

const recoverVerifySchema = type({
	action: "'verify'",
	snapshot: boundedSnapshotSchema.describe("Original bounded machine snapshot"),
	recovered: type({
		kind: type.enumerated("smt2", "ast", "llvm_ir"),
		"expression?": type("string").describe("Recovered SMT2 or AST formula"),
		"llvm_ir?": type("string").describe("Recovered LLVM IR text"),
		inputs: type({
			name: type("string"),
			size_bits: type("number.integer >= 1"),
			"reg?": type("string"),
			"kind?": type.enumerated("register", "memory"),
			"address?": type("string | number"),
			"size?": type("number.integer >= 1"),
			"min?": type("string | number"),
			"max?": type("string | number"),
		})
			.array()
			.describe("Input parameters with register or memory bindings"),
		output: recoveryOutputSchema,
		"domain_predicate?": type("string").describe("Optional domain predicate restricting candidate validity"),
		"domain_guard?": type("string").describe("Optional serialized domain guard"),
		"memory_side_effects?": type({
			address: type("string | number"),
			size: type("number.integer >= 1"),
			"condition?": type("string"),
			value: type("string | number"),
			"else_value?": type("string | number"),
		})
			.array()
			.describe("Expected memory writes under specific path conditions"),
		"strict_memory_check?": type("boolean").describe(
			"Reject unexpected unmodeled memory stores from original snapshot (default: false)",
		),
	}).describe("Recovered candidate formula or artifact"),
	"vectors?": type({
		"[string]": "string | number",
	})
		.array()
		.describe("User-supplied concrete test vectors"),
	"test_generation?": type({
		"boundary?": type("boolean").describe("Generate boundary test vectors (default: true)"),
		"random_count?": type("number.integer >= 0").describe("Generate N random test vectors (default: 10)"),
		"seed?": type("number.integer").describe("Random seed for reproducible vector generation"),
	}),
	"proof_mode?": type
		.enumerated("finite_vectors", "smt_formal", "both")
		.describe("Verification proof rigor mode (default: 'both')"),
	"bounds?": recoveryBoundsSchema.describe("Optional exploration and execution bounds"),
});

export const nativeRecoverSchema = recoverStatusSchema
	.or(recoverExploreSchema)
	.or(recoverHandlersSchema)
	.or(recoverMergeSchema)
	.or(recoverVerifySchema);

export type NativeRecoverParams = typeof nativeRecoverSchema.infer;

// ============================================================================
// Details Model
// ============================================================================

export interface NativeRecoverDetails {
	action: "status" | "explore" | "handlers" | "merge" | "verify";
	installed: boolean;
	python_path?: string | null;
	triton_version?: string | null;
	supported_architectures?: string[];
	solver?: {
		available: boolean;
		engine?: string | null;
		solvers?: string[];
		reason?: string | null;
	};
	llvm?: {
		available: boolean;
		status: string;
	};
	llvmlite?: {
		available: boolean;
		version?: string | null;
	};
	install_hint?: string | null;
	merged_paths_count?: number;
	// explore results
	discovered_paths_count?: number;
	discovered_paths?: Array<{
		path_id: number;
		seed: Record<string, number | string>;
		instructions_executed: number;
		concrete_return?: string | null;
		path_predicate?: string | null;
		output_ast?: string | null;
		memory_writes?: Array<{
			address: string;
			size: number;
			value: string;
			value_ast?: string | null;
		}>;
		status: string;
		visited_edges?: Array<{ from: string; to: string }>;
	}>;
	coverage?: {
		branches_seen: number;
		branches_inverted: number;
		incomplete_frontier: Array<Record<string, unknown>>;
		all_visited_edges: string[];
	};
	// handlers results
	handler_range?: { start: string; stop: string };
	handler_completed?: boolean;
	handler_status?: string;
	path_predicate?: string | null;
	transition_formula?: string | null;
	synth_formula?: string | null;
	data_dependencies?: string[];
	memory_side_effects?: Array<{ address: string; size: number; value: string }>;
	// merge results
	is_total_domain?: boolean;
	coverage_guard?: {
		is_total: boolean;
		uncovered_sample?: Record<string, unknown> | null;
	};
	conflicts?: Array<{ path_a: string | number; path_b: string | number; model: Record<string, unknown> }>;
	smt2_formula_artifact_id?: string | null;
	smt2_formula_file_path?: string | null;
	llvm_ir_artifact_id?: string | null;
	llvm_ir_file_path?: string | null;
	// verify results
	proof_mode?: "finite_vectors" | "smt_formal" | "both";
	passed_count?: number;
	total_count?: number;
	agreement_pct?: number;
	counterexamples?: Array<{
		input: Record<string, string | number>;
		original_return?: string | null;
		recovered_return?: string | null;
		original_memory_writes?: Array<{ address: string; size: number; value: string; value_ast?: string | null }>;
		expected_memory_writes?: Array<{ address: string; size: number; value: string }>;
		mismatch_reason: string;
	}>;
	out_of_domain_vectors?: Array<Record<string, string | number>>;
	proof_label?: string;
	assurance_level_recommendation?: string;
	error?: string;
	smt_formal_proved?: boolean;
	formal_proof_scope?: "full_algorithm" | "return_only" | null;
	side_effects_proved?: boolean;
	uncovered_domain_sample?: Record<string, string | number> | null;
}

// ============================================================================
// Worker Invocation & Subprocess Execution
// ============================================================================

const MAX_STDOUT_BYTES = 16 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60000;
const MANAGED_INSTALL_HINT = "Run 'reverse setup reverse triton --execute' to install the managed Triton toolchain.";

interface WorkerBaseResult<T> {
	status: "ok" | "missing_dependency" | "error";
	result?: T;
	error?: string;
}

async function runNativeRecoverWorker<T>(options: {
	pythonPath: string;
	cwd: string;
	request: unknown;
	signal?: AbortSignal;
	timeoutMs?: number;
}): Promise<WorkerBaseResult<T>> {
	if (options.signal?.aborted) {
		return { status: "error", error: "Operation cancelled before execution." };
	}

	const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "reverse-recover-"));
	const workerFile = path.join(tempDir, "native-recover-worker.py");

	try {
		await fs.promises.writeFile(workerFile, nativeRecoverWorkerSource, "utf-8");
		const verifyFile = path.join(tempDir, "native-recover-verify.py");
		await fs.promises.writeFile(verifyFile, nativeRecoverVerifySource, "utf-8");

		const childEnv: Record<string, string | undefined> = {
			...filterEnv(process.env as Record<string, string | undefined>),
			PYTHONUNBUFFERED: "1",
			PYTHONDONTWRITEBYTECODE: "1",
		};

		const isVerify =
			typeof options.request === "object" &&
			options.request !== null &&
			(options.request as Record<string, unknown>).action === "verify";
		const entryScript = isVerify ? verifyFile : workerFile;

		const child = Bun.spawn([options.pythonPath, "-u", entryScript], {
			stdin: "pipe",
			stdout: "pipe",
			stderr: "pipe",
			env: childEnv,
		});

		const reqJson = JSON.stringify(options.request);
		const stdinWriter = child.stdin;
		stdinWriter.write(reqJson);
		stdinWriter.flush();
		stdinWriter.end();

		const timeoutLimit = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			try {
				child.kill();
			} catch {}
		}, timeoutLimit);

		const abortListener = () => {
			try {
				child.kill();
			} catch {}
		};
		options.signal?.addEventListener("abort", abortListener, { once: true });

		const stdoutChunks: Uint8Array[] = [];
		const reader = child.stdout.getReader();
		let totalBytes = 0;
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (value) {
				totalBytes += value.byteLength;
				stdoutChunks.push(value);
				if (totalBytes > MAX_STDOUT_BYTES) {
					try {
						child.kill();
					} catch {}
					break;
				}
			}
		}

		clearTimeout(timer);
		options.signal?.removeEventListener("abort", abortListener);
		await child.exited;

		if (timedOut) {
			return { status: "error", error: `Execution timed out after ${timeoutLimit}ms.` };
		}
		if (options.signal?.aborted) {
			return { status: "error", error: "Execution aborted by caller signal." };
		}

		const merged = new Uint8Array(stdoutChunks.reduce((acc, c) => acc + c.byteLength, 0));
		let offset = 0;
		for (const c of stdoutChunks) {
			merged.set(c, offset);
			offset += c.byteLength;
		}
		const outText = new TextDecoder().decode(merged).trim();
		if (!outText) {
			return { status: "error", error: "Worker returned empty output on stdout." };
		}

		try {
			return JSON.parse(outText) as WorkerBaseResult<T>;
		} catch (e) {
			return { status: "error", error: `Failed to parse worker response as JSON: ${String(e)}` };
		}
	} finally {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	}
}

async function persistRecoverArtifact(
	session: ToolSession,
	category: string,
	content: string,
): Promise<{ artifactId?: string; filePath?: string; reference: string }> {
	const artifactId = await saveArtifactText(session, "native_recover", content).catch(() => undefined);
	if (artifactId) {
		return { artifactId, reference: `artifact://${artifactId}` };
	}
	const outputDir = path.join(session.cwd, "artifacts", "native_recover");
	await fs.promises.mkdir(outputDir, { recursive: true });
	const hash = crypto.createHash("sha256").update(content).digest("hex").slice(0, 12);
	const filePath = path.join(outputDir, `${category}-${Date.now()}-${hash}.txt`);
	await fs.promises.writeFile(filePath, content, "utf-8");
	return { filePath, reference: filePath };
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class NativeRecoverTool implements AgentTool<typeof nativeRecoverSchema, NativeRecoverDetails> {
	readonly name = "native_recover";
	readonly label = "Native Recover";
	readonly summary =
		"Bounded symbolic path exploration, handler semantic slicing, path-guarded merge, and differential verification";
	readonly description: string;
	readonly parameters = nativeRecoverSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			if (args.action === "status") {
				return "read";
			}
			if (args.action === "merge") {
				return "write";
			}
			if (args.action === "explore" || args.action === "handlers" || args.action === "verify") {
				return "exec";
			}
		}
		return "exec";
	};

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(nativeRecoverDescription);
	}

	async execute(
		_toolCallId: string,
		params: NativeRecoverParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<NativeRecoverDetails> & { details: NativeRecoverDetails }> {
		throwIfAborted(signal);

		const planMode = this.session.getPlanModeState?.();
		if (planMode?.enabled && params.action !== "status") {
			throw new ToolError(
				"Plan mode: native recovery actions (explore, handlers, merge, verify) execute symbolic emulation and write artifacts. Only 'status' is permitted in plan mode.",
			);
		}

		const pythonPath = resolveVmpTool("triton", {
			env: process.env,
			platform: process.platform,
		});

		// --------------------------------------------------------------------
		// Action: status
		// --------------------------------------------------------------------
		if (params.action === "status") {
			if (!pythonPath) {
				const details: NativeRecoverDetails = {
					action: "status",
					installed: false,
					python_path: null,
					triton_version: null,
					install_hint: MANAGED_INSTALL_HINT,
				};
				const text = [
					"Native Recover Engine Status: Not Available",
					"- Installed: false",
					"- Python: No managed Triton Python interpreter found.",
					`- Hint: ${details.install_hint}`,
				].join("\n");
				return { content: [{ type: "text", text }], details };
			}

			const workerRes = await runNativeRecoverWorker<{
				installed: boolean;
				python_path: string;
				python_version: string;
				triton_version: string | null;
				supported_architectures: string[];
				solver: { available: boolean; engine: string | null; solvers: string[]; reason?: string | null };
				llvm: { available: boolean; status: string };
				llvmlite: { available: boolean; version?: string | null };
				synthesizer: { available: boolean; reason?: string | null };
				install_hint: string;
			}>({
				pythonPath,
				cwd: this.session.cwd,
				request: { action: "status" },
				signal,
				timeoutMs: 10000,
			});

			if (workerRes.status === "error" || !workerRes.result) {
				throw new ToolError(workerRes.error || "Failed to probe Native Recover engine status.");
			}

			const r = workerRes.result;
			const details: NativeRecoverDetails = {
				action: "status",
				installed: r.installed,
				python_path: r.python_path,
				triton_version: r.triton_version,
				supported_architectures: r.supported_architectures,
				solver: r.solver,
				llvm: r.llvm,
				llvmlite: r.llvmlite,
				install_hint: r.install_hint,
			};

			const text = [
				`Native Recover Engine: ${r.installed ? "Available" : "Not Installed"}`,
				`- Triton: ${r.triton_version ?? "unknown"} (${r.python_path})`,
				`- Architectures: ${(r.supported_architectures || []).join(", ") || "none"}`,
				`- SMT Solver: ${r.solver.available ? `${r.solver.engine ?? "Z3"} (Solvers: ${r.solver.solvers.join(", ")})` : "unavailable"}`,
				`- LLVM / llvmlite: ${r.llvm.status}`,
			].join("\n");

			return { content: [{ type: "text", text }], details };
		}

		if (!pythonPath) {
			throw new ToolError(`Triton is not installed or configured in this environment. ${MANAGED_INSTALL_HINT}`);
		}

		// --------------------------------------------------------------------
		// Action: explore
		// --------------------------------------------------------------------
		if (params.action === "explore") {
			const workerRes = await runNativeRecoverWorker<{
				arch: string;
				discovered_paths: Array<{
					path_id: number;
					seed: Record<string, number | string>;
					instructions_executed: number;
					concrete_return: string | null;
					path_predicate: string | null;
					output_ast: string | null;
					memory_writes?: Array<{
						address: string;
						size: number;
						value: string;
						value_ast?: string | null;
					}>;
					status: string;
					visited_edges?: Array<{ from: string; to: string }>;
				}>;
				coverage: {
					discovered_paths_count: number;
					branches_seen: number;
					branches_inverted: number;
					incomplete_frontier: Array<Record<string, unknown>>;
					all_visited_edges: string[];
				};
			}>({
				pythonPath,
				cwd: this.session.cwd,
				request: {
					action: "explore",
					snapshot: params.snapshot,
					bounds: params.bounds,
				},
				signal,
				timeoutMs: params.bounds?.timeout_ms ?? DEFAULT_TIMEOUT_MS,
			});

			if (workerRes.status === "error" || !workerRes.result) {
				throw new ToolError(workerRes.error || "Path exploration failed.");
			}

			const r = workerRes.result;
			let exploreArtifactId: string | undefined;
			let exploreFilePath: string | undefined;
			try {
				const persisted = await persistRecoverArtifact(this.session, "explore-paths", JSON.stringify(r, null, 2));
				exploreArtifactId = persisted.artifactId;
				exploreFilePath = persisted.filePath;
			} catch {}

			const details: NativeRecoverDetails = {
				action: "explore",
				installed: true,
				discovered_paths_count: r.coverage.discovered_paths_count,
				discovered_paths: r.discovered_paths,
				coverage: r.coverage,
			};

			const lines = [
				`Bounded Symbolic Exploration (${r.arch}):`,
				`- Discovered Paths: ${r.coverage.discovered_paths_count}`,
				`- Branches Seen: ${r.coverage.branches_seen}, Inverted: ${r.coverage.branches_inverted}`,
				`- Incomplete Frontier: ${r.coverage.incomplete_frontier.length} untraversed branch targets`,
				`- Unique Edges Visited: ${r.coverage.all_visited_edges.length}`,
				exploreArtifactId
					? `- Full Exploration Artifact: artifact://${exploreArtifactId}`
					: exploreFilePath
						? `- Saved: ${exploreFilePath}`
						: null,
			].filter(Boolean) as string[];

			for (const p of r.discovered_paths) {
				lines.push(`  * Path #${p.path_id} (${p.status}):`);
				lines.push(`    - Seed: ${JSON.stringify(p.seed)}`);
				if (p.concrete_return !== null) {
					lines.push(`    - Return: ${p.concrete_return}`);
				}
				if (p.path_predicate) {
					lines.push(`    - Predicate: ${p.path_predicate}`);
				}
				if (p.output_ast) {
					lines.push(`    - Output AST: ${p.output_ast}`);
				}
			}

			return { content: [{ type: "text", text: lines.join("\n") }], details };
		}

		// --------------------------------------------------------------------
		// Action: handlers
		// --------------------------------------------------------------------
		if (params.action === "handlers") {
			const workerRes = await runNativeRecoverWorker<{
				completed: boolean;
				status: string;
				handler_range: { start: string; stop: string };
				instructions_executed: number;
				path_predicate: string | null;
				transition_formula: string | null;
				synth_formula: string | null;
				data_dependencies: string[];
				memory_side_effects: Array<{ address: string; size: number; value: string }>;
			}>({
				pythonPath,
				cwd: this.session.cwd,
				request: {
					action: "handlers",
					snapshot: params.snapshot,
					arch: params.arch,
					range: params.range,
					inputs: params.inputs,
					output: params.output,
					bounds: params.bounds,
					synthesize: params.synthesize,
				},
				signal,
				timeoutMs: DEFAULT_TIMEOUT_MS,
			});

			if (workerRes.status === "error" || !workerRes.result) {
				throw new ToolError(workerRes.error || "Handler semantic slicing failed.");
			}

			const r = workerRes.result;
			const details: NativeRecoverDetails = {
				action: "handlers",
				installed: true,
				handler_completed: r.completed,
				handler_status: r.status,
				handler_range: r.handler_range,
				path_predicate: r.path_predicate,
				transition_formula: r.transition_formula,
				synth_formula: r.synth_formula,
				data_dependencies: r.data_dependencies,
				memory_side_effects: r.memory_side_effects,
			};

			const text = [
				`Handler Semantic Slicing [${r.handler_range.start}..${r.handler_range.stop}]:`,
				`- Status: ${r.status}`,
				`- Instructions Executed: ${r.instructions_executed}`,
				r.path_predicate ? `- Path Predicate: ${r.path_predicate}` : null,
				`- Data Dependencies: ${r.data_dependencies.join(", ") || "none"}`,
				`- Memory Side Effects: ${r.memory_side_effects.length} stores recorded`,
				`- Transition Formula: ${r.synth_formula || r.transition_formula || "none"}`,
			]
				.filter(Boolean)
				.join("\n");

			return { content: [{ type: "text", text }], details };
		}

		// --------------------------------------------------------------------
		// Action: merge
		// --------------------------------------------------------------------
		if (params.action === "merge") {
			const workerRes = await runNativeRecoverWorker<{
				merged_paths_count: number;
				is_total_domain: boolean;
				coverage_guard: { is_total: boolean; uncovered_sample?: Record<string, unknown> | null };
				conflicts: Array<{ path_a: string | number; path_b: string | number; model: Record<string, unknown> }>;
				smt2_formula: string;
				llvm_available: boolean;
				llvm_ir: string | null;
				llvm_status: string;
			}>({
				pythonPath,
				cwd: this.session.cwd,
				request: {
					action: "merge",
					paths: params.paths,
					inputs: params.inputs,
					output_size_bits: params.output_size_bits ?? 32,
					arch: params.arch,
				},
				signal,
				timeoutMs: DEFAULT_TIMEOUT_MS,
			});

			if (workerRes.status === "error" || !workerRes.result) {
				throw new ToolError(workerRes.error || "Multi-path merge failed.");
			}

			const r = workerRes.result;
			let smtArtifactId: string | undefined;
			let smtFilePath: string | undefined;
			if (r.smt2_formula) {
				const persisted = await persistRecoverArtifact(this.session, "merged-smt2", r.smt2_formula);
				smtArtifactId = persisted.artifactId;
				smtFilePath = persisted.filePath;
			}

			let llvmArtifactId: string | undefined;
			let llvmFilePath: string | undefined;
			if (r.llvm_ir) {
				const persisted = await persistRecoverArtifact(this.session, "lifted-llvm", r.llvm_ir);
				llvmArtifactId = persisted.artifactId;
				llvmFilePath = persisted.filePath;
			}

			const details: NativeRecoverDetails = {
				action: "merge",
				installed: true,
				merged_paths_count: r.merged_paths_count,
				is_total_domain: r.is_total_domain,
				coverage_guard: r.coverage_guard,
				conflicts: r.conflicts,
				smt2_formula_artifact_id: smtArtifactId,
				smt2_formula_file_path: smtFilePath,
				llvm_ir_artifact_id: llvmArtifactId,
				llvm_ir_file_path: llvmFilePath,
				llvm: { available: r.llvm_available, status: r.llvm_status },
			};

			const lines = [
				`Multi-Path Guarded Merge:`,
				`- Merged Paths: ${r.merged_paths_count}`,
				`- Overlap Conflicts: ${r.conflicts.length === 0 ? "None (Consistent)" : `${r.conflicts.length} semantic conflicts detected!`}`,
				`- Domain Coverage: ${r.is_total_domain ? "Total (100% covered)" : "Partial (Explicit uncovered guard present)"}`,
				r.coverage_guard.uncovered_sample
					? `- Sample Uncovered Input: ${JSON.stringify(r.coverage_guard.uncovered_sample)}`
					: null,
				`- SMT-LIB2 Formula: ${smtArtifactId ? `artifact://${smtArtifactId}` : (smtFilePath ?? "generated")}`,
				`- LLVM IR: ${r.llvm_status} ${llvmArtifactId ? `(artifact://${llvmArtifactId})` : (llvmFilePath ?? "")}`,
			].filter(Boolean) as string[];

			return { content: [{ type: "text", text: lines.join("\n") }], details };
		}

		// --------------------------------------------------------------------
		// Action: verify
		// --------------------------------------------------------------------
		if (params.action === "verify") {
			const workerRes = await runNativeRecoverWorker<{
				passed_count: number;
				total_count: number;
				agreement_pct: number;
				counterexamples: Array<{
					input: Record<string, string | number>;
					original_return?: string | null;
					recovered_return?: string | null;
					original_memory_writes?: Array<{
						address: string;
						size: number;
						value: string;
						value_ast?: string | null;
					}>;
					expected_memory_writes?: Array<{ address: string; size: number; value: string }>;
					mismatch_reason: string;
				}>;
				out_of_domain_vectors: Array<Record<string, string | number>>;
				proof_label: string;
				assurance_level_recommendation: string;
				smt_formal_proved?: boolean;
				formal_proof_scope?: "full_algorithm" | "return_only" | null;
				side_effects_proved?: boolean;
				uncovered_domain_sample?: Record<string, string | number> | null;
			}>({
				pythonPath,
				cwd: this.session.cwd,
				request: {
					action: "verify",
					snapshot: params.snapshot,
					recovered: params.recovered,
					vectors: params.vectors,
					test_generation: params.test_generation,
					proof_mode: params.proof_mode ?? "both",
					bounds: params.bounds,
				},
				signal,
				timeoutMs: DEFAULT_TIMEOUT_MS,
			});

			if (workerRes.status === "error" || !workerRes.result) {
				throw new ToolError(workerRes.error || "Differential verification failed.");
			}

			const r = workerRes.result;
			const details: NativeRecoverDetails = {
				action: "verify",
				installed: true,
				proof_mode: (params.proof_mode as "finite_vectors" | "smt_formal" | "both") ?? "both",
				passed_count: r.passed_count,
				total_count: r.total_count,
				agreement_pct: r.agreement_pct,
				counterexamples: r.counterexamples,
				out_of_domain_vectors: r.out_of_domain_vectors,
				proof_label: r.proof_label,
				assurance_level_recommendation: r.assurance_level_recommendation,
				smt_formal_proved: r.smt_formal_proved,
				formal_proof_scope: r.formal_proof_scope,
				side_effects_proved: r.side_effects_proved,
				uncovered_domain_sample: r.uncovered_domain_sample,
			};
			let verifyArtifactId: string | undefined;
			let verifyFilePath: string | undefined;
			try {
				const persisted = await persistRecoverArtifact(this.session, "verify-report", JSON.stringify(r, null, 2));
				verifyArtifactId = persisted.artifactId;
				verifyFilePath = persisted.filePath;
			} catch {}

			const textLines = [
				`Differential Verification Report:`,
				`- Proof Mode: ${params.proof_mode ?? "both"}`,
				`- Formal Proof Scope: ${r.formal_proof_scope ?? "none"}`,
				`- Side Effects Proved: ${r.side_effects_proved ? "true" : "false"}`,
				`- Vectors Passed: ${r.passed_count}/${r.total_count} (${r.agreement_pct.toFixed(1)}%)`,
				`- Counterexamples: ${r.counterexamples.length}`,
				`- Proof Classification: ${r.proof_label}`,
				`- Assurance Recommendation: ${r.assurance_level_recommendation}`,
				verifyArtifactId
					? `- Full Report Artifact: artifact://${verifyArtifactId}`
					: verifyFilePath
						? `- Saved: ${verifyFilePath}`
						: null,
			].filter(Boolean) as string[];

			if (r.counterexamples.length > 0) {
				textLines.push("  * Mismatch Counterexamples:");
				for (const c of r.counterexamples.slice(0, 3)) {
					const reasonStr = c.mismatch_reason ? ` (Reason: ${c.mismatch_reason})` : "";
					textLines.push(
						`    - Input: ${JSON.stringify(c.input)} => Original: ${c.original_return ?? "none"}, Recovered: ${c.recovered_return ?? "none"}${reasonStr}`,
					);
				}
			}

			return { content: [{ type: "text", text: textLines.join("\n") }], details };
		}

		throw new ToolError(`Unsupported action.`);
	}
}

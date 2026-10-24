/**
 * Offline Triton Dynamic Binary Analysis and Symbolic Trace Replay Tool.
 *
 * Provides offline symbolic emulation, trace replay, AST simplification/synthesis,
 * and LLVM IR lifting using Jonathan Salwan's Triton library.
 *
 * 核心设计约束：
 * 1. 解释器隔离：通过 resolveVmpTool("triton") 解析专用 Python 环境，严格区分 NVIDIA triton。
 * 2. 审批层与 Plan Mode：status 归为 read 层并在 Plan Mode 开放；replay 归为 write 层且在 Plan Mode 拦截。
 * 3. 严禁硬编码调用约定：不假定 Linux SysV（RDI/RSI/EAX），输入种子与输出目标完全显式指定。
 * 4. 严禁伪造证据：未初始化通用寄存器位或内存读取时抛出明确缺失状态错误，严禁隐式填零。
 * 5. 快照一致性：跟踪快照仅在不一致时同步；符号状态若不一致则报错，防止破坏符号表达式。
 * 6. 完整性保证：当会话无 ArtifactManager 时自动回退写入本地工件目录，杜绝截断丢弃分析数据。
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
import tritonAnalyzeDescription from "../prompts/tools/triton-analyze.md" with { type: "text" };
import { appendArtifactReference, saveArtifactText } from "./gh-common";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";

// Staged text asset for Triton Python worker
import tritonAnalyzeWorkerSource from "./triton-analyze-worker.py" with { type: "text" };

// ============================================================================
// Parameter Schema
// ============================================================================

const tritonMemorySpecSchema = type({
	address: type("string | number").describe("Memory address (hex string or integer)"),
	"size?": type("number.integer >= 1").describe("Size in bytes (1, 2, 4, 8; default 1)"),
	value: type("string | number").describe("Concrete integer value or hex string"),
});

const tritonSymbolicRegisterSchema = type({
	name: type("string").describe("Register name to symbolize (e.g. 'rdi', 'esi', 'eax')"),
	"alias?": type("string").describe("Optional symbolic variable alias/label (e.g. 'x', 'y')"),
	"seed?": type("string | number").describe("Explicit concrete seed value if not present in initial_registers"),
});

const tritonSymbolicMemorySchema = type({
	address: type("string | number").describe("Memory address to symbolize"),
	size: type("number.integer >= 1").describe("Size in bytes to symbolize (1, 2, 4, 8)"),
	"alias?": type("string").describe("Optional symbolic variable alias/label"),
	seed: type("string | number").describe("Explicit concrete seed value for the symbolic memory"),
});

const tritonOutputSchema = type({
	kind: "'register'",
	target: "string",
}).or({
	kind: "'memory'",
	address: "string | number",
	size: "number.integer >= 1",
});

const tritonBoundsSchema = type({
	"max_instructions?": type("number.integer >= 1").describe(
		"Maximum instructions to replay before aborting (default: 50000, max: 200000)",
	),
	"max_trace_bytes?": type("number.integer >= 1").describe("Maximum trace file size in bytes (default: 32MB)"),
	"timeout_ms?": type("number.integer >= 1000").describe("Maximum execution timeout in milliseconds (default: 60000)"),
	"max_expr_chars?": type("number.integer >= 100").describe(
		"Maximum characters of expression to show in inline context before saving to artifact (default: 2000)",
	),
});

const tritonStatusSchema = type({
	action: "'status'",
});

const tritonReplaySchema = type({
	action: "'replay'",
	trace: type("string").describe("Path to trace file on disk (Salwan mr:/r:/i: format or JSONL)"),
	"arch?": type.enumerated("x86", "x86_64").describe("Target architecture (default: 'x86_64')"),
	"initial_registers?": type({
		"[string]": "string | number",
	}).describe("Explicit initial concrete register values (e.g. { rip: '0x401000', rdi: '0x1234' })"),
	"initial_memory?": type(tritonMemorySpecSchema).array().describe("Explicit initial concrete memory state"),
	"symbolic_registers?": type(tritonSymbolicRegisterSchema).array().describe("Registers to mark as symbolic inputs"),
	"symbolic_memory?": type(tritonSymbolicMemorySchema).array().describe("Memory locations to mark as symbolic inputs"),
	output: tritonOutputSchema.describe(
		"Output target: { kind: 'register', target: 'rax' } or { kind: 'memory', address, size }",
	),
	"bounds?": tritonBoundsSchema,
	"synthesize?": type("boolean").describe("Attempt expression synthesis via Triton AST synthesizer (default true)"),
	"lift_llvm?": type("boolean").describe("Attempt lifting symbolic expression to LLVM IR (default true)"),
});

export const tritonAnalyzeSchema = tritonStatusSchema.or(tritonReplaySchema);

export type TritonAnalyzeParams = typeof tritonAnalyzeSchema.infer;

// ============================================================================
// Detail Models
// ============================================================================

export interface TritonAnalyzeDetails {
	action: "status" | "replay";
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
	synthesizer?: {
		available: boolean;
		reason?: string | null;
	};
	install_hint?: string | null;
	arch?: string;
	instructions_executed?: number;
	concrete_return?: string | null;
	devirt_expr_preview?: string | null;
	devirt_expr_artifact_id?: string | null;
	devirt_expr_file_path?: string | null;
	synth_expr_preview?: string | null;
	synth_expr_artifact_id?: string | null;
	synth_expr_file_path?: string | null;
	llvm_available?: boolean;
	llvm_ir_preview?: string | null;
	llvm_ir_artifact_id?: string | null;
	llvm_ir_file_path?: string | null;
	llvm_status?: string | null;
	path_constraints_count?: number;
	path_constraints?: Array<{
		index: number;
		comment?: string;
		taken: boolean;
		address?: string | null;
	}>;
	execution_notice?: string;
	error?: string;
}

// ============================================================================
// Process Tree and Subprocess Runner Helpers
// ============================================================================

const MAX_STDOUT_BYTES = 16 * 1024 * 1024; // 16 MiB
const MAX_STDERR_BYTES = 1 * 1024 * 1024; // 1 MiB
const DEFAULT_TIMEOUT_MS = 60000;
const DEFAULT_MAX_TRACE_BYTES = 32 * 1024 * 1024; // 32 MiB
const MANAGED_INSTALL_HINT = "Run 'reverse setup reverse triton --execute' to install the managed Triton toolchain.";

function killProcessTree(pid: number, signal: NodeJS.Signals | number = "SIGKILL"): void {
	if (!pid || pid <= 0) return;
	if (process.platform === "win32") {
		try {
			Bun.spawnSync(["taskkill", "/F", "/T", "/PID", String(pid)]);
		} catch {
			try {
				process.kill(pid, signal);
			} catch {}
		}
	} else {
		try {
			process.kill(-pid, signal);
		} catch {
			try {
				process.kill(pid, signal);
			} catch {}
		}
	}
}

async function readBoundedStream(
	stream: ReadableStream<Uint8Array>,
	maxBytes: number,
	onOverflow: () => void,
): Promise<{ text: string; overflowed: boolean }> {
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let totalBytes = 0;
	let overflowed = false;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (value) {
				totalBytes += value.byteLength;
				if (totalBytes > maxBytes) {
					overflowed = true;
					onOverflow();
					break;
				}
				chunks.push(value);
			}
		}
	} finally {
		reader.releaseLock();
	}

	const merged = new Uint8Array(chunks.reduce((acc, c) => acc + c.byteLength, 0));
	let offset = 0;
	for (const c of chunks) {
		merged.set(c, offset);
		offset += c.byteLength;
	}
	return { text: new TextDecoder().decode(merged), overflowed };
}

interface WorkerBaseResult<T> {
	status: "ok" | "missing_dependency" | "error";
	result?: T;
	error?: string;
}

async function runTritonWorker<T>(options: {
	pythonPath: string;
	cwd: string;
	request: unknown;
	signal?: AbortSignal;
	timeoutMs?: number;
}): Promise<WorkerBaseResult<T>> {
	if (options.signal?.aborted) {
		return { status: "error", error: "Operation cancelled before execution." };
	}

	const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "reverse-triton-"));
	const workerFile = path.join(tempDir, "triton-analyze-worker.py");

	try {
		await fs.promises.writeFile(workerFile, tritonAnalyzeWorkerSource, "utf-8");

		const childEnv: Record<string, string | undefined> = {
			...filterEnv(process.env as Record<string, string | undefined>),
			PYTHONUNBUFFERED: "1",
			PYTHONDONTWRITEBYTECODE: "1",
		};

		const child = Bun.spawn([options.pythonPath, "-u", workerFile], {
			cwd: options.cwd,
			stdin: "pipe",
			stdout: "pipe",
			stderr: "pipe",
			env: childEnv,
			detached: process.platform !== "win32",
		});

		let timer: NodeJS.Timeout | number | undefined;
		let timedOut = false;
		let overflowError: string | null = null;

		const onAbort = () => {
			killProcessTree(child.pid);
		};

		if (options.signal?.aborted) {
			killProcessTree(child.pid);
			await child.exited.catch(() => {});
			return { status: "error", error: "Execution cancelled by abort signal." };
		}
		options.signal?.addEventListener("abort", onAbort, { once: true });

		const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
		if (timeoutMs > 0) {
			timer = setTimeout(() => {
				timedOut = true;
				killProcessTree(child.pid);
			}, timeoutMs);
		}

		let stdoutRes = { text: "", overflowed: false };
		let stderrRes = { text: "", overflowed: false };
		let exitCode: number | undefined;

		try {
			const requestJson = JSON.stringify(options.request);
			const stdinWriter = child.stdin;
			try {
				stdinWriter.write(new TextEncoder().encode(requestJson));
				await stdinWriter.end();
			} catch {
				// Subprocess might exit early on startup failure
			}

			[stdoutRes, stderrRes, exitCode] = await Promise.all([
				readBoundedStream(child.stdout, MAX_STDOUT_BYTES, () => {
					overflowError = "stdout exceeded 16 MiB budget";
					killProcessTree(child.pid);
				}),
				readBoundedStream(child.stderr, MAX_STDERR_BYTES, () => {
					overflowError = "stderr exceeded 1 MiB budget";
					killProcessTree(child.pid);
				}),
				child.exited,
			]);
		} finally {
			clearTimeout(timer);
			options.signal?.removeEventListener("abort", onAbort);
			killProcessTree(child.pid);
			await child.exited.catch(() => {});
		}

		if (timedOut) {
			return {
				status: "error",
				error: `Triton execution timed out after ${timeoutMs}ms.`,
			};
		}

		if (overflowError) {
			return { status: "error", error: `Stream overflow: ${overflowError}.` };
		}

		const rawStdout = stdoutRes.text.trim();
		if (!rawStdout) {
			return {
				status: "error",
				error: `Worker process exited with code ${exitCode} without JSON output. Stderr: ${stderrRes.text.trim() || "(empty)"}`,
			};
		}

		try {
			const parsed = JSON.parse(rawStdout) as WorkerBaseResult<T>;
			return parsed;
		} catch (parseErr) {
			return {
				status: "error",
				error: `Failed to parse worker JSON output: ${parseErr instanceof Error ? parseErr.message : String(parseErr)}. Raw output: ${rawStdout.slice(0, 1000)}`,
			};
		}
	} finally {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	}
}

interface PersistedOutputRef {
	artifactId?: string;
	filePath?: string;
	reference: string;
}

async function persistTritonOutput(
	session: ToolSession,
	category: string,
	content: string,
): Promise<PersistedOutputRef> {
	const artifactId = await saveArtifactText(session, "triton_analyze", content).catch(() => undefined);
	if (artifactId) {
		return {
			artifactId,
			reference: `artifact://${artifactId}`,
		};
	}

	// 针对无 ArtifactManager 的 SDK 会话与测试环境：回退写入工作区工件目录，杜绝截断丢弃完整分析数据
	const outputDir = path.join(session.cwd, "artifacts", "triton");
	await fs.promises.mkdir(outputDir, { recursive: true });
	const hash = crypto.createHash("sha256").update(content).digest("hex").slice(0, 12);
	const fileName = `${category}-${Date.now()}-${hash}.txt`;
	const filePath = path.join(outputDir, fileName);
	await fs.promises.writeFile(filePath, content, "utf-8");
	return {
		filePath,
		reference: filePath,
	};
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class TritonAnalyzeTool implements AgentTool<typeof tritonAnalyzeSchema, TritonAnalyzeDetails> {
	readonly name = "triton_analyze";
	readonly label = "Triton Analyze";
	readonly summary = "Offline symbolic trace analysis, AST simplification/synthesis, and LLVM IR lifting using Triton";
	readonly description: string;
	readonly parameters = tritonAnalyzeSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	/**
	 * Action-based read/write approvals:
	 * - status: read tier (harmless capability check, allowed in plan mode)
	 * - replay: write tier (bounded emulation that allocates and writes persistent session artifacts)
	 */
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			if (args.action === "status") {
				return "read";
			}
		}
		return "write";
	};

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(tritonAnalyzeDescription);
	}

	async execute(
		_toolCallId: string,
		params: TritonAnalyzeParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<TritonAnalyzeDetails> & { details: TritonAnalyzeDetails }> {
		throwIfAborted(signal);

		// Plan Mode 守卫：replay 涉及仿真和写入工件，必须被 Plan Mode 拦截；仅 status 允许在 Plan Mode 运行
		const planMode = this.session.getPlanModeState?.();
		if (planMode?.enabled && params.action !== "status") {
			throw new ToolError(
				"Plan mode: triton trace replay executes symbolic emulation and writes session artifacts. Only 'status' is permitted in plan mode.",
			);
		}

		// 解析 Triton Python 运行环境
		const pythonPath = resolveVmpTool("triton", {
			env: process.env,
			platform: process.platform,
		});

		// ------------------------------------------------------------------------
		// Action: status
		// ------------------------------------------------------------------------
		if (params.action === "status") {
			if (!pythonPath) {
				const details: TritonAnalyzeDetails = {
					action: "status",
					installed: false,
					python_path: null,
					triton_version: null,
					install_hint: MANAGED_INSTALL_HINT,
				};
				const text = [
					"Triton Environment Status: Not Available",
					"- Installed: false",
					"- Python: No managed or valid Triton Python interpreter found.",
					`- Hint: ${details.install_hint}`,
				].join("\n");
				return {
					content: [{ type: "text", text }],
					details,
				};
			}

			const workerRes = await runTritonWorker<{
				installed: boolean;
				python_path: string;
				python_version: string;
				triton_version: string | null;
				supported_architectures: string[];
				solver: { available: boolean; engine: string | null; solvers: string[]; reason?: string | null };
				llvm: { available: boolean; status: string };
				synthesizer: { available: boolean; reason?: string | null };
				install_hint: string;
				error?: string;
			}>({
				pythonPath,
				cwd: this.session.cwd,
				request: { action: "status" },
				signal,
				timeoutMs: 10000,
			});

			if (workerRes.status === "error" || !workerRes.result) {
				const details: TritonAnalyzeDetails = {
					action: "status",
					installed: false,
					python_path: pythonPath,
					error: workerRes.error ?? "Failed to query Triton status",
				};
				const text = `Triton Probe Error: ${details.error}`;
				return {
					content: [{ type: "text", text }],
					details,
					isError: true,
				};
			}

			const r = workerRes.result;
			const details: TritonAnalyzeDetails = {
				action: "status",
				installed: r.installed,
				python_path: r.python_path,
				triton_version: r.triton_version,
				supported_architectures: r.supported_architectures,
				solver: r.solver,
				llvm: r.llvm,
				synthesizer: r.synthesizer,
				install_hint: r.installed ? null : r.install_hint,
				error: r.error,
			};

			const lines: string[] = [
				`Triton Environment Status: ${r.installed ? "Available" : "Not Installed"}`,
				`- Python: ${r.python_path} (Python ${r.python_version})`,
				`- Triton Version: ${r.triton_version ?? "N/A"}`,
				`- Architectures: ${r.supported_architectures?.length ? r.supported_architectures.join(", ") : "None"}`,
				`- Solver Engine: ${r.solver?.available ? `${r.solver.engine ?? "Available"} (${r.solver.solvers?.join(", ")})` : `Not available (${r.solver?.reason ?? "missing SMT solver"})`}`,
				`- AST Synthesizer: ${r.synthesizer?.available ? "Available" : `Not available (${r.synthesizer?.reason ?? "missing synthesizer"})`}`,
				`- LLVM IR Lifting: ${r.llvm?.available ? "Available" : `Unavailable (${r.llvm?.status ?? "not supported"})`}`,
			];
			if (!r.installed && r.install_hint) {
				lines.push(`- Hint: ${r.install_hint}`);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details,
			};
		}

		// ------------------------------------------------------------------------
		// Action: replay
		// ------------------------------------------------------------------------
		if (!pythonPath) {
			throw new ToolError(`Triton is not installed or configured in this environment. ${MANAGED_INSTALL_HINT}`);
		}

		// 严格校验 trace 文件路径
		const resolvedTracePath = resolveReadPath(params.trace, this.session.cwd);
		if (!fs.existsSync(resolvedTracePath)) {
			throw new ToolError(`Trace file not found: ${resolvedTracePath}`);
		}
		const stat = fs.statSync(resolvedTracePath);
		if (stat.isDirectory()) {
			throw new ToolError(`Target trace path is a directory, not a file: ${resolvedTracePath}`);
		}

		const bounds = params.bounds ?? {};
		const maxTraceBytes = bounds.max_trace_bytes ?? DEFAULT_MAX_TRACE_BYTES;
		const maxExprChars = bounds.max_expr_chars ?? 2000;
		const timeoutMs = bounds.timeout_ms ?? DEFAULT_TIMEOUT_MS;

		if (stat.size > maxTraceBytes) {
			throw new ToolError(
				`Trace file size (${stat.size} bytes) exceeds limit of ${maxTraceBytes} bytes. Use bounds.max_trace_bytes to increase.`,
			);
		}

		const replayRequest = {
			action: "replay",
			trace: resolvedTracePath,
			arch: params.arch ?? "x86_64",
			initial_registers: params.initial_registers,
			initial_memory: params.initial_memory,
			symbolic_registers: params.symbolic_registers,
			symbolic_memory: params.symbolic_memory,
			output: params.output,
			bounds: {
				max_instructions: bounds.max_instructions ?? 50000,
			},
			synthesize: params.synthesize ?? true,
			lift_llvm: params.lift_llvm ?? true,
		};

		const workerRes = await runTritonWorker<{
			arch: string;
			instructions_executed: number;
			concrete_return: string | null;
			devirt_expr: string | null;
			synth_expr: string | null;
			llvm_available: boolean;
			llvm_ir: string | null;
			llvm_status: string;
			path_constraints_count: number;
			path_constraints: Array<{
				index: number;
				comment?: string;
				taken: boolean;
				address?: string | null;
			}>;
			execution_notice: string;
		}>({
			pythonPath,
			cwd: this.session.cwd,
			request: replayRequest,
			signal,
			timeoutMs,
		});

		if (workerRes.status === "missing_dependency") {
			throw new ToolError(
				workerRes.error ??
					`Triton library is not installed in the resolved Python environment. ${MANAGED_INSTALL_HINT}`,
			);
		}

		if (workerRes.status === "error" || !workerRes.result) {
			throw new ToolError(`Triton trace replay failed: ${workerRes.error ?? "Unknown execution error"}`);
		}

		const r = workerRes.result;

		// ------------------------------------------------------------------------
		// 上下文截断与工件持久化 (Session Artifacts & Local Fallback Retention)
		// ------------------------------------------------------------------------
		let devirtPreview = r.devirt_expr;
		let devirtArtifactId: string | null = null;
		let devirtFilePath: string | null = null;
		if (r.devirt_expr) {
			const persisted = await persistTritonOutput(this.session, "triton-devirt-expr", r.devirt_expr);
			devirtArtifactId = persisted.artifactId ?? null;
			devirtFilePath = persisted.filePath ?? null;
			if (r.devirt_expr.length > maxExprChars) {
				devirtPreview = `${r.devirt_expr.slice(0, maxExprChars)}... (truncated)`;
			}
		}

		let synthPreview = r.synth_expr;
		let synthArtifactId: string | null = null;
		let synthFilePath: string | null = null;
		if (r.synth_expr) {
			const persisted = await persistTritonOutput(this.session, "triton-synth-expr", r.synth_expr);
			synthArtifactId = persisted.artifactId ?? null;
			synthFilePath = persisted.filePath ?? null;
			if (r.synth_expr.length > maxExprChars) {
				synthPreview = `${r.synth_expr.slice(0, maxExprChars)}... (truncated)`;
			}
		}

		let llvmPreview = r.llvm_ir;
		let llvmArtifactId: string | null = null;
		let llvmFilePath: string | null = null;
		if (r.llvm_ir) {
			const persisted = await persistTritonOutput(this.session, "triton-llvm-ir", r.llvm_ir);
			llvmArtifactId = persisted.artifactId ?? null;
			llvmFilePath = persisted.filePath ?? null;
			if (r.llvm_ir.length > maxExprChars) {
				llvmPreview = `${r.llvm_ir.slice(0, maxExprChars)}... (truncated)`;
			}
		}

		const details: TritonAnalyzeDetails = {
			action: "replay",
			installed: true,
			arch: r.arch,
			instructions_executed: r.instructions_executed,
			concrete_return: r.concrete_return,
			devirt_expr_preview: devirtPreview,
			devirt_expr_artifact_id: devirtArtifactId,
			devirt_expr_file_path: devirtFilePath,
			synth_expr_preview: synthPreview,
			synth_expr_artifact_id: synthArtifactId,
			synth_expr_file_path: synthFilePath,
			llvm_available: r.llvm_available,
			llvm_ir_preview: llvmPreview,
			llvm_ir_artifact_id: llvmArtifactId,
			llvm_ir_file_path: llvmFilePath,
			llvm_status: r.llvm_status,
			path_constraints_count: r.path_constraints_count,
			path_constraints: r.path_constraints,
			execution_notice: r.execution_notice,
		};

		const lines: string[] = [
			"### Triton Offline Trace Replay Results",
			`- Architecture: ${r.arch}`,
			`- Instructions Executed: ${r.instructions_executed}`,
			`- Concrete Return Value: ${r.concrete_return ?? "N/A"}`,
		];

		if (devirtPreview) {
			let devirtText = `- Devirtualized AST Expression:\n\`\`\`smt\n${devirtPreview}\n\`\`\``;
			if (devirtArtifactId) {
				devirtText = appendArtifactReference(devirtText, devirtArtifactId, "Full AST expression");
			} else if (devirtFilePath) {
				devirtText += `\n\nFull AST expression saved: ${devirtFilePath}`;
			}
			lines.push(devirtText);
		}

		if (synthPreview) {
			let synthText = `- Synthesized Expression:\n\`\`\`smt\n${synthPreview}\n\`\`\``;
			if (synthArtifactId) {
				synthText = appendArtifactReference(synthText, synthArtifactId, "Full synthesized expression");
			} else if (synthFilePath) {
				synthText += `\n\nFull synthesized expression saved: ${synthFilePath}`;
			}
			lines.push(synthText);
		}

		if (r.llvm_available && llvmPreview) {
			let llvmText = `- LLVM IR:\n\`\`\`llvm\n${llvmPreview}\n\`\`\``;
			if (llvmArtifactId) {
				llvmText = appendArtifactReference(llvmText, llvmArtifactId, "Complete LLVM IR module");
			} else if (llvmFilePath) {
				llvmText += `\n\nComplete LLVM IR module saved: ${llvmFilePath}`;
			}
			lines.push(llvmText);
		} else {
			lines.push(`- LLVM IR Lifting: Unavailable (${r.llvm_status})`);
		}

		lines.push(`- Path Constraints Recorded: ${r.path_constraints_count}`);
		lines.push(`\n**Notice**: ${r.execution_notice}`);

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details,
		};
	}
}

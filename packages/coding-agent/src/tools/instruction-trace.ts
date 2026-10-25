/**
 * Instruction Trace Tool: Controlled instruction tracing and execution state recording.
 *
 * Integrates Frida Stalker and QuarkslaB Dynamic binary Instrumentation (QBDI, Apache-2.0).
 * Generates bounded instruction execution traces with concrete pre-instruction register
 * snapshots and memory reads in structured JSONL format directly ingested by Triton.
 *
 * Licensed under Apache-2.0 (incorporating QBDI instrumentation patterns).
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import type { AgentTool, AgentToolResult, ToolTier, AgentToolUpdateCallback } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import instructionTraceDescription from "../prompts/tools/instruction-trace.md" with { type: "text" };
import { fridaDependency } from "./frida";
import { resolveInstructionTraceTarget } from "./instruction-trace-session";
import { probeFridaLiveDependency } from "./frida-live-env";
import { inspectProtectionTool, resolveProtectionTool } from "../extensibility/protection-toolchain";
import { appendArtifactReference } from "./gh-common";
import type { ToolSession } from "./index";
import { safePublishArtifact } from "./vmp-common";
import { throwIfAborted } from "./tool-errors";
import {
	executeInstructionTrace,
	type InstructionTraceMetadata,
	type InstructionTraceResult,
} from "./instruction-trace-agent";

// ============================================================================
// Parameter Schema
// ============================================================================

export const instructionTraceStatusSchema = type({
	action: "'status'",
});

export const instructionTraceCaptureSchema = type({
	action: "'capture'",
	"pid?": type("number").describe("Target process ID (PID) to attach to"),
	"process?": type("string").describe("Target process name or application package name to attach to"),
	"spawn?": type("string").describe("Target binary or application package to spawn and trace"),
	"session_id?": type("string").describe("Existing Frida live session identifier to reuse"),
	"device?": type("string").describe("Target device serial or ID (e.g. ADB serial for -D, or 'local')"),
	"usb?": type("boolean").describe("Target USB device/emulator (shorthand for -U)"),
	"host?": type("string").describe("Target remote Frida host (e.g. 192.168.1.5:27042)"),
	"module?": type("string").describe("Target module/library name (e.g. 'libnative-lib.so' or 'target_binary')"),
	"function?": type("string").describe(
		"Target function symbol name or export to trace (e.g. 'validate_key' or 'Java_com_example_Calc')",
	),
	"offset?": type("string | number").describe("RVA offset from module base (e.g. '0x1020' or 4128)"),
	"address?": type("string | number").describe("Absolute memory address to trace"),
	"thread_id?": type("number").describe("Specific thread ID to trace (defaults to calling thread of function)"),
	"scope?": type
		.enumerated("function", "thread", "range")
		.describe(
			"Tracing scope: 'function' (trace until return), 'thread' (trace thread instructions), 'range' (trace within address range)",
		),
	"range?": type({
		start: "string | number",
		end: "string | number",
	}).describe("Explicit address range [start, end] for range-scoped tracing"),
	"max_instructions?": type("number.integer >= 1").describe(
		"Maximum instructions to collect before stopping (default: 10000, max: 200000)",
	),
	"timeout_ms?": type("number.integer >= 1000").describe("Maximum execution timeout in milliseconds (default: 30000)"),
	"max_bytes?": type("number.integer >= 1024").describe(
		"Maximum trace output size in bytes (default: 33554432 / 32MB)",
	),
	"engine?": type
		.enumerated("auto", "qbdi", "stalker")
		.describe(
			"Tracing engine: 'auto' (prefer QBDI for full memory access, fallback to Stalker), 'qbdi' (deterministic memory reads), 'stalker' (Frida Stalker)",
		),
	"format?": type
		.enumerated("jsonl", "salwan")
		.describe(
			"Trace output format: 'jsonl' (default, structured JSONL for triton worker) or 'salwan' (legacy text mr:/r:/i: format)",
		),
	"output_path?": type("string").describe("Optional destination file path for the trace output"),
	"signature?": type({
		return_type: type.enumerated("pointer", "uint64", "int64", "uint32", "int32", "int", "uint", "void"),
		arg_types: type.enumerated("pointer", "uint64", "int64", "uint32", "int32", "int", "uint").array(),
	}).describe(
		"Explicit C function scalar signature for QBDI replacement: { return_type: 'uint64', arg_types: ['uint64', 'pointer'] }",
	),
});

export const instructionTraceSchema = instructionTraceStatusSchema.or(instructionTraceCaptureSchema);
export type InstructionTraceParams = typeof instructionTraceSchema.infer;

// ============================================================================
// Output Models
// ============================================================================

export interface InstructionTraceDetails {
	action: "status" | "capture";
	success: boolean;
	status: "ok" | "missing_dependency" | "truncated" | "error";
	engine?: "qbdi" | "stalker";
	frida?: {
		available: boolean;
		cliPath?: string;
		version?: string;
	};
	stalker?: {
		available: boolean;
		supported_architectures: string[];
	};
	qbdi?: {
		available: boolean;
		installed: boolean;
		path?: string;
		version?: string;
		install_hint?: string;
	};
	trace_path?: string;
	manifest_path?: string;
	sha256?: string;
	instruction_count?: number;
	memory_read_count?: number;
	total_bytes?: number;
	completion_reason?: string;
	arch?: string;
	module?: {
		name?: string;
		base?: string;
		size?: number;
		sha256?: string;
	};
	metadata?: InstructionTraceMetadata;
	replay_handoff?: {
		tool: "triton_analyze";
		valid: boolean;
		notice?: string;
		params: {
			action: "replay";
			trace: string;
			arch: string;
			initial_registers?: Record<string, string>;
			output: {
				kind: "register";
				target: string;
			};
		};
	};
	error?: string;
}

// ============================================================================
// InstructionTraceTool Class
// ============================================================================

export class InstructionTraceTool implements AgentTool<typeof instructionTraceSchema, InstructionTraceDetails> {
	readonly name = "instruction_trace";
	readonly label = "Instruction Trace";
	readonly summary = "Trace instruction execution and register/memory states via Frida Stalker and QBDI";
	readonly description: string;
	readonly parameters = instructionTraceSchema;
	readonly strict = true;
	readonly loadMode = "discoverable" as const;
	readonly approval = (args: unknown): ToolTier =>
		args && typeof args === "object" && "action" in args && args.action === "status" ? "read" : "exec";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(instructionTraceDescription);
	}

	async execute(
		_toolCallId: string,
		params: InstructionTraceParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback,
	): Promise<AgentToolResult<InstructionTraceDetails> & { details: InstructionTraceDetails }> {
		throwIfAborted(signal);

		// Plan Mode guard: status is allowed; capture executes dynamic hooks and is blocked
		const planMode = this.session.getPlanModeState?.();
		if (planMode?.enabled && params.action !== "status") {
			throw new ToolError(
				"Plan mode: instruction trace attaches to processes and executes dynamic hooks. Only 'status' is permitted in plan mode.",
			);
		}

		if (params.action === "status") {
			return this.handleStatus(signal);
		}

		return this.handleCapture(params, signal);
	}

	// --------------------------------------------------------------------------
	// Status Handler
	// --------------------------------------------------------------------------

	private async handleStatus(
		signal?: AbortSignal,
	): Promise<AgentToolResult<InstructionTraceDetails> & { details: InstructionTraceDetails }> {
		throwIfAborted(signal);

		// Probe Frida CLI
		const fridaDep = fridaDependency();

		// Probe Frida Live
		let liveDep;
		try {
			liveDep = await probeFridaLiveDependency();
		} catch {
			liveDep = { available: false };
		}

		// Probe QBDI runtime assets
		const qbdiTool = inspectProtectionTool("qbdi");
		const qbdiInstalled = Boolean(qbdiTool.installed && qbdiTool.canStart);

		const fridaAvailable = fridaDep.available || liveDep.available;
		const supportedArchitectures = ["arm", "arm64", "ia32", "x64"];

		const lines: string[] = [
			"Instruction Trace Capability Status:",
			`- Frida CLI: ${fridaDep.available ? `available (${fridaDep.path})` : "not found on PATH"}`,
			`- Frida Live Environment: ${liveDep.available ? "available" : "not configured"}`,
			`- Frida Stalker Engine: ${fridaAvailable ? "available" : "unavailable (requires Frida)"} (architectures: ${supportedArchitectures.join(", ")})`,
			`- QBDI DBI Engine: ${qbdiInstalled ? `installed (${qbdiTool.path}, v${qbdiTool.version ?? "0.12.1"})` : "not installed (install via `reverse setup reverse qbdi --execute`)"}`,
			`- Preferred Tracing Mode: ${qbdiInstalled ? "QBDI (deterministic instruction & full memory reads)" : "Frida Stalker (built-in instruction & register tracing)"}`,
		];

		const details: InstructionTraceDetails = {
			action: "status",
			success: true,
			status: "ok",
			frida: {
				available: fridaAvailable,
				cliPath: fridaDep.path ?? undefined,
				version: liveDep.fridaVersion ?? undefined,
			},
			stalker: {
				available: fridaAvailable,
				supported_architectures: supportedArchitectures,
			},
			qbdi: {
				available: qbdiInstalled,
				installed: qbdiInstalled,
				path: qbdiInstalled ? qbdiTool.path : undefined,
				version: qbdiTool.version ?? "0.12.1",
				install_hint: "reverse setup reverse qbdi --execute",
			},
		};

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details,
		};
	}

	// --------------------------------------------------------------------------
	// Capture Handler
	// --------------------------------------------------------------------------

	private async handleCapture(
		params: typeof instructionTraceCaptureSchema.infer,
		signal?: AbortSignal,
	): Promise<AgentToolResult<InstructionTraceDetails> & { details: InstructionTraceDetails }> {
		throwIfAborted(signal);

		// Resolve target parameters (supporting live active session registry & disk fallback with activeChildPid mapping)
		const targetResolution = await resolveInstructionTraceTarget({
			cwd: this.session.cwd,
			sessionId: params.session_id,
			pid: params.pid,
			process: params.process,
			spawn: params.spawn,
			device: params.device,
			usb: params.usb,
			host: params.host,
		});

		// Validate target identification
		const hasTarget =
			targetResolution.pid !== undefined ||
			(targetResolution.process && targetResolution.process.trim().length > 0) ||
			(targetResolution.spawn && targetResolution.spawn.trim().length > 0);

		if (!hasTarget) {
			throw new ToolError("Must specify a target: 'pid', 'process', 'spawn', or valid 'session_id'");
		}

		// Validate scope/bounds
		const hasBounds =
			Boolean(params.module?.trim()) ||
			Boolean(params.function?.trim()) ||
			params.offset !== undefined ||
			params.address !== undefined ||
			Boolean(params.range);

		if (!hasBounds) {
			throw new ToolError(
				"Must specify tracing bounds to prevent unbounded process instrumentation: provide 'module', 'function', 'offset', 'address', or 'range'",
			);
		}

		// Check QBDI availability and requirements if explicit qbdi engine requested
		if (params.engine === "qbdi") {
			const qbdiTool = resolveProtectionTool("qbdi");
			if (!qbdiTool?.installed) {
				throw new ToolError(
					"QBDI engine requested but QBDI runtime is not installed. Run 'reverse setup reverse qbdi --execute' to install pinned QBDI v0.12.1, or use engine: 'auto' / 'stalker'.",
				);
			}
			if (params.scope && params.scope !== "function") {
				throw new ToolError(
					"QBDI engine requires scope: 'function'. Use engine: 'stalker' for scope: 'thread' or 'range'.",
				);
			}
			if (!params.signature) {
				throw new ToolError(
					"QBDI function instrumentation requires explicit 'signature' ({ return_type: string, arg_types: string[] }) with integer/pointer scalar types to safely execute target under VM.call. Provide 'signature' or use engine: 'auto' / 'stalker'.",
				);
			}
			if (params.signature.arg_types.length > 10) {
				throw new ToolError(
					"QBDI function instrumentation supports up to 10 scalar arguments in function signature (matching upstream VM.call).",
				);
			}
		}

		// Allocate output artifact path
		let artifactPath: string | undefined;
		let artifactId: string | undefined;

		try {
			const allocated = await this.session.allocateOutputArtifact?.("instruction-trace");
			artifactPath = allocated?.path;
			artifactId = allocated?.id;
		} catch {
			// Ignore artifact allocation failure, fallback below
		}

		if (!artifactPath) {
			const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-trace-"));
			const ext = params.format === "salwan" ? "trace" : "jsonl";
			artifactPath = path.join(tmpDir, `trace_${Date.now()}.${ext}`);
		}

		// Execute trace capture
		const traceResult: InstructionTraceResult = await executeInstructionTrace({
			pid: targetResolution.pid,
			process: targetResolution.process,
			spawn: targetResolution.spawn,
			sessionId: targetResolution.sessionId,
			device: targetResolution.device,
			usb: targetResolution.usb,
			host: targetResolution.host,
			module: params.module,
			function: params.function,
			offset: params.offset,
			address: params.address,
			threadId: params.thread_id,
			scope: params.scope,
			range: params.range,
			maxInstructions: params.max_instructions,
			timeoutMs: params.timeout_ms,
			maxBytes: params.max_bytes,
			engine: params.engine,
			format: params.format,
			signature: params.signature,
			artifactPath,
			cwd: this.session.cwd,
			signal,
		});
		if (traceResult.totalBytes === 0 || traceResult.instructionCount === 0 || !traceResult.success) {
			try {
				await fs.rm(traceResult.tracePath, { force: true });
				await fs.rm(traceResult.manifestPath, { force: true });
			} catch {}
			if (traceResult.completionReason === "timeout") {
				throw new ToolError(
					"Instruction trace capture timed out without capturing instructions. Ensure target function was invoked.",
				);
			}
			throw new ToolError(
				`Instruction trace capture produced 0 instructions / bytes (${traceResult.completionReason || traceResult.status}). Check that target function was invoked and bounds were reached.`,
			);
		}

		// Publish to output_path if requested
		let publishedTracePath = traceResult.tracePath;
		let publishedManifestPath = traceResult.manifestPath;
		if (params.output_path && params.output_path.trim().length > 0) {
			const destTrace = path.resolve(this.session.cwd, params.output_path.trim());
			const destManifest = `${destTrace}.manifest.json`;

			let destTraceExisted = false;
			try {
				await fs.stat(destTrace);
				destTraceExisted = true;
			} catch {
				destTraceExisted = false;
			}

			let ownedTraceCreated = false;
			let ownedManifestCreated = false;

			try {
				await safePublishArtifact(traceResult.tracePath, destTrace);
				ownedTraceCreated = !destTraceExisted;

				// Update replay_handoff.params.trace to point to the published trace path
				if (traceResult.metadata.replay_handoff?.params) {
					traceResult.metadata.replay_handoff.params.trace = destTrace;
				}

				// Write published manifest exclusively with 'wx' flag to prevent clobbering pre-existing files
				await fs.writeFile(destManifest, JSON.stringify(traceResult.metadata, null, 2), {
					encoding: "utf-8",
					flag: "wx",
				});
				ownedManifestCreated = true;

				publishedTracePath = destTrace;
				publishedManifestPath = destManifest;
			} catch (publishErr) {
				// Only unlink files that were freshly created during this publish operation
				if (ownedTraceCreated) {
					try {
						await fs.rm(destTrace, { force: true });
					} catch {}
				}
				if (ownedManifestCreated) {
					try {
						await fs.rm(destManifest, { force: true });
					} catch {}
				}
				throw publishErr;
			}
		}

		// Format user-facing text result
		const summaryLines: string[] = [
			`Instruction Trace Captured Successfully:`,
			`- Status: ${traceResult.status === "truncated" ? "truncated (limit reached or missing chunks)" : "ok"}`,
			`- Engine: ${traceResult.engine}`,
			`- Memory Reads Complete: ${traceResult.metadata.flags.memory_reads_complete ? "true (deterministic QBDI capture)" : "false (Frida Stalker observation; partial memory reads)"}`,
			`- Target Architecture: ${traceResult.arch ?? "unknown"}`,
			`- Total Instructions: ${traceResult.instructionCount}`,
			`- Memory Reads: ${traceResult.memoryReadCount}`,
			`- Completion Reason: ${traceResult.completionReason}`,
			`- Trace File: ${publishedTracePath} (${traceResult.totalBytes} bytes, SHA-256: ${traceResult.sha256.slice(0, 16)}...)`,
			`- Manifest Sidecar: ${publishedManifestPath}`,
		];

		if (traceResult.metadata.flags.thumb_mode) {
			summaryLines.push("- Thumb Mode: true");
		}
		if (traceResult.metadata.flags.nzcv) {
			summaryLines.push(`- NZCV Flags: ${traceResult.metadata.flags.nzcv}`);
		}

		if (traceResult.metadata.replay_handoff?.valid) {
			summaryLines.push(
				`- Triton Replay Handoff: ready for triton_analyze(arch: "${traceResult.metadata.replay_handoff.params.arch}", output: { kind: "register", target: "${traceResult.metadata.replay_handoff.params.output.target}" })`,
			);
		} else if (traceResult.metadata.replay_handoff?.notice) {
			summaryLines.push(`- Triton Replay Notice: ${traceResult.metadata.replay_handoff.notice}`);
		}

		let outputText = summaryLines.join("\n");
		if (artifactId) {
			outputText = appendArtifactReference(outputText, artifactId, "instruction trace");
		}

		const details: InstructionTraceDetails = {
			action: "capture",
			success: traceResult.success,
			status: traceResult.status,
			engine: traceResult.engine,
			trace_path: publishedTracePath,
			manifest_path: publishedManifestPath,
			sha256: traceResult.sha256,
			instruction_count: traceResult.instructionCount,
			memory_read_count: traceResult.memoryReadCount,
			total_bytes: traceResult.totalBytes,
			completion_reason: traceResult.completionReason,
			arch: traceResult.arch,
			module: traceResult.module,
			metadata: traceResult.metadata,
			replay_handoff: traceResult.metadata.replay_handoff,
		};

		return {
			content: [{ type: "text", text: outputText }],
			details,
		};
	}
}

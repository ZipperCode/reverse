/**
 * Regression test suite for InstructionTraceTool (`instruction_trace`).
 *
 * Verifies tool identity, parameter schemas, approval tiers, plan mode guards,
 * QBDI / Stalker engine detection, chunk streaming and JSONL parsing,
 * Triton-compatible register/memory/instruction records, companion metadata sidecars,
 * and Triton replay request handoff.
 */

import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { Settings } from "../../src/config/settings";
import type { ToolSession } from "../../src/tools";
import { InstructionTraceTool, instructionTraceSchema } from "../../src/tools/instruction-trace";
import { executeInstructionTrace, type InstructionTraceMetadata } from "../../src/tools/instruction-trace-agent";
import type { FridaRunner } from "../../src/tools/frida";

function createTestSession(cwd: string, planModeEnabled = false): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		getPlanModeState: () => ({ enabled: planModeEnabled, planFilePath: "/tmp/PLAN.md" }),
	};
}

describe("InstructionTraceTool", () => {
	it("registers canonical name, parameter schema, strict flag, and tier approval contracts", () => {
		const session = createTestSession("/tmp");
		const tool = new InstructionTraceTool(session);

		expect(tool.name).toBe("instruction_trace");
		expect(tool.label).toBe("Instruction Trace");
		expect(tool.parameters).toBe(instructionTraceSchema);
		expect(tool.strict).toBe(true);
		expect(tool.loadMode).toBe("discoverable");

		// Read tier: status
		expect(tool.approval({ action: "status" })).toBe("read");

		// Exec tier: capture
		expect(
			tool.approval({
				action: "capture",
				pid: 1234,
				module: "libtest.so",
				function: "test_func",
			}),
		).toBe("exec");

		// Fail-closed to exec on unrecognized or null arguments
		expect(tool.approval(null)).toBe("exec");
		expect(tool.approval({})).toBe("exec");
		expect(tool.approval({ action: "unknown" })).toBe("exec");
	});

	it("blocks capture action in plan mode while permitting status action", async () => {
		const session = createTestSession("/tmp", true);
		const tool = new InstructionTraceTool(session);

		// Status allowed in plan mode
		const statusRes = await tool.execute("call-status", { action: "status" });
		expect(statusRes.details.action).toBe("status");
		expect(statusRes.details.success).toBe(true);
		expect(statusRes.details.status).toBe("ok");

		// Capture blocked in plan mode
		await expect(
			tool.execute("call-capture", {
				action: "capture",
				pid: 1234,
				module: "libtest.so",
				function: "verify_key",
			}),
		).rejects.toThrow(ToolError);
	});

	it("status action reports Frida, Stalker, and QBDI availability and architectures", async () => {
		const session = createTestSession("/tmp");
		const tool = new InstructionTraceTool(session);

		const res = await tool.execute("call-status-check", { action: "status" });
		expect(res.details.action).toBe("status");
		expect(res.details.success).toBe(true);
		expect(res.details.stalker?.supported_architectures).toContain("arm64");
		expect(res.details.stalker?.supported_architectures).toContain("x64");
		expect(res.details.qbdi?.install_hint).toBe("reverse setup reverse qbdi --execute");
	});

	it("validates target requirement on capture", async () => {
		const session = createTestSession("/tmp");
		const tool = new InstructionTraceTool(session);

		// Missing target entirely
		await expect(
			tool.execute("call-no-target", {
				action: "capture",
				module: "libtest.so",
				function: "test",
			}),
		).rejects.toThrow(/Must specify a target/);
	});

	it("validates bounds requirement on capture", async () => {
		const session = createTestSession("/tmp");
		const tool = new InstructionTraceTool(session);

		// Target provided but no bounds
		await expect(
			tool.execute("call-no-bounds", {
				action: "capture",
				pid: 4321,
			}),
		).rejects.toThrow(/Must specify tracing bounds/);
	});

	it("validates that explicit QBDI engine requires scope: function and explicit scalar signature", async () => {
		const session = createTestSession("/tmp");
		const tool = new InstructionTraceTool(session);

		// QBDI without signature
		await expect(
			tool.execute("call-qbdi-no-sig", {
				action: "capture",
				pid: 1234,
				module: "libtarget.so",
				function: "verify",
				engine: "qbdi",
			}),
		).rejects.toThrow();
	});

	it("executeInstructionTrace captures chunked stream and writes Triton-compatible JSONL and manifest sidecar", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "trace-test-"));
		const tracePath = path.join(tempDir, "sample_trace.jsonl");

		// Synthetic trace records matching Triton parser specifications
		const records = [
			JSON.stringify({
				type: "registers",
				values: {
					x0: "0x7ffffff0",
					x1: "0x1234",
					sp: "0x7fffff00",
					pc: "0x401000",
					nzcv: "0x60000000",
				},
			}),
			JSON.stringify({
				type: "memory_read",
				address: "0x7ffffff0",
				size: 8,
				value: "0xdeadbeef",
			}),
			JSON.stringify({
				type: "instruction",
				address: "0x401000",
				bytes: "f9400002",
				size: 4,
				disasm: "ldr x2, [x0]",
			}),
			JSON.stringify({
				type: "registers",
				values: {
					x0: "0x7ffffff0",
					x1: "0x1234",
					x2: "0xdeadbeef",
					sp: "0x7fffff00",
					pc: "0x401004",
					nzcv: "0x60000000",
				},
			}),
			JSON.stringify({
				type: "instruction",
				address: "0x401004",
				bytes: "ca010040",
				size: 4,
				disasm: "eor x0, x2, x1",
			}),
		];

		const b64Chunk = Buffer.from(records.join("\n") + "\n", "utf-8").toString("base64");

		const mockMeta = {
			type: "meta",
			arch: "arm64",
			module: {
				name: "libsample.so",
				base: "0x400000",
				size: 65536,
				path: "/tmp/fake_libsample.so",
			},
			range_start: "0x401000",
			range_end: "0x402000",
		};

		const mockDone = {
			success: true,
			reason: "function_return",
			instruction_count: 2,
			unique_addresses: 2,
			memory_read_count: 1,
			duration_ms: 45,
			engine: "stalker",
			memory_reads_complete: true,
			thumb_mode: false,
			nzcv: "0x60000000",
		};

		const stdoutPayload = [
			`__INSTRUCTION_TRACE_META__${JSON.stringify(mockMeta)}__INSTRUCTION_TRACE_META_END__`,
			`__INSTRUCTION_TRACE_CHUNK__0:${b64Chunk}__INSTRUCTION_TRACE_CHUNK_END__`,
			`__INSTRUCTION_TRACE_DONE__${JSON.stringify(mockDone)}__INSTRUCTION_TRACE_DONE_END__`,
		].join("\n");

		const fakeRunner: FridaRunner = async () => ({
			exitCode: 0,
			stdout: Buffer.from(stdoutPayload, "utf-8"),
			stderr: "",
			outputBytes: Buffer.byteLength(stdoutPayload),
			truncated: false,
			timedOut: false,
		});

		try {
			const res = await executeInstructionTrace({
				pid: 9999,
				module: "libsample.so",
				function: "calc",
				artifactPath: tracePath,
				cwd: tempDir,
				runner: fakeRunner,
			});

			expect(res.success).toBe(true);
			expect(res.status).toBe("ok");
			expect(res.instructionCount).toBe(2);
			expect(res.memoryReadCount).toBe(1);
			expect(res.completionReason).toBe("function_return");
			expect(res.arch).toBe("arm64");

			// Verify written JSONL content
			const traceContent = await fs.readFile(tracePath, "utf-8");
			const lines = traceContent.trim().split("\n");
			expect(lines.length).toBe(5);

			const parsedFirst = JSON.parse(lines[0]);
			expect(parsedFirst.type).toBe("registers");
			expect(parsedFirst.values.x0).toBe("0x7ffffff0");
			expect(parsedFirst.values.sp).toBe("0x7fffff00");

			const parsedMem = JSON.parse(lines[1]);
			expect(parsedMem.type).toBe("memory_read");
			expect(parsedMem.address).toBe("0x7ffffff0");
			expect(parsedMem.size).toBe(8);
			expect(parsedMem.value).toBe("0xdeadbeef");

			const parsedIns = JSON.parse(lines[2]);
			expect(parsedIns.type).toBe("instruction");
			expect(parsedIns.address).toBe("0x401000");
			expect(parsedIns.bytes).toBe("f9400002");
			expect(parsedIns.disasm).toBe("ldr x2, [x0]");

			// Verify companion metadata sidecar manifest
			const manifestPath = `${tracePath}.manifest.json`;
			const manifestRaw = await fs.readFile(manifestPath, "utf-8");
			const manifest: InstructionTraceMetadata = JSON.parse(manifestRaw);

			expect(manifest.trace_version).toBe("1.0.0");
			expect(manifest.target.arch).toBe("arm64");
			expect(manifest.target.pid).toBe(9999);
			expect(manifest.stats.total_instructions).toBe(2);
			expect(manifest.stats.total_memory_reads).toBe(1);
			expect(manifest.stats.completion_reason).toBe("function_return");
			expect(manifest.flags.nzcv).toBe("0x60000000");

			// Verify Triton Replay Handoff
			expect(manifest.replay_handoff?.tool).toBe("triton_analyze");
			expect(manifest.replay_handoff?.valid).toBe(true);
			expect(manifest.replay_handoff?.params.action).toBe("replay");
			expect(manifest.replay_handoff?.params.trace).toBe(tracePath);
			expect(manifest.replay_handoff?.params.arch).toBe("aarch64");
			expect(manifest.replay_handoff?.params.output.target).toBe("x0");
			expect(manifest.replay_handoff?.params.initial_registers?.x0).toBe("0x7ffffff0");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("executeInstructionTrace correctly handles ARM32 canonical r14/lr mapping and Thumb mode", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "trace-arm32-"));
		const tracePath = path.join(tempDir, "arm32_trace.jsonl");

		const records = [
			JSON.stringify({
				type: "registers",
				values: {
					r0: "0x10",
					r1: "0x20",
					lr: "0x1008",
					r14: "0x1008", // Triton ARM32 link register mapping
					sp: "0x7000",
					pc: "0x1000",
					apsr: "0x20000000",
					cpsr: "0x20000000",
					z: 1,
					n: 0,
					c: 0,
					v: 0,
				},
			}),
			JSON.stringify({
				type: "instruction",
				address: "0x1000",
				bytes: "000050e1",
				size: 4,
				disasm: "cmp r0, r0",
			}),
		];

		const b64 = Buffer.from(records.join("\n") + "\n", "utf-8").toString("base64");

		const mockMeta = {
			type: "meta",
			arch: "arm",
			module: {
				name: "libthumb.so",
				base: "0x1000",
				size: 4096,
				path: "/tmp/fake_thumb.so",
			},
			thumb_mode: true,
		};

		const mockDone = {
			success: true,
			reason: "function_return",
			instruction_count: 1,
			unique_addresses: 1,
			memory_read_count: 0,
			duration_ms: 10,
			engine: "stalker",
			thumb_mode: true,
			cpsr: "0x20000000",
		};

		const stdoutPayload = [
			`__INSTRUCTION_TRACE_META__${JSON.stringify(mockMeta)}__INSTRUCTION_TRACE_META_END__`,
			`__INSTRUCTION_TRACE_CHUNK__0:${b64}__INSTRUCTION_TRACE_CHUNK_END__`,
			`__INSTRUCTION_TRACE_DONE__${JSON.stringify(mockDone)}__INSTRUCTION_TRACE_DONE_END__`,
		].join("\n");
		const fakeRunner: FridaRunner = async () => ({
			exitCode: 0,
			stdout: Buffer.from(stdoutPayload, "utf-8"),
			stderr: "",
			outputBytes: Buffer.byteLength(stdoutPayload),
			truncated: false,
			timedOut: false,
		});

		try {
			const res = await executeInstructionTrace({
				pid: 1234,
				module: "libthumb.so",
				function: "thumb_entry",
				artifactPath: tracePath,
				cwd: tempDir,
				runner: fakeRunner,
			});

			expect(res.success).toBe(true);
			expect(res.arch).toBe("arm");
			expect(res.metadata.flags.thumb_mode).toBe(true);
			expect(res.metadata.replay_handoff?.params.arch).toBe("arm32");
			expect(res.metadata.replay_handoff?.params.output.target).toBe("r0");
			expect(res.metadata.first_registers?.r14).toBe("0x1008");
			expect(res.metadata.first_registers?.lr).toBe("0x1008");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("enforces max_bytes limit and truncates gracefully", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "trace-limit-"));
		const tracePath = path.join(tempDir, "truncated.jsonl");

		// Large payload of instructions
		const singleRecord = JSON.stringify({
			type: "instruction",
			address: "0x1000",
			bytes: "00000000",
			size: 4,
			disasm: "nop",
		});
		const bigChunk = Buffer.from(Array(50).fill(singleRecord).join("\n") + "\n").toString("base64");

		const stdoutPayload = [
			`__INSTRUCTION_TRACE_META__${JSON.stringify({ arch: "x64" })}__INSTRUCTION_TRACE_META_END__`,
			`__INSTRUCTION_TRACE_CHUNK__0:${bigChunk}__INSTRUCTION_TRACE_CHUNK_END__`,
			`__INSTRUCTION_TRACE_CHUNK__1:${bigChunk}__INSTRUCTION_TRACE_CHUNK_END__`,
			`__INSTRUCTION_TRACE_DONE__{"success":true,"reason":"completed","instruction_count":100}__INSTRUCTION_TRACE_DONE_END__`,
		].join("\n");
		const fakeRunner: FridaRunner = async () => ({
			exitCode: 0,
			stdout: Buffer.from(stdoutPayload, "utf-8"),
			stderr: "",
			outputBytes: Buffer.byteLength(stdoutPayload),
			truncated: false,
			timedOut: false,
		});

		try {
			const res = await executeInstructionTrace({
				pid: 1111,
				module: "target",
				offset: 0,
				maxBytes: 1024, // Low max_bytes limit
				artifactPath: tracePath,
				cwd: tempDir,
				runner: fakeRunner,
			});

			expect(res.totalBytes).toBeLessThanOrEqual(1024);
			expect(res.status).toBe("truncated");
			expect(res.completionReason).toBe("max_bytes_exceeded");
			expect(res.metadata.stats.truncated).toBe(true);
			expect(res.metadata.replay_handoff?.valid).toBe(false);
			expect(res.metadata.replay_handoff?.notice).toContain("truncated");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("supports device: 'local' without passing -D local flag to Frida CLI", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "trace-local-"));
		const tracePath = path.join(tempDir, "local.jsonl");

		let capturedCliArgs: string[] = [];
		const stdoutPayload = [
			`__INSTRUCTION_TRACE_META__{"arch":"arm64"}__INSTRUCTION_TRACE_META_END__`,
			`__INSTRUCTION_TRACE_CHUNK__0:${Buffer.from('{"type":"instruction","address":"0x1000","bytes":"00000000","size":4,"disasm":"nop"}\n').toString("base64")}__INSTRUCTION_TRACE_CHUNK_END__`,
			`__INSTRUCTION_TRACE_DONE__{"success":true,"reason":"completed","instruction_count":1}__INSTRUCTION_TRACE_DONE_END__`,
		].join("\n");
		const fakeRunner: FridaRunner = async (_binary, args) => {
			capturedCliArgs = [...args];
			return {
				exitCode: 0,
				stdout: Buffer.from(stdoutPayload, "utf-8"),
				stderr: "",
				outputBytes: Buffer.byteLength(stdoutPayload),
				truncated: false,
				timedOut: false,
			};
		};

		try {
			await executeInstructionTrace({
				pid: 2222,
				module: "host_bin",
				function: "main",
				device: "local",
				artifactPath: tracePath,
				cwd: tempDir,
				runner: fakeRunner,
			});

			// Verify -D is not passed for local device, and staged script is passed via -l
			expect(capturedCliArgs).toContain("-l");
			expect(capturedCliArgs).not.toContain("-D");
			expect(capturedCliArgs).not.toContain("local");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("supports Salwan format output matching triton-analyze-worker specification", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "trace-salwan-"));
		const tracePath = path.join(tempDir, "salwan.trace");

		const salwanRecords = [
			"r:x0=0x7ffffff0:x1=0x1234:sp=0x7fffff00:pc=0x401000",
			"mr:0x7ffffff0:8:0xdeadbeef",
			"i:0x401000:4:f9400002:ldr x2, [x0]",
		];

		const b64 = Buffer.from(salwanRecords.join("\n") + "\n", "utf-8").toString("base64");

		const stdoutPayload = [
			`__INSTRUCTION_TRACE_META__{"arch":"arm64"}__INSTRUCTION_TRACE_META_END__`,
			`__INSTRUCTION_TRACE_CHUNK__0:${b64}__INSTRUCTION_TRACE_CHUNK_END__`,
			`__INSTRUCTION_TRACE_DONE__{"success":true,"reason":"completed","instruction_count":1,"memory_read_count":1}__INSTRUCTION_TRACE_DONE_END__`,
		].join("\n");
		const fakeRunner: FridaRunner = async () => ({
			exitCode: 0,
			stdout: Buffer.from(stdoutPayload, "utf-8"),
			stderr: "",
			outputBytes: Buffer.byteLength(stdoutPayload),
			truncated: false,
			timedOut: false,
		});

		try {
			const res = await executeInstructionTrace({
				pid: 3333,
				module: "salwan_test",
				function: "test",
				format: "salwan",
				artifactPath: tracePath,
				cwd: tempDir,
				runner: fakeRunner,
			});

			expect(res.success).toBe(true);
			const content = await fs.readFile(tracePath, "utf-8");
			expect(content).toContain("i:0x401000:4:f9400002:ldr x2, [x0]");
			expect(content).toContain("mr:0x7ffffff0:8:0xdeadbeef");
			expect(content).toContain("r:x0=0x7ffffff0");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("cleans up destination artifacts if publication fails", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "trace-pub-fail-"));
		const session = createTestSession(tempDir);
		const tool = new InstructionTraceTool(session);

		// Existing destination file to trigger safePublishArtifact conflict (COPYFILE_EXCL)
		const conflictDest = path.join(tempDir, "conflict.jsonl");
		await fs.writeFile(conflictDest, "existing data");

		await expect(
			tool.execute("call-conflict", {
				action: "capture",
				pid: 1234,
				module: "target",
				function: "main",
				output_path: "conflict.jsonl",
			}),
		).rejects.toThrow();

		// Ensure existing file was preserved and not overwritten
		const preserved = await fs.readFile(conflictDest, "utf-8");
		expect(preserved).toBe("existing data");
		await fs.rm(tempDir, { recursive: true, force: true });
	});

	it("rewrites metadata and manifest replay_handoff trace path to published destination across output_path", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "trace-pub-dest-"));

		const targetOutput = path.join(tempDir, "final_published.jsonl");
		const targetManifest = `${targetOutput}.manifest.json`;

		const mockMeta = {
			type: "meta",
			arch: "arm64",
			module: {
				name: "target",
				base: "0x1000",
				size: 4096,
			},
		};

		const mockDone = {
			success: true,
			reason: "function_return",
			instruction_count: 1,
			unique_addresses: 1,
			memory_read_count: 0,
			engine: "stalker",
			first_registers: {
				x0: "0x1",
				n: "0x0",
				z: "0x1",
				c: "0x1",
				v: "0x0",
			},
		};

		const stdoutPayload = [
			`__INSTRUCTION_TRACE_META__${JSON.stringify(mockMeta)}__INSTRUCTION_TRACE_META_END__`,
			`__INSTRUCTION_TRACE_CHUNK__0:${Buffer.from('{"type":"instruction","address":"0x1000","bytes":"00000000","size":4,"disasm":"nop"}\n').toString("base64")}__INSTRUCTION_TRACE_CHUNK_END__`,
			`__INSTRUCTION_TRACE_DONE__${JSON.stringify(mockDone)}__INSTRUCTION_TRACE_DONE_END__`,
		].join("\n");
		const fakeRunner: FridaRunner = async () => ({
			exitCode: 0,
			stdout: Buffer.from(stdoutPayload, "utf-8"),
			stderr: "",
			outputBytes: Buffer.byteLength(stdoutPayload),
			truncated: false,
			timedOut: false,
		});

		try {
			// Execute trace capture with output_path
			const res = await executeInstructionTrace({
				pid: 4444,
				module: "target",
				function: "main",
				outputPath: targetOutput,
				cwd: tempDir,
				runner: fakeRunner,
			});

			expect(res.success).toBe(true);
			expect(res.tracePath).toBe(targetOutput);
			expect(res.manifestPath).toBe(targetManifest);

			// Verify metadata sidecar persisted to disk points to targetOutput
			const manifestRaw = await fs.readFile(targetManifest, "utf-8");
			const manifest: InstructionTraceMetadata = JSON.parse(manifestRaw);
			expect(manifest.replay_handoff?.params.trace).toBe(targetOutput);

			// Verify first_registers contains string values
			expect(typeof manifest.first_registers?.n).toBe("string");
			expect(manifest.first_registers?.n).toBe("0x0");
			expect(manifest.first_registers?.z).toBe("0x1");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});

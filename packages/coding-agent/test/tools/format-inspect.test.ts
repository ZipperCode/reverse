import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { removeWithRetries } from "@reverse/utils";
import { Settings } from "../../src/config/settings";
import { resolveKaitaiToolchainReadiness } from "../../src/extensibility/protocol-toolchain";
import { ReverseWorkflowStore } from "../../src/reverse-workflow";
import { deterministicJsonStringify, hashBuffer } from "../../src/reverse-workspace";
import { FormatInspectTool, ReverseWorkflowTool, ReverseWorkspaceTool, type ToolSession } from "../../src/tools";
import { formatFieldAssertionSchema } from "../../src/tools/format-inspect";
function createTestSession(cwd: string, options?: { planMode?: boolean }): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		...(options?.planMode
			? {
					getPlanModeState: () => ({
						enabled: true,
						planFilePath: "local://format-inspect-plan.md",
					}),
				}
			: {}),
	};
}

function assertRealKaitaiToolchainOrActionableBlocker(): void {
	const readiness = resolveKaitaiToolchainReadiness();
	if (!readiness.ready) {
		throw new Error(
			`Actionable real-engine blocker: Kaitai toolchain is not ready (${readiness.incompatibilityReason ?? readiness.compiler.error ?? readiness.runtime.error ?? "missing dependencies"}). Missing: [${readiness.missingRequirements.join(", ")}]. Run: ${readiness.setupCommands.join(" && ")}`,
		);
	}
}

/**
 * 构造合成协议二进制样本：
 * - magic: "RVF1" (0..4)
 * - flags: u1 (4..5) -> bit0 控制可选 UTF-8 备注字段
 * - session_id: u8be (5..13) -> 64位大整数
 * - record_count: u2le (13..15)
 * - records: record_count * tlv_entry(tag: u1, val_le: u2le)
 * - [if flags & 1] opt_note_len: u1, opt_note: UTF-8 str
 * - plain_sub_len: u2be, plain_sub: plain_nested(inner_code: u2be, inner_val: u2le)
 * - masked_sub_len: u2be, masked_sub: xor(0xaa) -> masked_nested(secret_tag: u2be, secret_num: u2le)
 * - trailing: 可选尾部附加字节
 */
function buildSynthFrameSample(options?: {
	magic?: Buffer;
	flags?: number;
	sessionId?: bigint;
	records?: Array<{ tag: number; valLe: number }>;
	optNote?: string;
	plainSubLenOverride?: number;
	plainInnerCode?: number;
	plainInnerVal?: number;
	maskedSecretTag?: number;
	maskedSecretNum?: number;
	trailing?: Buffer;
}): Buffer {
	const magic = options?.magic ?? Buffer.from("RVF1", "ascii");
	const flags = options?.flags ?? 1;
	const sessionId = options?.sessionId ?? 18446744073709551613n; // 0xfffffffffffffffd (> MAX_SAFE_INTEGER)
	const records = options?.records ?? [
		{ tag: 0x11, valLe: 0x1234 },
		{ tag: 0x22, valLe: 0xabcd },
	];

	const chunks: Buffer[] = [magic, Buffer.from([flags & 0xff])];

	const u8Buf = Buffer.alloc(8);
	u8Buf.writeBigUInt64BE(sessionId, 0);
	chunks.push(u8Buf);

	const recCountBuf = Buffer.alloc(2);
	recCountBuf.writeUInt16LE(records.length, 0);
	chunks.push(recCountBuf);

	for (const rec of records) {
		const b = Buffer.alloc(3);
		b.writeUInt8(rec.tag & 0xff, 0);
		b.writeUInt16LE(rec.valLe & 0xffff, 1);
		chunks.push(b);
	}

	if ((flags & 1) !== 0) {
		const noteBytes = Buffer.from(options?.optNote ?? "ok!", "utf8");
		chunks.push(Buffer.from([noteBytes.length]), noteBytes);
	}

	const plainPayload = Buffer.alloc(4);
	plainPayload.writeUInt16BE(options?.plainInnerCode ?? 0xcafe, 0);
	plainPayload.writeUInt16LE(options?.plainInnerVal ?? 0x0506, 2);

	const plainLenBuf = Buffer.alloc(2);
	plainLenBuf.writeUInt16BE(options?.plainSubLenOverride ?? plainPayload.length, 0);
	chunks.push(plainLenBuf, plainPayload);

	const rawMaskedPayload = Buffer.alloc(4);
	rawMaskedPayload.writeUInt16BE(options?.maskedSecretTag ?? 0xbeef, 0);
	rawMaskedPayload.writeUInt16LE(options?.maskedSecretNum ?? 0x7788, 2);
	const xoredPayload = Buffer.from(rawMaskedPayload.map(byte => byte ^ 0xaa));

	const maskedLenBuf = Buffer.alloc(2);
	maskedLenBuf.writeUInt16BE(xoredPayload.length, 0);
	chunks.push(maskedLenBuf, xoredPayload);

	if (options?.trailing) {
		chunks.push(options.trailing);
	}

	return Buffer.concat(chunks);
}

const TLV_ENTRY_KSY = [
	"meta:",
	"  id: tlv_entry",
	"  endian: be",
	"seq:",
	"  - id: tag",
	"    type: u1",
	"  - id: val_le",
	"    type: u2le",
	"",
].join("\n");

const SYNTH_FRAME_KSY = [
	"meta:",
	"  id: synth_frame",
	"  endian: be",
	"  imports:",
	"    - tlv_entry",
	"seq:",
	"  - id: magic",
	"    contents: [0x52, 0x56, 0x46, 0x31]",
	"  - id: flags",
	"    type: u1",
	"  - id: session_id",
	"    type: u8",
	"  - id: record_count",
	"    type: u2le",
	"  - id: records",
	"    type: tlv_entry",
	"    repeat: expr",
	"    repeat-expr: record_count",
	"  - id: opt_note_len",
	"    type: u1",
	"    if: (flags & 1) != 0",
	"  - id: opt_note",
	"    type: str",
	"    encoding: UTF-8",
	"    size: opt_note_len",
	"    if: (flags & 1) != 0",
	"  - id: plain_sub_len",
	"    type: u2",
	"  - id: plain_sub",
	"    type: plain_nested",
	"    size: plain_sub_len",
	"  - id: masked_sub_len",
	"    type: u2",
	"  - id: masked_sub",
	"    type: masked_nested",
	"    size: masked_sub_len",
	"    process: xor(0xaa)",
	"instances:",
	"  lazy_header_word:",
	"    pos: 0",
	"    type: u4",
	"types:",
	"  plain_nested:",
	"    seq:",
	"      - id: inner_code",
	"        type: u2",
	"      - id: inner_val",
	"        type: u2le",
	"  masked_nested:",
	"    seq:",
	"      - id: secret_tag",
	"        type: u2",
	"      - id: secret_num",
	"        type: u2le",
	"",
].join("\n");

describe("format_inspect Kaitai executable protocol definition (Step 4)", () => {
	it("assigns read tier only to status, exec tier to compile/parse/validate, and rejects all write/exec actions in Plan mode before process execution", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fmt-inspect-planmode-"));
		try {
			const normalTool = new FormatInspectTool(createTestSession(tempDir));
			expect(normalTool.approval({ action: "status" })).toBe("read");
			expect(normalTool.approval({ action: "compile" })).toBe("exec");
			expect(normalTool.approval({ action: "parse" })).toBe("exec");
			expect(normalTool.approval({ action: "validate" })).toBe("exec");
			expect(normalTool.approval({})).toBe("exec");

			const assertionJsonSchema = formatFieldAssertionSchema.toJsonSchema() as {
				properties?: Record<string, unknown>;
			};
			expect(assertionJsonSchema.properties).toHaveProperty("equals");
			expect(assertionJsonSchema.properties).not.toHaveProperty("eq");
			const planTool = new FormatInspectTool(createTestSession(tempDir, { planMode: true }));
			const statusRes = await planTool.execute("plan-status", { action: "status" });
			expect(["ok", "missing_dependency"]).toContain(statusRes.details.status);

			await expect(
				planTool.execute("plan-compile", {
					action: "compile",
					workflow_id: "wf_1",
					step_id: "step_1",
					run_id: "run_1",
					schema_path: "packet.ksy",
				}),
			).rejects.toThrow(/Plan mode/i);

			await expect(
				planTool.execute("plan-parse", {
					action: "parse",
					workflow_id: "wf_1",
					step_id: "step_1",
					run_id: "run_1",
					manifest_path: "manifest.json",
					sample_path: "sample.bin",
				}),
			).rejects.toThrow(/Plan mode/i);

			await expect(
				planTool.execute("plan-validate", {
					action: "validate",
					workflow_id: "wf_1",
					step_id: "step_1",
					run_id: "run_1",
					manifest_path: "manifest.json",
					sample_paths: ["sample.bin"],
				}),
			).rejects.toThrow(/Plan mode/i);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("reports structured missing_dependency with actionable install commands when compiler or Python runtime is unavailable", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fmt-inspect-missingdeps-"));
		const emptyBinDir = path.join(tempDir, "empty_bin");
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		try {
			await fs.mkdir(emptyBinDir, { recursive: true });
			const samplePath = path.join(tempDir, "sample.bin");
			const schemaPath = path.join(tempDir, "minimal.ksy");
			await fs.writeFile(samplePath, Buffer.from([0x01, 0x02]));
			await fs.writeFile(schemaPath, "meta:\n  id: minimal\nseq:\n  - id: b\n    type: u2be\n", "utf8");

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);

			const wfRes = await wfTool.execute("wf-create", {
				action: "create",
				target: samplePath,
				goal: "Test missing dependencies reporting",
			});
			const workflowId = wfRes.details.workflow!.id;
			const stepId = wfRes.details.workflow!.steps[0]!.id;

			const beginRes = await wsTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Attempt compile with isolated empty toolchain",
				command: "format_inspect compile",
				inputs: ["minimal.ksy"],
			});
			const runId = beginRes.details.run_id!;

			const isolatedTool = new FormatInspectTool(session, {
				agentDir: emptyBinDir,
				env: {
					PATH: emptyBinDir,
					HOME: emptyBinDir,
					REVERSE_CODING_AGENT_DIR: emptyBinDir,
				},
				which: () => null,
				pythonPath: path.join(emptyBinDir, "nonexistent-python3"),
			});

			const statusRes = await isolatedTool.execute("st-miss", { action: "status" });
			expect(statusRes.details.status).toBe("missing_dependency");
			expect(statusRes.details.ready).toBe(false);
			expect(statusRes.details.missingTools).toContain("kaitai-struct-compiler");
			expect(statusRes.details.missingTools).toContain("kaitaistruct");
			expect(statusRes.details.setupCommands?.some(cmd => cmd.includes("kaitai-struct-compiler"))).toBe(true);
			expect(statusRes.details.setupCommands?.some(cmd => cmd.includes("kaitaistruct"))).toBe(true);

			const compileMiss = await isolatedTool.execute("comp-miss", {
				action: "compile",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				schema_path: "minimal.ksy",
			});
			expect(compileMiss.details.status).toBe("missing_dependency");
			expect(compileMiss.details.missingTools).toContain("kaitai-struct-compiler");

			// 若真实工具链就绪，先正常编译 manifest，再验证仅缺失 compiler（即使 Python kaitaistruct 可用）也会阻断 parse 与 validate
			const hostReadiness = resolveKaitaiToolchainReadiness();
			if (hostReadiness.ready && hostReadiness.runtime.pythonBin) {
				const realTool = new FormatInspectTool(session);
				const compiledForMiss = await realTool.execute("comp-real-for-miss", {
					action: "compile",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					schema_path: "minimal.ksy",
				});
				expect(compiledForMiss.details.status).toBe("ok");
				const compiledManifestRel = compiledForMiss.details.manifestRelativePath!;

				const noCompilerTool = new FormatInspectTool(session, {
					agentDir: emptyBinDir,
					env: {
						PATH: emptyBinDir,
						HOME: emptyBinDir,
						REVERSE_CODING_AGENT_DIR: emptyBinDir,
					},
					which: () => null,
					compilerPath: path.join(emptyBinDir, "nonexistent-kaitai-struct-compiler"),
					pythonPath: hostReadiness.runtime.pythonBin,
				});

				const parseNoCompiler = await noCompilerTool.execute("parse-miss-compiler", {
					action: "parse",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					manifest_path: compiledManifestRel,
					sample_path: "sample.bin",
				});
				expect(parseNoCompiler.details.status).toBe("missing_dependency");
				expect(parseNoCompiler.details.missingTools).toContain("kaitai-struct-compiler");

				const validateNoCompiler = await noCompilerTool.execute("validate-miss-compiler", {
					action: "validate",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					manifest_path: compiledManifestRel,
					sample_paths: ["sample.bin"],
				});
				expect(validateNoCompiler.details.status).toBe("missing_dependency");
				expect(validateNoCompiler.details.missingTools).toContain("kaitai-struct-compiler");
			}
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	}, 30_000);

	it("compiles, parses, and reuses prior-run manifests with real Kaitai compiler/runtime across magic, endian, length, arrays, conditional branches, unprocessed/processed substreams, uint64 strings, and lazy instances", async () => {
		assertRealKaitaiToolchainOrActionableBlocker();

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fmt-inspect-real-e2e-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		try {
			const schemasDir = path.join(tempDir, "schemas");
			const commonDir = path.join(schemasDir, "common");
			const samplesDir = path.join(tempDir, "samples");
			await fs.mkdir(commonDir, { recursive: true });
			await fs.mkdir(samplesDir, { recursive: true });

			const rootKsyPath = path.join(schemasDir, "synth_frame.ksy");
			const importKsyPath = path.join(commonDir, "tlv_entry.ksy");
			await fs.writeFile(rootKsyPath, SYNTH_FRAME_KSY, "utf8");
			await fs.writeFile(importKsyPath, TLV_ENTRY_KSY, "utf8");

			const sampleWithOptPath = path.join(samplesDir, "frame_opt.bin");
			const sampleNoOptPath = path.join(samplesDir, "frame_no_opt.bin");
			await fs.writeFile(sampleWithOptPath, buildSynthFrameSample({ flags: 1, optNote: "ok!" }));
			await fs.writeFile(
				sampleNoOptPath,
				buildSynthFrameSample({
					flags: 0,
					sessionId: 9223372036854775808n, // 2^63
					records: [{ tag: 0x7f, valLe: 0x0042 }],
				}),
			);

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const fmtTool = new FormatInspectTool(session);

			const statusRes = await fmtTool.execute("st-ready", { action: "status" });
			expect(statusRes.details.status).toBe("ok");
			expect(statusRes.details.ready).toBe(true);
			expect(statusRes.details.compatible).toBe(true);

			const wfRes = await wfTool.execute("wf-create", {
				action: "create",
				target: sampleWithOptPath,
				goal: "Verify SynthFrame Kaitai specification",
			});
			const workflowId = wfRes.details.workflow!.id;
			const stepId = wfRes.details.workflow!.steps[0]!.id;

			const beginRes = await wsTool.execute("ws-begin-1", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Compile synth_frame.ksy and parse binary samples",
				command: "format_inspect compile && format_inspect parse",
				inputs: ["schemas/synth_frame.ksy", "schemas/common/tlv_entry.ksy", "samples/frame_no_opt.bin"],
			});
			const runId = beginRes.details.run_id!;

			const compileRes = await fmtTool.execute("fmt-compile", {
				action: "compile",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				schema_path: "schemas/synth_frame.ksy",
				import_roots: ["schemas/common"],
			});
			expect(compileRes.details.error).toBeUndefined();
			expect(compileRes.details.status).toBe("ok");
			const manifest = compileRes.details.manifest!;
			const manifestRelPath = compileRes.details.manifestRelativePath!;
			expect(manifest.entry_module).toBe("synth_frame");
			expect(manifest.entry_class).toBe("SynthFrame");
			expect(manifest.schema_closure.map(c => c.meta_id)).toEqual(["synth_frame", "tlv_entry"]);
			expect(manifest.compiler.argv).toContain("--read-pos");
			expect(manifest.compiler.argv).toContain("python");
			expect(manifest.generated_sources).toHaveLength(2);

			// 校验所有编译产物权限均为 0600
			if (process.platform !== "win32") {
				for (const outAbs of compileRes.details.outputPaths ?? []) {
					const st = await fs.stat(outAbs);
					expect(st.mode & 0o777).toBe(0o600);
				}
			}

			// 解释元数据从已绑定的 KSY 重建，manifest 中自报的提示不能改变整数精度或子流地址。
			await fs.writeFile(
				path.join(tempDir, manifestRelPath),
				deterministicJsonStringify({
					...manifest,
					field_type_hints: Object.fromEntries(Object.keys(manifest.field_type_hints).map(key => [key, "u1"])),
					processed_field_hints: Object.fromEntries(
						Object.keys(manifest.processed_field_hints).map(key => [key, false]),
					),
				}),
				{ mode: 0o600 },
			);

			// 解析含条件分支样本（frame_opt.bin，总长 37 字节）
			const parseOptRes = await fmtTool.execute("fmt-parse-opt", {
				action: "parse",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				manifest_path: manifestRelPath,
				sample_path: "samples/frame_opt.bin",
			});
			expect(parseOptRes.details.status).toBe("ok");
			const pr = parseOptRes.details.parseResult!;
			expect(pr.ok).toBe(true);
			expect(pr.sample_size).toBe(37);
			expect(pr.consumed_bytes).toBe(37);
			expect(pr.trailing_bytes).toBe(0);
			expect(pr.trailing.count).toBe(0);

			// Lazy @property 实例绝不自动求值，仅记录在 root_lazy_instances_skipped
			expect(pr.root_lazy_instances_skipped).toContain("lazy_header_word");
			expect(pr.fields.some(f => f.path === "lazy_header_word")).toBe(false);

			const byPath = new Map(pr.fields.map(f => [f.path, f]));

			// magic: [0..4)
			expect(byPath.get("magic")).toMatchObject({
				type: "bytes",
				value: "52564631",
				stream_id: "root",
				start: 0,
				end: 4,
				file_start: 0,
				file_end: 4,
				processed: false,
			});

			// uint64: [5..13)，精确十进制字符串
			expect(byPath.get("session_id")).toMatchObject({
				type: "uint64",
				value: "18446744073709551613",
				stream_id: "root",
				start: 5,
				end: 13,
				file_start: 5,
				file_end: 13,
			});

			// 数组与导入子类型 + 小端字段：[15..21)
			expect(byPath.get("records")).toMatchObject({
				type: "array",
				value: 2,
				stream_id: "root",
				start: 15,
				end: 21,
			});
			expect(byPath.get("records[0].tag")).toMatchObject({
				type: "int",
				value: 0x11,
				stream_id: "root",
				start: 15,
				end: 16,
				file_start: 15,
				file_end: 16,
			});
			expect(byPath.get("records[1].val_le")).toMatchObject({
				type: "int",
				value: 0xabcd,
				stream_id: "root",
				start: 19,
				end: 21,
				file_start: 19,
				file_end: 21,
			});

			// 条件激活字段：[22..25)
			expect(byPath.get("opt_note")).toMatchObject({
				type: "str",
				value: "ok!",
				stream_id: "root",
				start: 22,
				end: 25,
			});

			// 未变换嵌套子流：stream_id 为 substream:plain_sub，流内偏移 0..2 / 2..4，且精确映射原文件偏移 27..29 / 29..31
			expect(byPath.get("plain_sub.inner_code")).toMatchObject({
				type: "int",
				value: 0xcafe,
				stream_id: "substream:plain_sub",
				start: 0,
				end: 2,
				file_start: 27,
				file_end: 29,
				file_offset: { start: 27, end: 29 },
				processed: false,
			});
			expect(byPath.get("plain_sub.inner_val")).toMatchObject({
				type: "int",
				value: 0x0506,
				stream_id: "substream:plain_sub",
				start: 2,
				end: 4,
				file_start: 29,
				file_end: 31,
				file_offset: { start: 29, end: 31 },
				processed: false,
			});

			// 经 xor(0xaa) 变换的嵌套子流：stream_id 为 substream:masked_sub，流内偏移 0..2 / 2..4，绝不伪造原文件偏移（file_offset: null）
			expect(byPath.get("masked_sub.secret_tag")).toMatchObject({
				type: "int",
				value: 0xbeef,
				stream_id: "substream:masked_sub",
				start: 0,
				end: 2,
				file_start: null,
				file_end: null,
				file_offset: null,
				processed: true,
			});
			expect(byPath.get("masked_sub.secret_num")).toMatchObject({
				type: "int",
				value: 0x7788,
				stream_id: "substream:masked_sub",
				start: 2,
				end: 4,
				file_start: null,
				file_end: null,
				file_offset: null,
				processed: true,
			});

			// 结束 run 1 并在新 run 中验证历史编译产物复用契约
			const run1Outputs = [
				...(compileRes.details.relativeOutputPaths ?? []),
				...(parseOptRes.details.relativeOutputPaths ?? []),
			];
			const recRes = await wsTool.execute("ws-rec-1", {
				action: "record",
				workflow_id: workflowId,
				run_id: runId,
				exit_code: 0,
				summary: "Compiled SynthFrame schema and verified opt frame",
				output_paths: run1Outputs,
			});
			expect(recRes.details.run?.status).toBe("succeeded");

			// Run 2：若 begin 未完整声明先前生成的 .py 引用，拒绝执行
			const beginIncomplete = await wsTool.execute("ws-begin-2", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Incomplete prior-run parser inputs test",
				command: "format_inspect parse",
				inputs: [
					manifestRelPath,
					"schemas/synth_frame.ksy",
					"schemas/common/tlv_entry.ksy",
					"samples/frame_no_opt.bin",
				],
			});
			await expect(
				fmtTool.execute("fmt-parse-incomplete-begin", {
					action: "parse",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: beginIncomplete.details.run_id!,
					manifest_path: manifestRelPath,
					sample_path: "samples/frame_no_opt.bin",
				}),
			).rejects.toThrow(/not declared in 'inputs' at 'begin'/i);

			// Run 3：begin 完整声明 manifest + KSY 闭包 + 生成 .py + 样本后，可安全复用历史解析器
			const beginComplete = await wsTool.execute("ws-begin-3", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Reuse prior-run compiled parser on frame_no_opt.bin",
				command: "format_inspect parse",
				inputs: [
					manifestRelPath,
					...manifest.schema_closure.map(c => c.path),
					...manifest.generated_sources.map(g => g.path),
					"samples/frame_no_opt.bin",
				],
			});
			const parseNoOptRes = await fmtTool.execute("fmt-parse-reused", {
				action: "parse",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: beginComplete.details.run_id!,
				manifest_path: manifestRelPath,
				sample_path: "samples/frame_no_opt.bin",
			});
			expect(parseNoOptRes.details.status).toBe("ok");
			const noOptFields = new Map(parseNoOptRes.details.parseResult!.fields.map(f => [f.path, f]));
			expect(noOptFields.has("opt_note")).toBe(false);
			expect(noOptFields.has("opt_note_len")).toBe(false);
			expect(noOptFields.get("session_id")?.value).toBe("9223372036854775808");
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	}, 30_000);

	it("handles wrong magic, length overrun, trailing bytes, negative corpus assertions, and compiler diagnostic failure retention without fake coverage claims", async () => {
		assertRealKaitaiToolchainOrActionableBlocker();

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fmt-inspect-negative-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		try {
			const schemasDir = path.join(tempDir, "schemas");
			const commonDir = path.join(schemasDir, "common");
			const samplesDir = path.join(tempDir, "samples");
			await fs.mkdir(commonDir, { recursive: true });
			await fs.mkdir(samplesDir, { recursive: true });

			await fs.writeFile(path.join(schemasDir, "synth_frame.ksy"), SYNTH_FRAME_KSY, "utf8");
			await fs.writeFile(path.join(commonDir, "tlv_entry.ksy"), TLV_ENTRY_KSY, "utf8");
			await fs.writeFile(
				path.join(schemasDir, "broken_expr.ksy"),
				"meta:\n  id: broken_expr\nseq:\n  - id: body\n    size: missing_len_symbol + 4\n",
				"utf8",
			);

			const goodPath = path.join(samplesDir, "good.bin");
			const wrongMagicPath = path.join(samplesDir, "wrong_magic.bin");
			const overrunPath = path.join(samplesDir, "overrun.bin");
			const trailingPath = path.join(samplesDir, "trailing.bin");

			await fs.writeFile(goodPath, buildSynthFrameSample({ flags: 0 }));
			await fs.writeFile(wrongMagicPath, buildSynthFrameSample({ magic: Buffer.from("NOPE", "ascii"), flags: 0 }));
			await fs.writeFile(overrunPath, buildSynthFrameSample({ flags: 0, plainSubLenOverride: 250 }));
			await fs.writeFile(
				trailingPath,
				buildSynthFrameSample({ flags: 0, trailing: Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x99]) }),
			);

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const fmtTool = new FormatInspectTool(session);

			const wfRes = await wfTool.execute("wf-create", {
				action: "create",
				target: goodPath,
				goal: "Negative and multi-sample validation",
			});
			const workflowId = wfRes.details.workflow!.id;
			const stepId = wfRes.details.workflow!.steps[0]!.id;

			const beginRes = await wsTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Test negative samples, trailing bytes, and broken expression compile diagnostics",
				command: "format_inspect compile/parse/validate",
				inputs: [
					"schemas/synth_frame.ksy",
					"schemas/common/tlv_entry.ksy",
					"schemas/broken_expr.ksy",
					"samples/wrong_magic.bin",
					"samples/overrun.bin",
					"samples/trailing.bin",
				],
			});
			const runId = beginRes.details.run_id!;

			// 1. 编译器表达式错误：保留 mode-0600 诊断失败报告并返回 KSY 路径
			const brokenCompile = await fmtTool.execute("compile-broken", {
				action: "compile",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				schema_path: "schemas/broken_expr.ksy",
			});
			expect(brokenCompile.details.status).toBe("error");
			expect(brokenCompile.details.compileFailureReport?.schema_path).toBe("schemas/broken_expr.ksy");
			expect(brokenCompile.details.reportPath).toBeTruthy();
			const brokenReportStat = await fs.stat(brokenCompile.details.reportPath!);
			expect(brokenReportStat.isFile()).toBe(true);
			if (process.platform !== "win32") {
				expect(brokenReportStat.mode & 0o777).toBe(0o600);
			}

			// 2. 编译合法 schema
			const compileRes = await fmtTool.execute("compile-ok", {
				action: "compile",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				schema_path: "schemas/synth_frame.ksy",
				import_roots: ["schemas/common"],
			});
			expect(compileRes.details.status).toBe("ok");
			const manifestRelPath = compileRes.details.manifestRelativePath!;

			// 3. wrongmagic：定位到 magic 字段起始偏移 0，且保留诊断报告
			const wrongMagicParse = await fmtTool.execute("parse-wrong-magic", {
				action: "parse",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				manifest_path: manifestRelPath,
				sample_path: "samples/wrong_magic.bin",
			});
			expect(wrongMagicParse.details.status).toBe("error");
			expect(wrongMagicParse.details.parseResult?.ok).toBe(false);
			expect(wrongMagicParse.details.parseResult?.error_kind).toBe("validation_failed");
			expect(wrongMagicParse.details.parseResult?.error_offset).toBe(0);
			expect(wrongMagicParse.details.parseResult?.error_field_path).toBe("magic");
			expect((await fs.stat(wrongMagicParse.details.reportPath!)).isFile()).toBe(true);

			// 4. overrun：长度越界触发 eof_overrun，报告精确流末尾错误偏移并保留此前已解析字段
			const overrunParse = await fmtTool.execute("parse-overrun", {
				action: "parse",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				manifest_path: manifestRelPath,
				sample_path: "samples/overrun.bin",
			});
			expect(overrunParse.details.status).toBe("error");
			const overrunRes = overrunParse.details.parseResult!;
			expect(overrunRes.ok).toBe(false);
			expect(overrunRes.error_kind).toBe("eof_overrun");
			expect(overrunRes.error_offset).toBe(overrunRes.sample_size);
			expect(overrunRes.error_field_path).toBe("plain_sub");
			expect(overrunRes.fields.some(f => f.path === "magic")).toBe(true);
			expect(overrunRes.fields.some(f => f.path === "plain_sub_len" && f.value === 250)).toBe(true);

			// 5. trailing：成功解析主体但精确记录 5 字节尾部残留
			const trailingParse = await fmtTool.execute("parse-trailing", {
				action: "parse",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				manifest_path: manifestRelPath,
				sample_path: "samples/trailing.bin",
			});
			expect(trailingParse.details.status).toBe("ok");
			expect(trailingParse.details.parseResult?.trailing_bytes).toBe(5);
			expect(trailingParse.details.parseResult?.trailing.preview_hex).toBe("deadbeef99");

			// 6. validate：混合正样本、预期失败反例（wrong_magic 满足预期）与故意失败的字段/尾部断言
			const valFailRes = await fmtTool.execute("validate-mixed", {
				action: "validate",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				manifest_path: manifestRelPath,
				sample_paths: ["samples/good.bin", "samples/wrong_magic.bin", "samples/trailing.bin"],
				sample_expectations: [
					{
						sample_path: "samples/good.bin",
						expect_success: true,
						max_trailing_bytes: 0,
						assertions: [
							{ path: "magic", type: "bytes", equals: "52564631", start: 0, end: 4 },
							{ path: "opt_note", exists: false },
							{ path: "flags", equals: 99 }, // 故意不匹配的断言，验证负断言检出与下一步建议绑定
						],
					},
					{
						sample_path: "samples/wrong_magic.bin",
						expect_success: false,
						expected_error_offset: 0,
					},
					{
						sample_path: "samples/trailing.bin",
						expect_success: true,
						max_trailing_bytes: 0, // 因有 5 字节 trailing 而失败
					},
				],
			});
			expect(valFailRes.details.status).toBe("error");
			const vr = valFailRes.details.validateReport!;
			expect(vr.coverage_claim).toBe("corpus_and_explicit_assertions_only");
			expect(vr.assurance_level).toBe("static_candidate");
			expect(vr.total_samples).toBe(3);
			expect(vr.samples_matching_expectation).toBe(2); // good.bin 与 wrong_magic.bin 的解析成败预期满足，trailing.bin 因 max_trailing_bytes:0 失败
			expect(vr.total_assertions).toBe(3);
			expect(vr.passed_assertions).toBe(2);
			expect(vr.failed_assertions).toBe(1);
			expect(vr.next_experiment_suggestions.some(s => s.includes("flags"))).toBe(true);
			expect(vr.next_experiment_suggestions.some(s => s.includes("trailing.bin"))).toBe(true);

			// 7. validate 全部正/负样本与显式字段断言均满足时返回 status: "ok"
			const valPassRes = await fmtTool.execute("validate-pass", {
				action: "validate",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				manifest_path: manifestRelPath,
				sample_paths: ["samples/good.bin", "samples/wrong_magic.bin"],
				sample_expectations: [
					{
						sample_path: "samples/good.bin",
						expect_success: true,
						max_trailing_bytes: 0,
						assertions: [
							{ path: "magic", type: "bytes", equals: "52564631", start: 0, end: 4 },
							{ path: "session_id", type: "uint64", equals: "18446744073709551613" },
							{ path: "masked_sub.secret_tag", equals: 0xbeef, file_start: null, file_end: null },
							{ path: "opt_note", exists: false },
						],
					},
					{
						sample_path: "samples/wrong_magic.bin",
						expect_success: false,
						expected_error_offset: 0,
						expected_error_contains: "ValidationNotEqualError",
					},
				],
			});
			expect(valPassRes.details.status).toBe("ok");
			expect(valPassRes.details.validateReport?.all_passed).toBe(true);
			expect(valPassRes.details.validateReport?.assertion_satisfaction_rate).toBe(1);
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	}, 30_000);

	it("rejects custom processors, opaque external types, implicit KSPATH imports, network/escaping/symlink paths, overwriting outputs, import drift, generated parser drift, and forged open()+self-hash parsers with 0 execution", async () => {
		assertRealKaitaiToolchainOrActionableBlocker();

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fmt-inspect-security-"));
		const outsideDir = await fs.mkdtemp(path.join(os.tmpdir(), "fmt-inspect-outside-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		try {
			const schemasDir = path.join(tempDir, "schemas");
			const commonDir = path.join(schemasDir, "common");
			await fs.mkdir(commonDir, { recursive: true });

			const samplePath = path.join(tempDir, "sample.bin");
			await fs.writeFile(samplePath, buildSynthFrameSample({ flags: 0 }));

			await fs.writeFile(path.join(schemasDir, "synth_frame.ksy"), SYNTH_FRAME_KSY, "utf8");
			await fs.writeFile(path.join(commonDir, "tlv_entry.ksy"), TLV_ENTRY_KSY, "utf8");

			const customProcKsy = path.join(schemasDir, "custom_proc.ksy");
			await fs.writeFile(
				customProcKsy,
				"meta:\n  id: custom_proc\nseq:\n  - id: data\n    size: 4\n    process: evil_cipher(0x11)\n",
				"utf8",
			);

			const opaqueFlagKsy = path.join(schemasDir, "opaque_flag.ksy");
			await fs.writeFile(
				opaqueFlagKsy,
				"meta:\n  id: opaque_flag\n  ks-opaque-types: true\nseq:\n  - id: ext\n    type: external_blob\n",
				"utf8",
			);

			const opaqueUnresolvedKsy = path.join(schemasDir, "opaque_unresolved.ksy");
			await fs.writeFile(
				opaqueUnresolvedKsy,
				"meta:\n  id: opaque_unresolved\nseq:\n  - id: ext\n    type: undeclared_foreign_struct\n",
				"utf8",
			);

			const implicitStdlibKsy = path.join(schemasDir, "implicit_stdlib.ksy");
			await fs.writeFile(
				implicitStdlibKsy,
				"meta:\n  id: implicit_stdlib\n  imports:\n    - common/vlq_base128_le\nseq:\n  - id: v\n    type: vlq_base128_le\n",
				"utf8",
			);

			const badIdentKsy = path.join(schemasDir, "bad_ident.ksy");
			await fs.writeFile(badIdentKsy, "meta:\n  id: os\nseq:\n  - id: x\n    type: u1\n", "utf8");

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const fmtTool = new FormatInspectTool(session);

			const wfRes = await wfTool.execute("wf-create", {
				action: "create",
				target: samplePath,
				goal: "Security and drift boundary verification",
			});
			const workflowId = wfRes.details.workflow!.id;
			const stepId = wfRes.details.workflow!.steps[0]!.id;

			const beginRes = await wsTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Security boundary checks",
				command: "format_inspect compile/parse",
				inputs: [
					"schemas/synth_frame.ksy",
					"schemas/common/tlv_entry.ksy",
					"schemas/custom_proc.ksy",
					"schemas/opaque_flag.ksy",
					"schemas/opaque_unresolved.ksy",
					"schemas/implicit_stdlib.ksy",
					"schemas/bad_ident.ksy",
				],
			});
			const runId = beginRes.details.run_id!;

			const baseCompile = {
				action: "compile" as const,
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
			};

			// 1. 拒绝自定义 processor
			await expect(
				fmtTool.execute("rej-custom-proc", { ...baseCompile, schema_path: "schemas/custom_proc.ksy" }),
			).rejects.toThrow(/Custom processor/i);

			// 2. 拒绝 ks-opaque-types 与未解析外部类型
			await expect(
				fmtTool.execute("rej-opaque-flag", { ...baseCompile, schema_path: "schemas/opaque_flag.ksy" }),
			).rejects.toThrow(/Opaque external types/i);

			await expect(
				fmtTool.execute("rej-opaque-type", { ...baseCompile, schema_path: "schemas/opaque_unresolved.ksy" }),
			).rejects.toThrow(/Unresolved or opaque external type/i);

			// 3. 拒绝隐式标准库（未显式声明本地 import_roots 或本地不存在该 KSY）
			await expect(
				fmtTool.execute("rej-implicit-lib", { ...baseCompile, schema_path: "schemas/implicit_stdlib.ksy" }),
			).rejects.toThrow(/import_roots/i);

			await expect(
				fmtTool.execute("rej-implicit-lib-2", {
					...baseCompile,
					schema_path: "schemas/implicit_stdlib.ksy",
					import_roots: ["schemas"],
				}),
			).rejects.toThrow(/not found in any declared import_roots/i);

			// 4. 拒绝保留/危险模块名标识符
			await expect(
				fmtTool.execute("rej-bad-ident", { ...baseCompile, schema_path: "schemas/bad_ident.ksy" }),
			).rejects.toThrow(/Reserved or prohibited/i);

			// 5. 拒绝网络 URL、目录越界与软链 import_roots
			await expect(
				fmtTool.execute("rej-url-root", {
					...baseCompile,
					schema_path: "schemas/synth_frame.ksy",
					import_roots: ["https://example.com/ksy"],
				}),
			).rejects.toThrow(/Network or URI path is prohibited/i);

			await expect(
				fmtTool.execute("rej-escape-root", {
					...baseCompile,
					schema_path: "schemas/synth_frame.ksy",
					import_roots: [outsideDir],
				}),
			).rejects.toThrow(/Invalid import_roots/i);

			const symlinkRoot = path.join(tempDir, "symlink_imports");
			await fs.symlink(outsideDir, symlinkRoot);
			await expect(
				fmtTool.execute("rej-symlink-root", {
					...baseCompile,
					schema_path: "schemas/synth_frame.ksy",
					import_roots: ["symlink_imports"],
				}),
			).rejects.toThrow(/Invalid import_roots|Symlink/i);

			// 6. 拒绝 run 目录之外的项目相对 output_path、拒绝覆盖当前 run 的完整 run.json 路径、拒绝覆盖已存在产物
			await expect(
				fmtTool.execute("rej-outside-run-output", {
					...baseCompile,
					schema_path: "schemas/synth_frame.ksy",
					import_roots: ["schemas/common"],
					output_path: "reports/outside_run_manifest.json",
				}),
			).rejects.toThrow(/Invalid output path[\s\S]*(?:escapes allowed directory|outside)/i);

			await expect(
				fmtTool.execute("rej-overwrite-meta", {
					...baseCompile,
					schema_path: "schemas/synth_frame.ksy",
					import_roots: ["schemas/common"],
					output_path: beginRes.details.paths!.relative.run_json,
				}),
			).rejects.toThrow(/Cannot overwrite internal run metadata/i);

			const explicitManifestOutput = path.join(beginRes.details.paths!.relative.reports_dir, "fixed_manifest.json");
			const compileOk = await fmtTool.execute("compile-valid", {
				...baseCompile,
				schema_path: "schemas/synth_frame.ksy",
				import_roots: ["schemas/common"],
				output_path: explicitManifestOutput,
			});
			expect(compileOk.details.status).toBe("ok");
			const manifestRel = compileOk.details.manifestRelativePath!;
			expect(manifestRel).toBe(explicitManifestOutput);

			await expect(
				fmtTool.execute("rej-overwrite-existing", {
					...baseCompile,
					schema_path: "schemas/synth_frame.ksy",
					import_roots: ["schemas/common"],
					output_path: explicitManifestOutput,
				}),
			).rejects.toThrow(/already exists; refusing to overwrite/i);
			// 7. import drift：编译后篡改导入的 tlv_entry.ksy，parse 在执行前检测到哈希漂移并拒绝
			const importKsyAbs = path.join(commonDir, "tlv_entry.ksy");
			await fs.writeFile(importKsyAbs, `${TLV_ENTRY_KSY}# drifted comment\n`, "utf8");
			await expect(
				fmtTool.execute("rej-import-drift", {
					action: "parse",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					manifest_path: manifestRel,
					sample_path: "sample.bin",
				}),
			).rejects.toThrow(/changed since run began|drift detected/i);
			// 恢复原导入文件以继续测试 generated drift
			await fs.writeFile(importKsyAbs, TLV_ENTRY_KSY, "utf8");

			// 8. generated drift：篡改编译生成的 .py 源码，parse 检测到生成文件哈希不匹配并拒绝执行
			const entryGenRel = compileOk.details.generatedSources!.find(g => g.is_entry)!.path;
			const entryGenAbs = path.join(tempDir, entryGenRel);
			const origPy = await fs.readFile(entryGenAbs, "utf8");
			await fs.writeFile(entryGenAbs, `${origPy}\n# tampered line\n`, "utf8");
			await expect(
				fmtTool.execute("rej-generated-drift", {
					action: "parse",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					manifest_path: manifestRel,
					sample_path: "sample.bin",
				}),
			).rejects.toThrow(/Generated parser drift detected/i);

			// 9. 伪造无额外 import 的 open() 副作用解析器 + 自洽 manifest 自哈希（且在新 run begin 中合法声明输入）：
			//    必须通过私有规范重编译比对全量源码哈希予以拦截，实现 0 执行（不产生任何文件副作用）
			await fs.writeFile(entryGenAbs, origPy, "utf8");
			const sideEffectMarker = path.join(tempDir, "forged_side_effect_marker.txt");
			const forgedGenRel = path.join(
				beginRes.details.paths!.relative.scripts_dir,
				"kaitai_gen_forged",
				"synth_frame.py",
			);
			const forgedGenAbs = path.join(tempDir, forgedGenRel);
			await fs.mkdir(path.dirname(forgedGenAbs), { recursive: true });

			// 保持官方 banner、类名、SEQ_FIELDS、self._debug 与原有合法 import，不引入任何新 import，仅注入内置 open() 写入副作用
			const forgedPyText = `${origPy}\nopen(${JSON.stringify(sideEffectMarker)}, "wb").write(b"FORGED_EXECUTED")\n`;
			const forgedPyBuf = Buffer.from(forgedPyText, "utf8");
			await fs.writeFile(forgedGenAbs, forgedPyBuf, { mode: 0o600 });
			const forgedPyHash = hashBuffer(forgedPyBuf);

			const forgedManifestRel = path.join(
				beginRes.details.paths!.relative.reports_dir,
				"forged_selfhash.manifest.json",
			);
			const forgedManifestAbs = path.join(tempDir, forgedManifestRel);
			const baseManifestObj = compileOk.details.manifest!;
			const forgedManifestObj = {
				...baseManifestObj,
				generated_sources: baseManifestObj.generated_sources.map(g =>
					g.is_entry
						? {
								...g,
								path: forgedGenRel,
								sha256: forgedPyHash.sha256,
								size_bytes: forgedPyHash.size,
							}
						: g,
				),
			};
			await fs.writeFile(forgedManifestAbs, deterministicJsonStringify(forgedManifestObj), { mode: 0o600 });

			const beginForged = await wsTool.execute("ws-begin-forged", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Attempt forged parser + matching manifest self-hash execution",
				command: "format_inspect parse/validate",
				inputs: [
					forgedManifestRel,
					...forgedManifestObj.schema_closure.map(c => c.path),
					...forgedManifestObj.generated_sources.map(g => g.path),
					"sample.bin",
				],
			});
			const forgedRunId = beginForged.details.run_id!;

			await expect(
				fmtTool.execute("rej-forged-parse", {
					action: "parse",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: forgedRunId,
					manifest_path: forgedManifestRel,
					sample_path: "sample.bin",
				}),
			).rejects.toThrow(/Canonical Kaitai source verification failed/i);

			await expect(
				fmtTool.execute("rej-forged-validate", {
					action: "validate",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: forgedRunId,
					manifest_path: forgedManifestRel,
					sample_paths: ["sample.bin"],
				}),
			).rejects.toThrow(/Canonical Kaitai source verification failed/i);

			await expect(fs.lstat(sideEffectMarker)).rejects.toThrow(/ENOENT/i);
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(outsideDir);
			await removeWithRetries(tempDir);
		}
	}, 30_000);

	it("enforces bounded input/depth/fields/output limits, reports truthful platform resource limits, and honors AbortSignal cancellation", async () => {
		assertRealKaitaiToolchainOrActionableBlocker();

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fmt-inspect-limits-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		try {
			const schemasDir = path.join(tempDir, "schemas");
			const commonDir = path.join(schemasDir, "common");
			await fs.mkdir(commonDir, { recursive: true });

			await fs.writeFile(path.join(schemasDir, "synth_frame.ksy"), SYNTH_FRAME_KSY, "utf8");
			await fs.writeFile(path.join(commonDir, "tlv_entry.ksy"), TLV_ENTRY_KSY, "utf8");

			const manyRecords = Array.from({ length: 40 }, (_, i) => ({ tag: i & 0xff, valLe: 1000 + i }));
			const bigArraySamplePath = path.join(tempDir, "many_records.bin");
			await fs.writeFile(bigArraySamplePath, buildSynthFrameSample({ flags: 1, records: manyRecords }));

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const fmtTool = new FormatInspectTool(session);

			const wfRes = await wfTool.execute("wf-create", {
				action: "create",
				target: bigArraySamplePath,
				goal: "Verify parser bounds and cancellation",
			});
			const workflowId = wfRes.details.workflow!.id;
			const stepId = wfRes.details.workflow!.steps[0]!.id;

			const beginRes = await wsTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Verify execution limits and cancellation",
				command: "format_inspect compile && format_inspect parse",
				inputs: ["schemas/synth_frame.ksy", "schemas/common/tlv_entry.ksy"],
			});
			const runId = beginRes.details.run_id!;

			const compileRes = await fmtTool.execute("compile-limits", {
				action: "compile",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				schema_path: "schemas/synth_frame.ksy",
				import_roots: ["schemas/common"],
			});
			expect(compileRes.details.status).toBe("ok");
			const manifestRel = compileRes.details.manifestRelativePath!;

			// 1. max_input_bytes 上限拦截
			await expect(
				fmtTool.execute("limit-input-bytes", {
					action: "parse",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					manifest_path: manifestRel,
					sample_path: "many_records.bin",
					max_input_bytes: 16,
				}),
			).rejects.toThrow(/exceeds max_input_bytes/i);

			// 2. max_fields 上限裁剪
			const fieldsCapRes = await fmtTool.execute("limit-max-fields", {
				action: "parse",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				manifest_path: manifestRel,
				sample_path: "many_records.bin",
				max_fields: 5,
			});
			expect(fieldsCapRes.details.status).toBe("ok");
			expect(fieldsCapRes.details.parseResult?.fields).toHaveLength(5);
			expect(fieldsCapRes.details.parseResult?.truncated).toBe(true);
			expect(fieldsCapRes.details.parseResult?.truncation_reason).toBe("max_fields_exceeded");

			// 3. max_depth 上限裁剪（depth=1 仅保留顶层字段，不展开数组元素或子流内部字段）
			const depthCapRes = await fmtTool.execute("limit-max-depth", {
				action: "parse",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				manifest_path: manifestRel,
				sample_path: "many_records.bin",
				max_depth: 1,
			});
			expect(depthCapRes.details.status).toBe("ok");
			expect(depthCapRes.details.parseResult?.truncated).toBe(true);
			expect(depthCapRes.details.parseResult?.truncation_reason).toBe("max_depth_exceeded");
			expect(depthCapRes.details.parseResult?.fields.some(f => f.path.includes("."))).toBe(false);
			expect(depthCapRes.details.parseResult?.fields.some(f => f.path.includes("["))).toBe(false);

			// 4. max_output_bytes 输出 JSON 字节上限裁剪 + 如实报告平台资源限制模型
			const outputCapRes = await fmtTool.execute("limit-max-output", {
				action: "parse",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				manifest_path: manifestRel,
				sample_path: "many_records.bin",
				max_output_bytes: 2048,
			});
			expect(outputCapRes.details.status).toBe("ok");
			expect(outputCapRes.details.parseResult?.output_truncated).toBe(true);
			expect(outputCapRes.details.parseResult?.truncation_reason).toBe("max_output_bytes_exceeded");
			expect(outputCapRes.details.resourceLimits?.isolation_model).toBe("subprocess_staging_not_security_sandbox");
			expect(typeof outputCapRes.details.resourceLimits?.rlimit_cpu.enforced).toBe("boolean");
			expect(typeof outputCapRes.details.resourceLimits?.rlimit_as.enforced).toBe("boolean");

			// 5. AbortSignal 取消（预先取消与运行中途取消）
			const preAborted = new AbortController();
			preAborted.abort();
			await expect(
				fmtTool.execute(
					"cancel-pre",
					{
						action: "parse",
						workflow_id: workflowId,
						step_id: stepId,
						run_id: runId,
						manifest_path: manifestRel,
						sample_path: "many_records.bin",
					},
					preAborted.signal,
				),
			).rejects.toThrow(/abort|cancel/i);

			const midAbort = new AbortController();
			const pendingMidCompile = fmtTool.execute(
				"cancel-mid",
				{
					action: "compile",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					schema_path: "schemas/synth_frame.ksy",
					import_roots: ["schemas/common"],
				},
				midAbort.signal,
			);
			queueMicrotask(() => midAbort.abort());
			await expect(pendingMidCompile).rejects.toThrow(/abort|cancel/i);
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	}, 30_000);
});

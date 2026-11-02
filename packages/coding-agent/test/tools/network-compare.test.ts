import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { removeWithRetries } from "@reverse/utils";
import { Settings } from "../../src/config/settings";
import { EvidenceStore } from "../../src/evidence";
import { hashBuffer, type AnalysisRunRecord } from "../../src/reverse-workspace";
import { AppExperimentTool, ReverseWorkflowTool, ReverseWorkspaceTool, type ToolSession } from "../../src/tools";
import {
	writePrivateRunArtifactFile,
	type ReplayCaseSourceFormat,
	type ReplayCaseV1,
} from "../../src/tools/app-experiment";

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
						planFilePath: "local://network-compare-plan.md",
					}),
				}
			: {}),
	};
}

async function createTargetFixture(dir: string, name = "target_app.bin"): Promise<string> {
	const filePath = path.join(dir, name);
	await fs.writeFile(filePath, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 9, 8, 7, 6]));
	return filePath;
}

const NO_NETWORK_FETCHER: typeof fetch = (async () => {
	throw new Error("Unexpected network call during offline network_compare");
}) as unknown as typeof fetch;

async function writeCanonicalCaseArtifact(options: {
	projectDir: string;
	dumpsDir: string;
	workflowId: string;
	stepId: string;
	runId: string;
	sourceFile: string;
	sourceFormat?: ReplayCaseSourceFormat;
	stem: string;
	caseId: string;
	method?: string;
	url?: string;
	requestHeaders?: Array<{ name: string; value: string }>;
	requestBody: Buffer | null;
	requestRepresentation?: "none" | "captured_raw_bytes" | "decoded_entity_bytes" | "text_reencoded";
	requestCompleteness?: "empty" | "complete" | "truncated" | "missing";
	requestContentEncoding?: string;
	response?: {
		status: number;
		statusText?: string;
		headers?: Array<{ name: string; value: string }>;
		body: Buffer | null;
		representation?: "none" | "captured_raw_bytes" | "decoded_entity_bytes" | "text_reencoded";
		completeness?: "empty" | "complete" | "truncated" | "missing";
		contentEncoding?: string;
	} | null;
}): Promise<{ casePath: string; caseRelativePath: string; bodyRelativePaths: string[] }> {
	const bodyRelativePaths: string[] = [];

	const sourceAbs = path.resolve(options.projectDir, options.sourceFile);
	const sourceInfo = hashBuffer(await fs.readFile(sourceAbs));
	const sourceRel = path.relative(options.projectDir, sourceAbs).replace(/\\/g, "/");

	let reqBodyPathRel: string | null = null;
	let reqSha: string | null = null;
	let reqSize = 0;
	const reqComp =
		options.requestCompleteness ??
		(options.requestBody === null ? "missing" : options.requestBody.byteLength === 0 ? "empty" : "complete");
	const reqRep =
		options.requestRepresentation ?? (reqComp === "missing" || reqComp === "empty" ? "none" : "captured_raw_bytes");

	if (options.requestBody !== null) {
		const reqAbs = path.join(options.dumpsDir, `${options.stem}.request.body.bin`);
		const written = await writePrivateRunArtifactFile(reqAbs, options.requestBody);
		reqBodyPathRel = path.relative(options.projectDir, reqAbs).replace(/\\/g, "/");
		reqSha = written.sha256;
		reqSize = written.size_bytes;
		bodyRelativePaths.push(reqBodyPathRel);
	}

	let recordedResponse: ReplayCaseV1["recorded_response"];
	if (options.response !== null && options.response !== undefined) {
		let respPathRel: string | null = null;
		let respSha: string | null = null;
		let respSize = 0;
		const respComp =
			options.response.completeness ??
			(options.response.body === null ? "missing" : options.response.body.byteLength === 0 ? "empty" : "complete");
		const respRep =
			options.response.representation ??
			(respComp === "missing" || respComp === "empty" ? "none" : "captured_raw_bytes");

		if (options.response.body !== null) {
			const respAbs = path.join(options.dumpsDir, `${options.stem}.response.body.bin`);
			const written = await writePrivateRunArtifactFile(respAbs, options.response.body);
			respPathRel = path.relative(options.projectDir, respAbs).replace(/\\/g, "/");
			respSha = written.sha256;
			respSize = written.size_bytes;
			bodyRelativePaths.push(respPathRel);
		}

		recordedResponse = {
			status: options.response.status,
			status_text: options.response.statusText ?? "OK",
			headers: options.response.headers ?? [{ name: "Content-Type", value: "application/json" }],
			body: {
				path: respPathRel,
				sha256: respSha,
				size_bytes: respSize,
				representation: respRep,
				completeness: respComp,
				...(options.response.contentEncoding ? { content_encoding: options.response.contentEncoding } : {}),
			},
		};
	} else {
		recordedResponse = {
			status: 0,
			status_text: "unrecorded",
			headers: [],
			body: {
				path: null,
				sha256: null,
				size_bytes: 0,
				representation: "none",
				completeness: "missing",
			},
		};
	}

	const doc: ReplayCaseV1 = {
		schema_version: "1",
		case_id: options.caseId,
		workflow_id: options.workflowId,
		step_id: options.stepId,
		run_id: options.runId,
		created_at: new Date().toISOString(),
		source: {
			path: sourceRel,
			sha256: sourceInfo.sha256,
			size_bytes: sourceInfo.size,
			format: options.sourceFormat ?? "generated",
			entry_id: options.caseId,
			entry_index: 0,
			selector: { kind: "entry_index", value: 0 },
		},
		request: {
			method: options.method ?? "POST",
			url: options.url ?? "https://api.example.com/v1/sign-check?ver=2",
			headers: options.requestHeaders ?? [
				{ name: "Content-Type", value: "application/json" },
				{ name: "X-Duplicate-Tag", value: "alpha" },
				{ name: "X-Duplicate-Tag", value: "beta" },
			],
			body: {
				path: reqBodyPathRel,
				sha256: reqSha,
				size_bytes: reqSize,
				representation: reqRep,
				completeness: reqComp,
				...(options.requestContentEncoding ? { content_encoding: options.requestContentEncoding } : {}),
			},
			credential_slots: [],
		},
		recorded_response: recordedResponse,
		replay_ready: reqComp === "complete" || reqComp === "empty",
		blocked_prerequisites: [],
	};

	const caseAbs = path.join(options.dumpsDir, `${options.stem}.case.json`);
	await writePrivateRunArtifactFile(caseAbs, `${JSON.stringify(doc, null, 2)}\n`);
	const caseRel = path.relative(options.projectDir, caseAbs).replace(/\\/g, "/");
	return {
		casePath: caseAbs,
		caseRelativePath: caseRel,
		bodyRelativePaths,
	};
}

describe("app_experiment network_compare offline comparison (Step 3)", () => {
	it("enforces write approval tier and blocks execution in read-only Plan mode without touching files or network", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-compare-plan-"));
		try {
			const normalTool = new AppExperimentTool(createTestSession(tempDir), {
				fetcher: NO_NETWORK_FETCHER,
			});
			expect(normalTool.approval({ action: "network_compare" })).toBe("write");

			const planTool = new AppExperimentTool(createTestSession(tempDir, { planMode: true }), {
				fetcher: NO_NETWORK_FETCHER,
			});
			await expect(
				planTool.execute("cmp-plan", {
					action: "network_compare",
					workflow_id: "wf_1",
					step_id: "step_1",
					run_id: "run_1",
					left_case: "left.json",
					right_case: "right.json",
				}),
			).rejects.toThrow("Plan mode is read-only");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("keeps dynamic fields (nonce/timestamp/sign/token) as differences by default and preserves raw_equal=false + ignored_diffs when explicitly ignored via RFC 6901 JSON Pointer", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-compare-dynamic-"));
		try {
			const targetFile = await createTargetFixture(tempDir);
			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const appTool = new AppExperimentTool(session, { fetcher: NO_NETWORK_FETCHER });

			const wfRes = await wfTool.execute("wf-create", {
				action: "create",
				target: targetFile,
				format: "ELF",
				goal: "Verify candidate request generator against captured baseline",
			});
			const workflowId = wfRes.details.workflow!.id;
			const stepId = wfRes.details.workflow!.steps[0]!.id;

			const beginRes = await wsTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Compare captured request with candidate implementation output",
				command: "app_experiment(action: 'network_compare')",
			});
			const runId = beginRes.details.run_id!;
			const runPaths = beginRes.details.paths!;

			const leftReqJson = {
				op: "transfer",
				amount: 100,
				nonce: "nonce_aaa",
				timestamp: 1700000001,
				sign: "hmac_left_111",
				meta: { token_hint: "t1", channel: "app" },
			};
			const rightReqJson = {
				op: "transfer",
				amount: 100,
				nonce: "nonce_bbb",
				timestamp: 1700000099,
				sign: "hmac_right_222",
				meta: { token_hint: "t2", channel: "app" },
			};

			const leftRespJson = { code: 0, receipt: { id: "rcpt_1", server_ts: 10 } };
			const rightRespJson = { code: 0, receipt: { id: "rcpt_1", server_ts: 20 } };

			const leftCase = await writeCanonicalCaseArtifact({
				projectDir: tempDir,
				dumpsDir: runPaths.dumps_dir,
				workflowId,
				stepId,
				runId,
				sourceFile: targetFile,
				sourceFormat: "har",
				stem: "captured_base",
				caseId: "case_captured_base",
				requestBody: Buffer.from(JSON.stringify(leftReqJson), "utf8"),
				response: {
					status: 200,
					headers: [
						{ name: "Content-Type", value: "application/json" },
						{ name: "X-Gateway", value: "gw-a" },
					],
					body: Buffer.from(JSON.stringify(leftRespJson), "utf8"),
				},
			});

			const rightCase = await writeCanonicalCaseArtifact({
				projectDir: tempDir,
				dumpsDir: runPaths.dumps_dir,
				workflowId,
				stepId,
				runId,
				sourceFile: targetFile,
				sourceFormat: "generated",
				stem: "candidate_gen",
				caseId: "case_candidate_gen",
				requestBody: Buffer.from(JSON.stringify(rightReqJson), "utf8"),
				response: {
					status: 200,
					headers: [
						{ name: "Content-Type", value: "application/json" },
						{ name: "X-Gateway", value: "gw-a" },
					],
					body: Buffer.from(JSON.stringify(rightRespJson), "utf8"),
				},
			});

			// 1. 默认对比：绝不默认忽略 nonce / timestamp / sign / token
			const defaultCmp = await appTool.execute("cmp-default", {
				action: "network_compare",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				left_case: leftCase.caseRelativePath,
				right_case: rightCase.caseRelativePath,
			});

			expect(defaultCmp.details.status).toBe("ok");
			expect(defaultCmp.details.acceptance).toBe("pending_verification");
			expect(defaultCmp.details.evidenceCandidates?.[0]?.assurance).toBeUndefined();
			expect(defaultCmp.details.compareReport?.independent_reproduction_certified).toBe(false);

			// 验证返回的候选事实可直接写入 EvidenceStore 且不带自动提权的 assurance
			const evidenceStore = new EvidenceStore({
				repositoryRoot: tempDir,
				stateRoot: path.join(tempDir, ".state"),
			});
			const storedFact = await evidenceStore.addFact(defaultCmp.details.evidenceCandidates![0]!);
			expect(storedFact.kind).toBe("fact");
			expect(storedFact.context?.assurance).toBeUndefined();

			const reqCmp1 = defaultCmp.details.requestComparison!;
			expect(reqCmp1.raw_equal).toBe(false);
			expect(reqCmp1.normalized_equal).toBe(false);
			expect(reqCmp1.total_unignored_diffs).toBe(4);
			expect(reqCmp1.total_ignored_diffs).toBe(0);
			const diffPointers1 = reqCmp1.field_diffs.map(d => d.pointer);
			expect(diffPointers1).toEqual(["/meta/token_hint", "/nonce", "/sign", "/timestamp"]);

			const respCmp1 = defaultCmp.details.responseComparison!;
			expect(respCmp1.raw_equal).toBe(false);
			expect(respCmp1.normalized_equal).toBe(false);
			expect(respCmp1.field_diffs.map(d => d.pointer)).toEqual(["/receipt/server_ts"]);

			// 校验 output_path 严格遵循 resolveAnalysisOutputPath 项目相对/run绝对路径规范（拒绝越出 run 目录的相对路径）
			await expect(
				appTool.execute("cmp-outside-run-out", {
					action: "network_compare",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					left_case: leftCase.caseRelativePath,
					right_case: rightCase.caseRelativePath,
					output_path: "reports/outside_run.report.json",
				}),
			).rejects.toThrow("Invalid output path");

			// 2. 显式指定 ignore_json_pointers：normalized_equal 变为 true，但 raw_equal 必须保持 false 且完整保留 ignored_diffs
			const explicitReportRel = path.join(runPaths.relative.reports_dir, "explicit_ignored.report.json");
			const ignoredCmp = await appTool.execute("cmp-ignored", {
				action: "network_compare",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				left_case: leftCase.caseRelativePath,
				right_case: rightCase.caseRelativePath,
				ignore_json_pointers: ["/nonce", "/timestamp", "/sign", "/meta/token_hint", "/receipt/server_ts"],
				compare_headers: ["X-Gateway", "Content-Type"],
				output_path: explicitReportRel,
			});

			const reqCmp2 = ignoredCmp.details.requestComparison!;
			expect(reqCmp2.raw_equal).toBe(false);
			expect(reqCmp2.normalized_equal).toBe(true);
			expect(reqCmp2.total_raw_diffs).toBe(4);
			expect(reqCmp2.total_unignored_diffs).toBe(0);
			expect(reqCmp2.total_ignored_diffs).toBe(4);
			expect(reqCmp2.ignored_diffs.map(d => d.pointer)).toEqual([
				"/meta/token_hint",
				"/nonce",
				"/sign",
				"/timestamp",
			]);
			expect(reqCmp2.applied_ignore_pointers).toEqual([
				"/nonce",
				"/timestamp",
				"/sign",
				"/meta/token_hint",
				"/receipt/server_ts",
			]);

			const respCmp2 = ignoredCmp.details.responseComparison!;
			expect(respCmp2.raw_equal).toBe(false);
			expect(respCmp2.normalized_equal).toBe(true);
			expect(respCmp2.selected_headers_equal).toBe(true);
			expect(respCmp2.ignored_diffs.map(d => d.pointer)).toEqual(["/receipt/server_ts"]);

			// 验证报告为 mode 0600 且未自动篡改 run.json
			if (process.platform !== "win32") {
				const st = await fs.stat(ignoredCmp.details.reportPath!);
				expect(st.mode & 0o777).toBe(0o600);
			}
			const runRecord = JSON.parse(await fs.readFile(runPaths.run_json, "utf8")) as AnalysisRunRecord;
			expect(runRecord.status).toBe("running");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("enforces array order (no sorting), no type coercion, RFC 6901 pointer escaping (~0 and ~1), and explicit assertions (eq/type/exists)", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-compare-pointers-"));
		try {
			const targetFile = await createTargetFixture(tempDir);
			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const appTool = new AppExperimentTool(session, { fetcher: NO_NETWORK_FETCHER });

			const wf = (
				await wfTool.execute("wf-c", {
					action: "create",
					target: targetFile,
					format: "ELF",
					goal: "Test nested arrays, pointer escaping, and assertions",
				})
			).details.workflow!;
			const stepId = wf.steps[0]!.id;
			const begin = await wsTool.execute("ws-b", {
				action: "begin",
				workflow_id: wf.id,
				step_id: stepId,
				purpose: "Verify JSON pointer escaping and strict typing",
				command: "app_experiment(action: 'network_compare')",
			});
			const runId = begin.details.run_id!;
			const dumpsDir = begin.details.paths!.dumps_dir;

			// 包含特殊键名 "a/b" 与 "m~n"、嵌套对象数组与严格数值/字符串区分
			const leftDoc = {
				"a/b": { "m~n": "dyn_1", fixed: true },
				steps: [
					{ id: 1, tag: "first" },
					{ id: 2, tag: "second" },
				],
				count: 42,
			};
			const rightDocReorderedAndStringCount = {
				"a/b": { "m~n": "dyn_2", fixed: true },
				steps: [
					{ id: 2, tag: "second" },
					{ id: 1, tag: "first" },
				],
				count: "42",
			};

			const leftCase = await writeCanonicalCaseArtifact({
				projectDir: tempDir,
				dumpsDir,
				workflowId: wf.id,
				stepId,
				runId,
				sourceFile: targetFile,
				stem: "ptr_left",
				caseId: "ptr_left",
				requestBody: Buffer.from(JSON.stringify(leftDoc), "utf8"),
				response: null, // generated 候选请求用例（recorded_response.status = 0, completeness = missing）
			});
			const rightCase = await writeCanonicalCaseArtifact({
				projectDir: tempDir,
				dumpsDir,
				workflowId: wf.id,
				stepId,
				runId,
				sourceFile: targetFile,
				stem: "ptr_right",
				caseId: "ptr_right",
				requestHeaders: [
					{ name: "Content-Type", value: "application/json" },
					{ name: "X-Duplicate-Tag", value: "beta" }, // 重复头顺序颠倒
					{ name: "X-Duplicate-Tag", value: "alpha" },
				],
				requestBody: Buffer.from(JSON.stringify(rightDocReorderedAndStringCount), "utf8"),
				response: null,
			});

			// 非法 JSON Pointer（不以 / 开头或含非法 ~2 转义）必须在执行前拒绝
			await expect(
				appTool.execute("bad-ptr-1", {
					action: "network_compare",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: runId,
					left_case: leftCase.caseRelativePath,
					right_case: rightCase.caseRelativePath,
					ignore_json_pointers: ["a/b"],
				}),
			).rejects.toThrow("must be empty string '' (root) or start with '/'");

			await expect(
				appTool.execute("bad-ptr-2", {
					action: "network_compare",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: runId,
					left_case: leftCase.caseRelativePath,
					right_case: rightCase.caseRelativePath,
					ignore_json_pointers: ["/a~2b"],
				}),
			).rejects.toThrow("invalid escape sequence '~2'");

			// 使用 /a~1b/m~0n 精确忽略 "a/b" -> "m~n"，同时验证数组乱序不相等、字符串 "42" !== 数字 42、重复头顺序敏感
			const cmpRes = await appTool.execute("cmp-ptr", {
				action: "network_compare",
				workflow_id: wf.id,
				step_id: stepId,
				run_id: runId,
				left_case: leftCase.caseRelativePath,
				right_case: rightCase.caseRelativePath,
				ignore_json_pointers: ["/a~1b/m~0n"],
				assertions: [
					{ pointer: "/a~1b/fixed", target: "right_request", eq: true, type: "boolean", exists: true },
					{ pointer: "/a~1b/missing_key", target: "right_request", exists: false },
					{ pointer: "/steps/0/id", target: "left_request", eq: 1, type: "number" },
					{ pointer: "/count", target: "right_request", eq: 42, type: "number" }, // 应失败：实际为 string "42"
				],
			});

			const reqCmp = cmpRes.details.requestComparison!;
			expect(reqCmp.headers_equal).toBe(false);
			expect(reqCmp.duplicate_headers_equal).toBe(false);
			expect(reqCmp.normalized_equal).toBe(false);
			// "/a~1b/m~0n" 已被忽略，而数组元素 0/1 与 "/count" 类型不匹配仍在 field_diffs 中
			expect(reqCmp.ignored_diffs.map(d => d.pointer)).toEqual(["/a~1b/m~0n"]);
			expect(reqCmp.field_diffs.map(d => d.pointer)).toEqual([
				"/count",
				"/steps/0/id",
				"/steps/0/tag",
				"/steps/1/id",
				"/steps/1/tag",
			]);
			expect(reqCmp.field_diffs[0]?.kind).toBe("type_mismatch");

			// 未记录响应（status=0）时 responseComparison 标记为 not_applicable
			expect(cmpRes.details.responseComparison?.available).toBe(false);
			expect(cmpRes.details.responseComparison?.raw_equal).toBe("not_applicable");
			expect(cmpRes.details.responseComparison?.normalized_equal).toBe("not_applicable");

			// 断言评估：前 3 条通过，第 4 条（"42" vs 42）失败
			expect(cmpRes.details.assertionsPassed).toBe(false);
			const asserts = cmpRes.details.assertionResults!;
			expect(asserts.map(a => a.status)).toEqual(["passed", "passed", "passed", "failed"]);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("distinguishes representation_mismatch/incomplete as unknown and non-JSON/no-body as not_applicable, bounds large diffs, and rejects tampered/undeclared/alias cases", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-compare-rep-"));
		try {
			const targetFile = await createTargetFixture(tempDir);
			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const appTool = new AppExperimentTool(session, { fetcher: NO_NETWORK_FETCHER });

			const wf = (
				await wfTool.execute("wf-c", {
					action: "create",
					target: targetFile,
					format: "ELF",
					goal: "Test representation mismatch, truncation, binary, and security checks",
				})
			).details.workflow!;
			const stepId = wf.steps[0]!.id;
			const begin = await wsTool.execute("ws-b", {
				action: "begin",
				workflow_id: wf.id,
				step_id: stepId,
				purpose: "Test edge cases in offline network_compare",
				command: "app_experiment(action: 'network_compare')",
			});
			const runId = begin.details.run_id!;
			const dumpsDir = begin.details.paths!.dumps_dir;

			const jsonBytes = Buffer.from(JSON.stringify({ hello: "world" }), "utf8");
			const binBytesA = Buffer.from([0x00, 0xff, 0xfe, 0x80, 0x11]);
			const binBytesB = Buffer.from([0x00, 0xff, 0xfe, 0x80, 0x22]);

			// 1. 不同表示层（captured_raw_bytes vs decoded_entity_bytes）与截断消息体 -> unknown
			const rawCase = await writeCanonicalCaseArtifact({
				projectDir: tempDir,
				dumpsDir,
				workflowId: wf.id,
				stepId,
				runId,
				sourceFile: targetFile,
				stem: "rep_raw",
				caseId: "rep_raw",
				requestBody: jsonBytes,
				requestRepresentation: "captured_raw_bytes",
				response: {
					status: 200,
					body: jsonBytes,
					representation: "captured_raw_bytes",
					completeness: "truncated",
				},
			});
			const entityCase = await writeCanonicalCaseArtifact({
				projectDir: tempDir,
				dumpsDir,
				workflowId: wf.id,
				stepId,
				runId,
				sourceFile: targetFile,
				stem: "rep_entity",
				caseId: "rep_entity",
				requestBody: jsonBytes,
				requestRepresentation: "decoded_entity_bytes",
				response: {
					status: 200,
					body: jsonBytes,
					representation: "captured_raw_bytes",
					completeness: "complete",
				},
			});

			const repRes = await appTool.execute("cmp-rep", {
				action: "network_compare",
				workflow_id: wf.id,
				step_id: stepId,
				run_id: runId,
				left_case: rawCase.caseRelativePath,
				right_case: entityCase.caseRelativePath,
				assertions: [{ pointer: "/hello", target: "left_response", eq: "world" }],
			});
			expect(repRes.details.requestComparison?.raw_equal).toBe("unknown");
			expect(repRes.details.requestComparison?.normalized_equal).toBe("unknown");
			expect(repRes.details.requestComparison?.comparison_reason).toContain("representation_mismatch");
			expect(repRes.details.responseComparison?.raw_equal).toBe("unknown");
			expect(repRes.details.responseComparison?.normalized_equal).toBe("unknown");
			expect(repRes.details.assertionResults?.[0]?.status).toBe("unknown");

			// 2. 二进制非 JSON 消息体与空消息体 -> raw_equal 为 boolean / not_applicable，normalized_equal 为 not_applicable
			const binLeft = await writeCanonicalCaseArtifact({
				projectDir: tempDir,
				dumpsDir,
				workflowId: wf.id,
				stepId,
				runId,
				sourceFile: targetFile,
				stem: "bin_left",
				caseId: "bin_left",
				requestBody: binBytesA,
				response: { status: 204, body: Buffer.alloc(0) },
			});
			const binRight = await writeCanonicalCaseArtifact({
				projectDir: tempDir,
				dumpsDir,
				workflowId: wf.id,
				stepId,
				runId,
				sourceFile: targetFile,
				stem: "bin_right",
				caseId: "bin_right",
				requestBody: binBytesB,
				response: { status: 204, body: Buffer.alloc(0) },
			});

			const binRes = await appTool.execute("cmp-bin", {
				action: "network_compare",
				workflow_id: wf.id,
				step_id: stepId,
				run_id: runId,
				left_case: binLeft.caseRelativePath,
				right_case: binRight.caseRelativePath,
				assertions: [{ pointer: "/x", target: "right_request", exists: true }],
			});
			expect(binRes.details.requestComparison?.raw_equal).toBe(false);
			expect(binRes.details.requestComparison?.normalized_equal).toBe("not_applicable");
			expect(binRes.details.responseComparison?.raw_equal).toBe("not_applicable");
			expect(binRes.details.responseComparison?.normalized_equal).toBe("not_applicable");
			expect(binRes.details.assertionResults?.[0]?.status).toBe("not_applicable");

			// 3. 大量字段差异裁剪（inline <= 50 条，报告保留更多）
			const bigLeftObj: Record<string, number> = {};
			const bigRightObj: Record<string, number> = {};
			for (let i = 0; i < 80; i++) {
				const k = `field_${String(i).padStart(3, "0")}`;
				bigLeftObj[k] = i;
				bigRightObj[k] = i + 1000;
			}
			const bigLeft = await writeCanonicalCaseArtifact({
				projectDir: tempDir,
				dumpsDir,
				workflowId: wf.id,
				stepId,
				runId,
				sourceFile: targetFile,
				stem: "big_left",
				caseId: "big_left",
				requestBody: Buffer.from(JSON.stringify(bigLeftObj), "utf8"),
				response: null,
			});
			const bigRight = await writeCanonicalCaseArtifact({
				projectDir: tempDir,
				dumpsDir,
				workflowId: wf.id,
				stepId,
				runId,
				sourceFile: targetFile,
				stem: "big_right",
				caseId: "big_right",
				requestBody: Buffer.from(JSON.stringify(bigRightObj), "utf8"),
				response: null,
			});

			const bigRes = await appTool.execute("cmp-big", {
				action: "network_compare",
				workflow_id: wf.id,
				step_id: stepId,
				run_id: runId,
				left_case: bigLeft.caseRelativePath,
				right_case: bigRight.caseRelativePath,
			});
			expect(bigRes.details.requestComparison?.total_unignored_diffs).toBe(80);
			expect(bigRes.details.requestComparison?.diffs_truncated).toBe(true);
			expect(bigRes.details.requestComparison?.field_diffs.length).toBe(50);
			const savedReport = JSON.parse(await fs.readFile(bigRes.details.reportPath!, "utf8"));
			expect(savedReport.request_comparison.field_diffs.length).toBe(80);

			// 4. 拒绝非标准兼容别名（baseline_request）、未在 begin 登记的外部文件、以及篡改后的 body 哈希
			const aliasCasePath = path.join(dumpsDir, "bad_alias.case.json");
			await writePrivateRunArtifactFile(
				aliasCasePath,
				JSON.stringify({
					schema_version: "1",
					case_id: "bad_alias",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: runId,
					created_at: new Date().toISOString(),
					baseline_request: { method: "GET", url: "https://api.example.com/v1" },
				}),
			);
			await expect(
				appTool.execute("cmp-alias", {
					action: "network_compare",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: runId,
					left_case: path.relative(tempDir, aliasCasePath),
					right_case: binRight.caseRelativePath,
				}),
			).rejects.toThrow("missing canonical 'request' object");

			const undeclaredExternal = path.join(tempDir, "outside_run.case.json");
			await fs.writeFile(undeclaredExternal, await fs.readFile(binLeft.casePath, "utf8"), { mode: 0o600 });
			await expect(
				appTool.execute("cmp-undeclared", {
					action: "network_compare",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: runId,
					left_case: "outside_run.case.json",
					right_case: binRight.caseRelativePath,
				}),
			).rejects.toThrow("was not declared in 'inputs' at 'begin'");

			// 篡改 binLeft 的请求体文件字节，验证 SHA-256 漂移被拦截
			const tamperedBodyAbs = path.resolve(tempDir, binLeft.bodyRelativePaths[0]!);
			await fs.writeFile(tamperedBodyAbs, Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00]), { mode: 0o600 });
			expect(hashBuffer(Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00])).sha256).not.toBe(hashBuffer(binBytesA).sha256);
			await expect(
				appTool.execute("cmp-tampered", {
					action: "network_compare",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: runId,
					left_case: binLeft.caseRelativePath,
					right_case: binRight.caseRelativePath,
				}),
			).rejects.toThrow("Request body hash/size mismatch");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

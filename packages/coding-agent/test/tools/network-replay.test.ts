import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { gzipSync } from "node:zlib";
import { removeWithRetries } from "@reverse/utils";
import { Settings } from "../../src/config/settings";
import { EvidenceStore } from "../../src/evidence";
import { resolveMitmproxy } from "../../src/extensibility/protocol-toolchain";
import { hashBuffer, type AnalysisRunRecord } from "../../src/reverse-workspace";
import { AppExperimentTool, ReverseWorkflowTool, ReverseWorkspaceTool, type ToolSession } from "../../src/tools";
import {
	writePrivateRunArtifactFile,
	type NetworkReplayReportV1,
	type ReplayCaseV1,
} from "../../src/tools/app-experiment";

interface DisposableTestSession extends ToolSession {
	triggerDispose: () => void;
}

function createTestSession(cwd: string, options?: { planMode?: boolean }): DisposableTestSession {
	const disposeHooks = new Set<() => void>();
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		registerDisposeCallback: (cb: () => void) => {
			disposeHooks.add(cb);
			return () => disposeHooks.delete(cb);
		},
		triggerDispose: () => {
			for (const hook of disposeHooks) hook();
		},
		...(options?.planMode
			? {
					getPlanModeState: () => ({
						enabled: true,
						planFilePath: "local://network-replay-plan.md",
					}),
				}
			: {}),
	};
}

async function createTargetFixture(dir: string, name = "target_app.bin"): Promise<string> {
	const filePath = path.join(dir, name);
	await fs.writeFile(filePath, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 5, 4, 3, 2]));
	return filePath;
}

function getFreePort(): Promise<number> {
	const { promise, resolve } = Promise.withResolvers<number>();
	const srv = net.createServer();
	srv.listen(0, "127.0.0.1", () => {
		const port = (srv.address() as net.AddressInfo).port;
		srv.close(() => resolve(port));
	});
	return promise;
}

async function withNoAmbientHttpProxy<T>(fn: () => Promise<T>): Promise<T> {
	const keys = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"] as const;
	const saved: Record<string, string | undefined> = {};
	for (const k of keys) {
		saved[k] = process.env[k];
		delete process.env[k];
	}
	try {
		return await fn();
	} finally {
		for (const k of keys) {
			if (saved[k] === undefined) {
				delete process.env[k];
			} else {
				process.env[k] = saved[k];
			}
		}
	}
}

function sendHttpRequestViaForwardProxy(options: {
	proxyPort: number;
	targetUrl: string;
	method: string;
	rawHeaders: string[];
	body: Buffer;
}): Promise<{ status: number; body: Buffer }> {
	const { promise, resolve, reject } = Promise.withResolvers<{ status: number; body: Buffer }>();
	const socket = net.connect(options.proxyPort, "127.0.0.1", () => {
		const headerLines: string[] = [`${options.method} ${options.targetUrl} HTTP/1.1`];
		for (let i = 0; i < options.rawHeaders.length; i += 2) {
			headerLines.push(`${options.rawHeaders[i]}: ${options.rawHeaders[i + 1]}`);
		}
		headerLines.push("Connection: close", "", "");
		socket.write(Buffer.from(headerLines.join("\r\n"), "latin1"));
		if (options.body.byteLength > 0) {
			socket.write(options.body);
		}
	});

	const chunks: Buffer[] = [];
	socket.on("data", chunk => {
		chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
	});
	socket.on("error", reject);
	socket.on("end", () => {
		const rawResp = Buffer.concat(chunks);
		const sepIdx = rawResp.indexOf("\r\n\r\n");
		if (sepIdx < 0) {
			reject(new Error(`Malformed HTTP response from proxy: ${rawResp.toString("latin1")}`));
			return;
		}
		const headStr = rawResp.subarray(0, sepIdx).toString("latin1");
		const statusMatch = headStr.split("\r\n")[0]?.match(/^HTTP\/\d\.\d\s+(\d{3})/);
		const status = statusMatch ? Number(statusMatch[1]) : 0;
		const respBody = rawResp.subarray(sepIdx + 4);
		resolve({ status, body: respBody });
	});
	return promise;
}

describe("app_experiment network_replay Step 3 (case_file, three-way diff, binary fidelity, and real mitm capture->import->replay)", () => {
	it("enforces Plan mode block, mutual exclusion between case_file and request_file/baseline_request, and strict run/input/prerequisite checks with 0 network calls", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-replay-guards-"));
		let serverHits = 0;
		const server = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch() {
				serverHits++;
				return Response.json({ ok: true });
			},
		});
		const serverOrigin = `http://127.0.0.1:${server.port}`;

		try {
			await withNoAmbientHttpProxy(async () => {
				const targetFile = await createTargetFixture(tempDir);
				const session = createTestSession(tempDir);
				const wfTool = new ReverseWorkflowTool(session);
				const wsTool = new ReverseWorkspaceTool(session);
				const appTool = new AppExperimentTool(session);

				// 1. Plan mode 拒绝主动发包
				const planTool = new AppExperimentTool(createTestSession(tempDir, { planMode: true }));
				await expect(
					planTool.execute("plan-replay", {
						action: "network_replay",
						allowed_origins: [serverOrigin],
						baseline_request: { url: `${serverOrigin}/ping` },
					}),
				).rejects.toThrow("Plan mode is read-only");

				// 2. case_file 与 baseline_request / request_file 严格互斥
				await expect(
					appTool.execute("conflict-inline", {
						action: "network_replay",
						allowed_origins: [serverOrigin],
						case_file: "dumps/a.case.json",
						baseline_request: { url: `${serverOrigin}/ping` },
					}),
				).rejects.toThrow("mutually exclusive");

				await expect(
					appTool.execute("conflict-reqfile", {
						action: "network_replay",
						allowed_origins: [serverOrigin],
						case_file: "dumps/a.case.json",
						request_file: "req.json",
					}),
				).rejects.toThrow("mutually exclusive");

				// 3. case_file 必须显式提供 workflow_id / step_id / run_id
				await expect(
					appTool.execute("missing-run", {
						action: "network_replay",
						allowed_origins: [serverOrigin],
						case_file: "dumps/a.case.json",
					}),
				).rejects.toThrow("requires explicit 'workflow_id'");

				// 4. 创建 workflow 与 run，导入含敏感 URL query 的 HAR（replay_ready=false），验证主动回放被阻断
				const harBlockedPath = path.join(tempDir, "blocked.har");
				const harBlockedDoc = {
					log: {
						version: "1.2",
						entries: [
							{
								_id: "blocked-query-entry",
								request: {
									method: "GET",
									url: `${serverOrigin}/v1/secret?access_token=tok_live_secret_123`,
									httpVersion: "HTTP/1.1",
									headers: [{ name: "Host", value: `127.0.0.1:${server.port}` }],
									cookies: [],
									queryString: [],
									bodySize: 0,
								},
								response: {
									status: 200,
									statusText: "OK",
									httpVersion: "HTTP/1.1",
									headers: [{ name: "Content-Type", value: "application/json" }],
									cookies: [],
									content: { size: 11, mimeType: "application/json", text: '{"ok":true}' },
									redirectURL: "",
									bodySize: 11,
								},
							},
						],
					},
				};
				await fs.writeFile(harBlockedPath, JSON.stringify(harBlockedDoc), "utf8");

				const wf = (
					await wfTool.execute("wf-1", {
						action: "create",
						target: targetFile,
						format: "ELF",
						goal: "Validate replay prerequisites",
					})
				).details.workflow!;
				const begin = await wsTool.execute("ws-1", {
					action: "begin",
					workflow_id: wf.id,
					step_id: wf.steps[0]!.id,
					purpose: "Import and test blocked replay prerequisites",
					command: "app_experiment(action: 'network_replay')",
					inputs: [harBlockedPath],
				});
				const runId = begin.details.run_id!;

				const impBlocked = await appTool.execute("imp-blocked", {
					action: "network_import",
					workflow_id: wf.id,
					step_id: wf.steps[0]!.id,
					run_id: runId,
					capture_path: harBlockedPath,
					capture_format: "har",
					entry_index: 0,
				});
				expect(impBlocked.details.replayCase?.replay_ready).toBe(false);

				await expect(
					appTool.execute("replay-blocked", {
						action: "network_replay",
						workflow_id: wf.id,
						step_id: wf.steps[0]!.id,
						run_id: runId,
						allowed_origins: [serverOrigin],
						case_file: impBlocked.details.caseRelativePath!,
					}),
				).rejects.toThrow("replay_ready is false");

				// 5. 拒绝软链 case_file
				const symlinkCase = path.join(begin.details.paths!.dumps_dir, "link.case.json");
				await fs.symlink(impBlocked.details.casePath!, symlinkCase);
				await expect(
					appTool.execute("replay-symlink", {
						action: "network_replay",
						workflow_id: wf.id,
						step_id: wf.steps[0]!.id,
						run_id: runId,
						allowed_origins: [serverOrigin],
						case_file: path.relative(tempDir, symlinkCase),
					}),
				).rejects.toThrow("Symlink escape violation");

				expect(serverHits).toBe(0);
			});
		} finally {
			server.stop(true);
			await removeWithRetries(tempDir);
		}
	});

	it("evaluates three-way responses (recorded/baseline/variants), JSON Pointer ignores & escaping, array order, assertions, cross-run reuse, Content-Encoding consistency, redirects, invalid variant 0-calls, truncation, and cancellation against Bun.serve", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-replay-bunserve-"));
		let seqCounter = 100;
		let hitCount = 0;
		const receivedLog: Array<{
			pathname: string;
			method: string;
			auth: string | null;
			cookie: string | null;
			dupTag: string | null;
			contentEncoding: string | null;
			rawBody: Buffer;
		}> = [];
		let onHangReached: (() => void) | undefined;

		const server = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			idleTimeout: 0,
			async fetch(req) {
				hitCount++;
				const u = new URL(req.url);
				const arrBuf = await req.arrayBuffer();
				const rawBody = Buffer.from(arrBuf);
				const auth = req.headers.get("authorization");
				const cookie = req.headers.get("cookie");
				const dupTag = req.headers.get("x-duplicate-tag");
				const contentEncoding = req.headers.get("content-encoding");

				receivedLog.push({
					pathname: u.pathname,
					method: req.method,
					auth,
					cookie,
					dupTag,
					contentEncoding,
					rawBody,
				});

				if (u.pathname === "/v1/order") {
					seqCounter++;
					if (auth !== "Bearer alice_token_777" || cookie !== "sid=alice_sid; tier=pro") {
						return new Response(
							JSON.stringify({
								code: 403,
								error: "unauthorized",
								trace_seq: seqCounter,
							}),
							{
								status: 403,
								headers: {
									"Content-Type": "application/json",
									"X-Backend-Cluster": "auth-deny",
								},
							},
						);
					}
					const parsedReq = JSON.parse(rawBody.toString("utf8")) as { mode?: string };
					const items =
						parsedReq.mode === "reordered"
							? [
									{ sku: "B", qty: 2 },
									{ sku: "A", qty: 1 },
								]
							: [
									{ sku: "A", qty: 1 },
									{ sku: "B", qty: 2 },
								];
					return new Response(
						JSON.stringify({
							code: 0,
							trace_seq: seqCounter,
							"meta/slash": { "tilde~key": `nonce_${seqCounter}`, stable: "v1" },
							items,
						}),
						{
							status: 200,
							headers: {
								"Content-Type": "application/json",
								"X-Backend-Cluster": "core-1",
							},
						},
					);
				}

				if (u.pathname === "/v1/gzip-upload") {
					return new Response(
						JSON.stringify({
							compressed_bytes: rawBody.byteLength,
							encoding: contentEncoding,
						}),
						{ status: 200, headers: { "Content-Type": "application/json" } },
					);
				}

				if (u.pathname === "/v1/cross-redirect") {
					return new Response("", {
						status: 302,
						headers: {
							Location: "https://attacker.example.net/steal?access_token=leak_999#frag_secret",
						},
					});
				}

				if (u.pathname === "/v1/large") {
					const prefix = "Z".repeat(1400);
					const tail = u.searchParams.get("v") === "2" ? "_TAIL_TWO" : "_TAIL_ONE";
					return new Response(prefix + tail, {
						status: 200,
						headers: { "Content-Type": "text/plain" },
					});
				}

				if (u.pathname === "/v1/hang") {
					onHangReached?.();
					const { promise, resolve } = Promise.withResolvers<void>();
					req.signal.addEventListener("abort", () => resolve(), { once: true });
					await promise;
					return new Response("aborted", { status: 499 });
				}

				return new Response("not found", { status: 404 });
			},
		});
		const serverOrigin = `http://127.0.0.1:${server.port}`;

		try {
			await withNoAmbientHttpProxy(async () => {
				process.env.TEST_REPLAY_ALICE_AUTH = "alice_token_777";
				process.env.TEST_REPLAY_ALICE_COOKIE = "sid=alice_sid; tier=pro";

				const targetFile = await createTargetFixture(tempDir);
				const session = createTestSession(tempDir);
				const wfTool = new ReverseWorkflowTool(session);
				const wsTool = new ReverseWorkspaceTool(session);
				const appTool = new AppExperimentTool(session);

				// 构造带 _rawBytes=true 的 HAR 抓包（模拟历史捕获 trace_seq=100）
				const recordedReqBody = Buffer.from(JSON.stringify({ mode: "normal", client: "rev" }), "utf8");
				const recordedRespBody = Buffer.from(
					JSON.stringify({
						code: 0,
						trace_seq: 100,
						"meta/slash": { "tilde~key": "nonce_100", stable: "v1" },
						items: [
							{ sku: "A", qty: 1 },
							{ sku: "B", qty: 2 },
						],
					}),
					"utf8",
				);

				const harPath = path.join(tempDir, "order_capture.har");
				const harDoc = {
					log: {
						version: "1.2",
						entries: [
							{
								_id: "order-flow-1",
								request: {
									method: "POST",
									url: `${serverOrigin}/v1/order`,
									httpVersion: "HTTP/1.1",
									headers: [
										{ name: "Host", value: `127.0.0.1:${server.port}` },
										{ name: "Content-Type", value: "application/json" },
										{ name: "X-Duplicate-Tag", value: "first" },
										{ name: "X-Duplicate-Tag", value: "second" },
										{ name: "Authorization", value: "Bearer old_captured_token_redact" },
										{ name: "Cookie", value: "sid=old_captured_sid; tier=pro" },
										{ name: "Content-Length", value: String(recordedReqBody.byteLength) },
									],
									cookies: [],
									queryString: [],
									bodySize: recordedReqBody.byteLength,
									postData: {
										mimeType: "application/json",
										text: recordedReqBody.toString("base64"),
										encoding: "base64",
										_rawBytes: true,
									},
								},
								response: {
									status: 200,
									statusText: "OK",
									httpVersion: "HTTP/1.1",
									headers: [
										{ name: "Content-Type", value: "application/json" },
										{ name: "X-Backend-Cluster", value: "core-1" },
									],
									cookies: [],
									content: {
										size: recordedRespBody.byteLength,
										mimeType: "application/json",
										text: recordedRespBody.toString("base64"),
										encoding: "base64",
										_rawBytes: true,
									},
									redirectURL: "",
									bodySize: recordedRespBody.byteLength,
								},
							},
						],
					},
				};
				await fs.writeFile(harPath, JSON.stringify(harDoc, null, 2), "utf8");

				const wf = (
					await wfTool.execute("wf-main", {
						action: "create",
						target: targetFile,
						format: "ELF",
						goal: "Verify order protocol replay and three-way diffs",
					})
				).details.workflow!;
				const stepId = wf.steps[0]!.id;

				// Run 1: 导入 HAR 用例并写入变体请求体
				const begin1 = await wsTool.execute("ws-begin-1", {
					action: "begin",
					workflow_id: wf.id,
					step_id: stepId,
					purpose: "Import HAR and replay three-way variants",
					command: "app_experiment(action: 'network_replay')",
					inputs: [harPath],
				});
				const runId1 = begin1.details.run_id!;
				const runPaths1 = begin1.details.paths!;

				const imp = await appTool.execute("imp-order", {
					action: "network_import",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: runId1,
					capture_path: harPath,
					capture_format: "har",
					entry_index: 0,
				});
				expect(imp.details.status).toBe("ok");
				const caseRel = imp.details.caseRelativePath!;

				// 若缺少必需的 credential_slots 绑定（如漏传 header_env_map.Cookie），必须在发包前拒绝（0 发包）
				await expect(
					appTool.execute("missing-cookie-slot", {
						action: "network_replay",
						workflow_id: wf.id,
						step_id: stepId,
						run_id: runId1,
						allowed_origins: [serverOrigin],
						case_file: caseRel,
						auth_header_env: "TEST_REPLAY_ALICE_AUTH",
					}),
				).rejects.toThrow("requires credential slot 'Cookie'");
				expect(hitCount).toBe(0);

				// 若任一后续变体非法（如跨域 origin），必须在发包前拒绝（确保 0 发包）
				await expect(
					appTool.execute("bad-variant-origin", {
						action: "network_replay",
						workflow_id: wf.id,
						step_id: stepId,
						run_id: runId1,
						allowed_origins: [serverOrigin],
						case_file: caseRel,
						auth_header_env: "TEST_REPLAY_ALICE_AUTH",
						header_env_map: { Cookie: "TEST_REPLAY_ALICE_COOKIE" },
						variant_requests: [{ id: "v_ok" }, { id: "v_evil", url: "https://evil.example.org/exfil" }],
					}),
				).rejects.toThrow("is not in allowed_origins");
				expect(hitCount).toBe(0);

				// 准备数组顺序变体请求体文件（位于当前 run 的 dumps 目录内）
				const reorderedBodyPath = path.join(runPaths1.dumps_dir, "reordered_req.json");
				await writePrivateRunArtifactFile(reorderedBodyPath, JSON.stringify({ mode: "reordered", client: "rev" }));
				const reorderedBodyRel = path.relative(tempDir, reorderedBodyPath);

				// 正式执行三方回放：显式忽略 /trace_seq 与 /meta~1slash/tilde~0key
				const replay1 = await appTool.execute("replay-three-way", {
					action: "network_replay",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: runId1,
					allowed_origins: [serverOrigin],
					case_file: caseRel,
					auth_header_env: "TEST_REPLAY_ALICE_AUTH",
					header_env_map: { Cookie: "TEST_REPLAY_ALICE_COOKIE" },
					ignore_json_pointers: ["/trace_seq", "/meta~1slash/tilde~0key"],
					compare_headers: ["X-Backend-Cluster", "Content-Type"],
					assertions: [
						{ pointer: "/code", eq: 0, type: "number", exists: true },
						{ pointer: "/meta~1slash/stable", eq: "v1", type: "string" },
						{ pointer: "/items/0/sku", eq: "A" },
						{ pointer: "/nonexistent_debug", exists: false },
						{ pointer: "/code", target: "unauth_var", eq: 403, type: "number" },
					],
					variant_requests: [
						{
							id: "unauth_var",
							name: "No Credentials Inherited",
						},
						{
							id: "reordered_arr_var",
							name: "Reordered Array Items",
							body_file: reorderedBodyRel,
							auth_header_env: "TEST_REPLAY_ALICE_AUTH",
							header_env_map: { Cookie: "TEST_REPLAY_ALICE_COOKIE" },
						},
					],
				});

				expect(replay1.details.status).toBe("ok");
				expect(replay1.details.acceptance).toBe("pending_verification");
				expect(replay1.details.evidenceCandidates?.[0]?.assurance).toBe("static_candidate");
				const evidenceStore = new EvidenceStore({
					repositoryRoot: tempDir,
					stateRoot: path.join(tempDir, ".state"),
				});
				const addedFact = await evidenceStore.addFact(replay1.details.evidenceCandidates![0]!);
				expect(addedFact.context?.assurance).toBe("static_candidate");
				expect(replay1.details.assertionsPassed).toBe(true);

				// 验证服务端收到的真实头部：baseline 保留重复头顺序与凭据，unauth_var 不继承任何凭据
				expect(receivedLog.length).toBe(3);
				expect(receivedLog[0]?.auth).toBe("Bearer alice_token_777");
				expect(receivedLog[0]?.cookie).toBe("sid=alice_sid; tier=pro");
				expect(receivedLog[0]?.dupTag).toBe("first, second");
				expect(receivedLog[1]?.auth).toBeNull();
				expect(receivedLog[1]?.cookie).toBeNull();
				expect(receivedLog[1]?.dupTag).toBe("first, second");

				// 验证三方对比：recorded (trace_seq=100) vs live baseline (trace_seq=101)
				expect(replay1.details.recordedResponse?.isHistoricalRecord).toBe(true);
				expect(replay1.details.recordedResponse?.status).toBe(200);
				expect(replay1.details.baselineResult?.status).toBe(200);

				const baseVsRec = replay1.details.baselineVsRecorded!;
				expect(baseVsRec.status_equal).toBe(true);
				expect(baseVsRec.selected_headers_equal).toBe(true);
				expect(baseVsRec.raw_equal).toBe(false);
				expect(baseVsRec.normalized_equal).toBe(true);
				expect(baseVsRec.ignored_diffs.map(d => d.pointer)).toEqual(["/meta~1slash/tilde~0key", "/trace_seq"]);

				// 验证变体 1（无凭据 403）与变体 2（数组顺序不同，禁止排序 -> normalized_equal=false）
				const vUnauth = replay1.details.variantResults![0]!;
				expect(vUnauth.status).toBe(403);
				expect(vUnauth.diffAgainstBaseline.statusMatch).toBe(false);
				expect(vUnauth.diffAgainstBaseline.selected_headers_equal).toBe(false);
				expect(vUnauth.diffAgainstBaseline.raw_equal).toBe(false);
				expect(vUnauth.diffAgainstBaseline.normalized_equal).toBe(false);

				const vReordered = replay1.details.variantResults![1]!;
				expect(vReordered.status).toBe(200);
				expect(vReordered.diffAgainstBaseline.raw_equal).toBe(false);
				expect(vReordered.diffAgainstBaseline.normalized_equal).toBe(false);
				expect(vReordered.diffAgainstBaseline.field_diffs.map(d => d.pointer)).toEqual([
					"/items/0/qty",
					"/items/0/sku",
					"/items/1/qty",
					"/items/1/sku",
				]);

				// 验证私有文件权限（mode 0600）与完整报告落盘，且不自动修改 run.json
				const savedReport = JSON.parse(
					await fs.readFile(replay1.details.reportPath!, "utf8"),
				) as NetworkReplayReportV1;
				expect(savedReport.schema_version).toBe("1");
				expect(savedReport.comparison_config.ignore_json_pointers).toEqual([
					"/trace_seq",
					"/meta~1slash/tilde~0key",
				]);
				if (process.platform !== "win32") {
					for (const outFile of replay1.details.outputPaths!) {
						const st = await fs.stat(outFile);
						expect(st.mode & 0o777).toBe(0o600);
					}
				}
				const run1BeforeRecord = JSON.parse(await fs.readFile(runPaths1.run_json, "utf8")) as AnalysisRunRecord;
				expect(run1BeforeRecord.status).toBe("running");

				// 收敛 Run 1
				await wsTool.execute("ws-record-1", {
					action: "record",
					workflow_id: wf.id,
					run_id: runId1,
					exit_code: 0,
					summary: "Imported order HAR and verified three-way replay",
					output_paths: [
						...imp.details.relativeOutputPaths!,
						reorderedBodyRel,
						...replay1.details.relativeOutputPaths!,
					],
				});

				// Run 2: 测试已导入历史 case_file 在新 Run 中的严格路径校验（未声明拒绝，声明全部依赖后可正常回放）
				const begin2Incomplete = await wsTool.execute("ws-begin-2a", {
					action: "begin",
					workflow_id: wf.id,
					step_id: stepId,
					purpose: "Attempt replay without declaring prior case_file in inputs",
					command: "app_experiment(action: 'network_replay')",
					inputs: [harPath],
				});
				await expect(
					appTool.execute("replay-undeclared-case", {
						action: "network_replay",
						workflow_id: wf.id,
						step_id: stepId,
						run_id: begin2Incomplete.details.run_id!,
						allowed_origins: [serverOrigin],
						case_file: caseRel,
						auth_header_env: "TEST_REPLAY_ALICE_AUTH",
						header_env_map: { Cookie: "TEST_REPLAY_ALICE_COOKIE" },
					}),
				).rejects.toThrow("was not declared in 'inputs' at 'begin'");

				const begin2Valid = await wsTool.execute("ws-begin-2b", {
					action: "begin",
					workflow_id: wf.id,
					step_id: stepId,
					purpose: "Replay previously imported case_file in new run with declared inputs",
					command: "app_experiment(action: 'network_replay')",
					inputs: [harPath, ...imp.details.relativeOutputPaths!],
				});
				const replay2 = await appTool.execute("replay-cross-run", {
					action: "network_replay",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: begin2Valid.details.run_id!,
					allowed_origins: [serverOrigin],
					case_file: caseRel,
					auth_header_env: "TEST_REPLAY_ALICE_AUTH",
					header_env_map: { Cookie: "TEST_REPLAY_ALICE_COOKIE" },
					ignore_json_pointers: ["/trace_seq", "/meta~1slash/tilde~0key"],
				});
				expect(replay2.details.status).toBe("ok");
				expect(replay2.details.baselineVsRecorded?.normalized_equal).toBe(true);

				// 测试 Content-Encoding 一致性校验与关键单值重复头拒绝
				const run2Dumps = begin2Valid.details.paths!.dumps_dir;
				const plainJsonBuf = Buffer.from('{"hello":"gzip"}', "utf8");
				const gzippedBuf = gzipSync(plainJsonBuf);
				const gzBodyPath = path.join(run2Dumps, "gz.body.bin");
				const gzWritten = await writePrivateRunArtifactFile(gzBodyPath, gzippedBuf);
				const harInfo = hashBuffer(await fs.readFile(harPath));

				// (a) representation=decoded_entity_bytes 但带 Content-Encoding: gzip -> 歧义编码必须拒绝，绝不伪造
				const ambiguousCasePath = path.join(run2Dumps, "ambiguous_ce.case.json");
				const ambiguousCase: ReplayCaseV1 = {
					schema_version: "1",
					case_id: "case_ambiguous_ce",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: begin2Valid.details.run_id!,
					created_at: new Date().toISOString(),
					source: {
						path: path.relative(tempDir, harPath).replace(/\\/g, "/"),
						sha256: harInfo.sha256,
						size_bytes: harInfo.size,
						format: "har",
						entry_id: "e1",
						entry_index: 0,
						selector: { kind: "entry_index", value: 0 },
					},
					request: {
						method: "POST",
						url: `${serverOrigin}/v1/gzip-upload`,
						headers: [
							{ name: "Content-Type", value: "application/json" },
							{ name: "Content-Encoding", value: "gzip" },
						],
						body: {
							path: path.relative(tempDir, gzBodyPath).replace(/\\/g, "/"),
							sha256: gzWritten.sha256,
							size_bytes: gzWritten.size_bytes,
							representation: "decoded_entity_bytes",
							completeness: "complete",
							content_encoding: "gzip",
						},
						credential_slots: [],
					},
					recorded_response: {
						status: 200,
						status_text: "OK",
						headers: [{ name: "Content-Type", value: "application/json" }],
						body: {
							path: null,
							sha256: null,
							size_bytes: 0,
							representation: "none",
							completeness: "empty",
						},
					},
					replay_ready: true,
					blocked_prerequisites: [],
				};
				await writePrivateRunArtifactFile(ambiguousCasePath, JSON.stringify(ambiguousCase));

				const hitsBeforeAmbiguous = hitCount;
				await expect(
					appTool.execute("replay-ambiguous-ce", {
						action: "network_replay",
						workflow_id: wf.id,
						step_id: stepId,
						run_id: begin2Valid.details.run_id!,
						allowed_origins: [serverOrigin],
						case_file: path.relative(tempDir, ambiguousCasePath),
					}),
				).rejects.toThrow("Ambiguous request body encoding");
				expect(hitCount).toBe(hitsBeforeAmbiguous);

				// (b) 重复关键单值头（如两个 Content-Type）必须显式拒绝而非静默覆盖
				const dupSingletonPath = path.join(run2Dumps, "dup_singleton.case.json");
				const dupSingletonCase: ReplayCaseV1 = {
					...ambiguousCase,
					case_id: "case_dup_singleton",
					request: {
						...ambiguousCase.request,
						headers: [
							{ name: "Content-Type", value: "application/json" },
							{ name: "content-type", value: "text/plain" },
						],
						body: {
							...ambiguousCase.request.body,
							representation: "captured_raw_bytes",
							content_encoding: undefined,
						},
					},
				};
				await writePrivateRunArtifactFile(dupSingletonPath, JSON.stringify(dupSingletonCase));
				await expect(
					appTool.execute("replay-dup-singleton", {
						action: "network_replay",
						workflow_id: wf.id,
						step_id: stepId,
						run_id: begin2Valid.details.run_id!,
						allowed_origins: [serverOrigin],
						case_file: path.relative(tempDir, dupSingletonPath),
					}),
				).rejects.toThrow("Critical duplicate header");

				// (c) captured_raw_bytes 且 content_encoding="gzip" 与出站 Content-Encoding: gzip 一致 -> 原样发送压缩字节
				const validGzipPath = path.join(run2Dumps, "valid_gzip.case.json");
				const validGzipCase: ReplayCaseV1 = {
					...ambiguousCase,
					case_id: "case_valid_gzip",
					request: {
						...ambiguousCase.request,
						body: {
							...ambiguousCase.request.body,
							representation: "captured_raw_bytes",
							content_encoding: "gzip",
						},
					},
				};
				await writePrivateRunArtifactFile(validGzipPath, JSON.stringify(validGzipCase));
				const gzReplay = await appTool.execute("replay-valid-gzip", {
					action: "network_replay",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: begin2Valid.details.run_id!,
					allowed_origins: [serverOrigin],
					case_file: path.relative(tempDir, validGzipPath),
				});
				expect(gzReplay.details.status).toBe("ok");
				const lastReceived = receivedLog[receivedLog.length - 1]!;
				expect(lastReceived.contentEncoding).toBe("gzip");
				expect(Buffer.compare(lastReceived.rawBody, gzippedBuf)).toBe(0);

				// 测试跨源 302 重定向不跟随且剔除敏感 Location query/hash
				const redirectRes = await appTool.execute("replay-redirect", {
					action: "network_replay",
					allowed_origins: [serverOrigin],
					baseline_request: {
						url: `${serverOrigin}/v1/cross-redirect`,
						method: "GET",
					},
				});
				expect(redirectRes.details.baselineResult?.status).toBe(302);
				expect(redirectRes.details.baselineResult?.headers["location"]).toBe("https://attacker.example.net/steal");

				// 测试响应截断：raw_equal 与 normalized_equal 均为 unknown，bodyHashMatch 为 null
				const truncRes = await appTool.execute("replay-trunc", {
					action: "network_replay",
					allowed_origins: [serverOrigin],
					max_bytes: 1024,
					baseline_request: { url: `${serverOrigin}/v1/large?v=1`, method: "GET" },
					variant_requests: [{ id: "v_trunc", url: `${serverOrigin}/v1/large?v=2` }],
				});
				expect(truncRes.details.variantResults?.[0]?.diffAgainstBaseline.bodyHashMatch).toBeNull();
				expect(truncRes.details.variantResults?.[0]?.diffAgainstBaseline.raw_equal).toBe("unknown");
				expect(truncRes.details.variantResults?.[0]?.diffAgainstBaseline.normalized_equal).toBe("unknown");

				// 测试 caller AbortSignal 取消（在请求实际抵达 /v1/hang 时确定性触发 abort）
				const abortCtl = new AbortController();
				onHangReached = () => {
					abortCtl.abort(new Error("caller_cancelled_replay"));
				};
				await expect(
					appTool.execute(
						"replay-cancel",
						{
							action: "network_replay",
							allowed_origins: [serverOrigin],
							baseline_request: { url: `${serverOrigin}/v1/hang`, method: "GET" },
						},
						abortCtl.signal,
					),
				).rejects.toThrow("aborted or timed out");
			});
		} finally {
			delete process.env.TEST_REPLAY_ALICE_AUTH;
			delete process.env.TEST_REPLAY_ALICE_COOKIE;
			server.stop(true);
			await removeWithRetries(tempDir);
		}
	}, 15_000);

	it("executes real end-to-end mitm_capture -> network_import (.mitm FlowReader) -> network_replay -> reverse_workspace record/recall without mocks", async () => {
		const mitmInfo = resolveMitmproxy();
		expect(mitmInfo.available).toBe(true);
		expect(mitmInfo.mitmdumpPath).toBeTruthy();
		if (!mitmInfo.mitmdumpPath) {
			throw new Error(
				"Required dependency 'mitmdump' is not available for real mitm_capture -> import -> replay verification",
			);
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-replay-real-mitm-"));
		const binaryReqPayload = Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0xff, 0xfe, 0x80, 0x91, 0x01, 0x02, 0x03]);
		let serverCallSeq = 0;
		const serverObserved: Array<{
			auth: string | null;
			cookie: string | null;
			dupHeader: string | null;
			body: Buffer;
		}> = [];

		const server = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			async fetch(req) {
				serverCallSeq++;
				const body = Buffer.from(await req.arrayBuffer());
				const auth = req.headers.get("authorization");
				const cookie = req.headers.get("cookie");
				const dupHeader = req.headers.get("x-wire-hop");
				serverObserved.push({ auth, cookie, dupHeader, body });

				if (auth !== "Bearer live_mitm_secret_tok" || cookie !== "session_id=live_cookie_77; mode=raw") {
					return Response.json(
						{ code: 401, error: "missing_credentials", call_seq: serverCallSeq },
						{ status: 401, headers: { "X-Proto-Version": "3.0" } },
					);
				}

				return Response.json(
					{
						code: 0,
						echo_len: body.byteLength,
						first_byte: body[0],
						call_seq: serverCallSeq,
						steps: ["init", "commit"],
					},
					{ status: 200, headers: { "X-Proto-Version": "3.0" } },
				);
			},
		});
		const serverOrigin = `http://127.0.0.1:${server.port}`;
		const session = createTestSession(tempDir);
		const wfTool = new ReverseWorkflowTool(session);
		const wsTool = new ReverseWorkspaceTool(session);
		const appTool = new AppExperimentTool(session);

		try {
			await withNoAmbientHttpProxy(async () => {
				const targetFile = await createTargetFixture(tempDir);
				// 1. 启动真实 mitm_capture 代理监听
				const mitmPort = await getFreePort();
				const startRes = await appTool.execute("mitm-start", {
					action: "mitm_capture",
					mitm_op: "start",
					mitm_port: mitmPort,
					timeout: 30,
				});
				expect(startRes.details.status).toBe("ok");
				const flowPath = startRes.details.mitmFlowArtifact!;
				expect(flowPath).toBeTruthy();

				try {
					// 2. 通过真实 mitmdump HTTP 代理向本地 Bun.serve 发送原始非 UTF-8 二进制请求（含重复头与敏感凭据）
					const liveProxyResp = await sendHttpRequestViaForwardProxy({
						proxyPort: mitmPort,
						targetUrl: `${serverOrigin}/v1/bin-submit?channel=direct`,
						method: "POST",
						rawHeaders: [
							"Host",
							`127.0.0.1:${server.port}`,
							"Content-Type",
							"application/octet-stream",
							"X-Wire-Hop",
							"client-edge",
							"X-Wire-Hop",
							"proxy-core",
							"Authorization",
							"Bearer live_mitm_secret_tok",
							"Cookie",
							"session_id=live_cookie_77; mode=raw",
							"Content-Length",
							String(binaryReqPayload.byteLength),
						],
						body: binaryReqPayload,
					});
					expect(liveProxyResp.status).toBe(200);
				} finally {
					// 3. 停止 mitm_capture，落盘真实 .mitm 流量文件
					const stopRes = await appTool.execute("mitm-stop", {
						action: "mitm_capture",
						mitm_op: "stop",
					});
					expect(stopRes.details.status).toBe("ok");
				}

				expect(serverObserved.length).toBe(1);
				expect(Buffer.compare(serverObserved[0]!.body, binaryReqPayload)).toBe(0);

				// 4. 创建 workflow 与实验 run（将真实捕获的 .mitm 文件登记为 begin input）
				const wf = (
					await wfTool.execute("wf-mitm", {
						action: "create",
						target: targetFile,
						format: "ELF",
						goal: "End-to-end mitm capture -> import -> replay verification",
					})
				).details.workflow!;
				const stepId = wf.steps[0]!.id;

				const beginRes = await wsTool.execute("ws-begin-mitm", {
					action: "begin",
					workflow_id: wf.id,
					step_id: stepId,
					purpose: "Import real mitmdump capture and replay against local server",
					command: "app_experiment(action: 'network_import') && app_experiment(action: 'network_replay')",
					inputs: [flowPath],
				});
				const runId = beginRes.details.run_id!;

				// 5. 使用官方 FlowReader 导入真实 .mitm 流
				const importRes = await appTool.execute("mitm-import", {
					action: "network_import",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: runId,
					capture_path: flowPath,
					capture_format: "mitm",
					entry_index: 0,
				});
				expect(importRes.details.status).toBe("ok");
				const rc = importRes.details.replayCase!;
				expect(rc.replay_ready).toBe(true);
				expect(rc.request.body.representation).toBe("captured_raw_bytes");
				expect(rc.request.body.sha256).toBe(hashBuffer(binaryReqPayload).sha256);

				// 6. 通过环境变量重新供给已剥离凭据，回放导入的 case_file 并附带无凭据变体
				process.env.TEST_LIVE_MITM_AUTH = "live_mitm_secret_tok";
				process.env.TEST_LIVE_MITM_COOKIE = "session_id=live_cookie_77; mode=raw";

				const replayRes = await appTool.execute("mitm-replay", {
					action: "network_replay",
					workflow_id: wf.id,
					step_id: stepId,
					run_id: runId,
					allowed_origins: [serverOrigin],
					case_file: importRes.details.caseRelativePath!,
					auth_header_env: "TEST_LIVE_MITM_AUTH",
					header_env_map: { Cookie: "TEST_LIVE_MITM_COOKIE" },
					ignore_json_pointers: ["/call_seq"],
					compare_headers: ["X-Proto-Version"],
					assertions: [
						{ pointer: "/code", eq: 0, type: "number" },
						{ pointer: "/echo_len", eq: binaryReqPayload.byteLength, type: "number" },
						{ pointer: "/first_byte", eq: 0xca, type: "number" },
						{ pointer: "/steps", eq: ["init", "commit"], type: "array" },
					],
					variant_requests: [{ id: "no_creds", name: "Unauthenticated Probe" }],
				});

				expect(replayRes.details.status).toBe("ok");
				expect(replayRes.details.assertionsPassed).toBe(true);

				// 服务端累计收到 3 次请求：1 次原始代理抓包 + 1 次回放 baseline + 1 次回放 no_creds 变体
				expect(serverObserved.length).toBe(3);
				expect(Buffer.compare(serverObserved[1]!.body, binaryReqPayload)).toBe(0);
				expect(serverObserved[1]!.auth).toBe("Bearer live_mitm_secret_tok");
				expect(serverObserved[1]!.cookie).toBe("session_id=live_cookie_77; mode=raw");
				expect(serverObserved[1]!.dupHeader).toBe("client-edge, proxy-core");

				expect(Buffer.compare(serverObserved[2]!.body, binaryReqPayload)).toBe(0);
				expect(serverObserved[2]!.auth).toBeNull();
				expect(serverObserved[2]!.cookie).toBeNull();

				// 验证三方差分：call_seq 从 1 变为 2 -> raw_equal=false，显式忽略 /call_seq 后 normalized_equal=true
				expect(replayRes.details.recordedResponse?.status).toBe(200);
				expect(replayRes.details.baselineResult?.status).toBe(200);
				expect(replayRes.details.baselineVsRecorded?.raw_equal).toBe(false);
				expect(replayRes.details.baselineVsRecorded?.normalized_equal).toBe(true);
				expect(replayRes.details.baselineVsRecorded?.selected_headers_equal).toBe(true);
				expect(replayRes.details.variantResults?.[0]?.status).toBe(401);

				// 7. 调用 reverse_workspace(action: "record") 与 recall 验证全链路产物哈希可复核
				const recordRes = await wsTool.execute("ws-record-mitm", {
					action: "record",
					workflow_id: wf.id,
					run_id: runId,
					exit_code: 0,
					summary: "Completed real mitm capture, import, and replay verification",
					output_paths: [...importRes.details.relativeOutputPaths!, ...replayRes.details.relativeOutputPaths!],
				});
				expect(recordRes.details.run?.status).toBe("succeeded");

				const recallRes = await wsTool.execute("ws-recall-mitm", {
					action: "recall",
					workflow_id: wf.id,
				});
				expect(recallRes.details.recalled_runs?.[0]?.reuse_status).toBe("available");
			});
		} finally {
			delete process.env.TEST_LIVE_MITM_AUTH;
			delete process.env.TEST_LIVE_MITM_COOKIE;
			await appTool.execute("mitm-final-cleanup", { action: "mitm_capture", mitm_op: "stop" }).catch(() => {});
			session.triggerDispose();
			server.stop(true);
			await removeWithRetries(tempDir);
		}
		// Real mitmdump proxy daemon startup + FlowReader subprocess + replay + record/recall requires ~30s budget
	}, 30_000);
});

import { spawn } from "node:child_process";
import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "../../src/config/settings";
import { resolveMitmproxy } from "../../src/extensibility/protocol-toolchain";
import type { SkillRequirementWhich } from "../../src/extensibility/skill-requirements";
import { ReverseWorkflowStore } from "../../src/reverse-workflow";
import { hashBuffer, type AnalysisRunRecord } from "../../src/reverse-workspace";
import { AppExperimentTool, ReverseWorkflowTool, ReverseWorkspaceTool, type ToolSession } from "../../src/tools";
import { writePrivateRunArtifactFile, type ReplayCaseV1 } from "../../src/tools/app-experiment";
import { removeWithRetries } from "@reverse/utils";

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
						planFilePath: "local://network-import-plan.md",
					}),
				}
			: {}),
	};
}

async function createTargetFixture(dir: string, name = "target_app.bin"): Promise<string> {
	const filePath = path.join(dir, name);
	await fs.writeFile(filePath, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 1, 2, 3, 4]));
	return filePath;
}

const NO_NETWORK_FETCHER: typeof fetch = (async () => {
	throw new Error("Unexpected network request during offline network_import");
}) as unknown as typeof fetch;

// ============================================================================
// 测试专用辅助函数：通过 mitmdump --no-server (-n) 官方 FlowWriter 生成真实 .mitm 夹具
// ============================================================================

const MITM_FLOW_WRITER_ADDON_SOURCE = `import base64
import json
import os
from urllib.parse import urlsplit
from mitmproxy import connection, ctx, flow as mflow, http, websocket
from mitmproxy.io import FlowWriter


def _run_writer() -> None:
    cfg_path = os.environ.get("REVERSE_MITM_WRITER_CONFIG", "").strip()
    if not cfg_path:
        return
    with open(cfg_path, "r", encoding="utf-8") as fp:
        cfg = json.load(fp)

    output_path = cfg["output_path"]
    flows_spec = cfg.get("flows", [])

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(output_path, flags, 0o600)
    with os.fdopen(fd, "wb") as out_fp:
        writer = FlowWriter(out_fp)
        for idx, spec in enumerate(flows_spec):
            req_spec = spec["request"]
            url_str = str(req_spec["url"])
            parsed = urlsplit(url_str)
            host = parsed.hostname or "example.com"
            port = parsed.port or (443 if parsed.scheme in ("https", "wss") else 80)

            client = connection.Client(
                peername=("127.0.0.1", 50000 + (idx % 1000)),
                sockname=("127.0.0.1", 8080),
            )
            server = connection.Server(address=(host, port))
            flow = http.HTTPFlow(client, server)
            if spec.get("id"):
                flow.id = str(spec["id"])

            req_header_tuples = [
                (str(k).encode("latin-1", errors="replace"), str(v).encode("latin-1", errors="replace"))
                for k, v in req_spec.get("headers", [])
            ]
            req_b64 = req_spec.get("body_base64")
            req_bytes = b"" if req_b64 is None else base64.b64decode(req_b64)
            http_url = url_str
            if parsed.scheme == "ws":
                http_url = "http://" + url_str[len("ws://"):]
            elif parsed.scheme == "wss":
                http_url = "https://" + url_str[len("wss://"):]

            flow.request = http.Request.make(
                str(req_spec.get("method", "GET")),
                http_url,
                content=req_bytes,
                headers=http.Headers(req_header_tuples),
            )
            if req_spec.get("http_version"):
                flow.request.http_version = str(req_spec["http_version"])
            if req_spec.get("preserve_headers"):
                flow.request.data.headers = http.Headers(req_header_tuples)
            if req_spec.get("content_missing"):
                flow.request.data.content = None

            resp_spec = spec.get("response")
            if resp_spec is not None:
                resp_header_tuples = [
                    (str(k).encode("latin-1", errors="replace"), str(v).encode("latin-1", errors="replace"))
                    for k, v in resp_spec.get("headers", [])
                ]
                resp_b64 = resp_spec.get("body_base64")
                resp_bytes = b"" if resp_b64 is None else base64.b64decode(resp_b64)
                flow.response = http.Response.make(
                    int(resp_spec.get("status", 200)),
                    content=resp_bytes,
                    headers=http.Headers(resp_header_tuples),
                )
                if resp_spec.get("status_text") is not None:
                    flow.response.reason = str(resp_spec["status_text"])
                if resp_spec.get("http_version"):
                    flow.response.http_version = str(resp_spec["http_version"])
                if resp_spec.get("preserve_headers"):
                    flow.response.data.headers = http.Headers(resp_header_tuples)
                if resp_spec.get("content_missing"):
                    flow.response.data.content = None

            if spec.get("error_message"):
                flow.error = mflow.Error(str(spec["error_message"]))

            if spec.get("websocket"):
                flow.websocket = websocket.WebSocketData()
            writer.add(flow)


class _ReverseFlowWriterAddon:
    def running(self) -> None:
        try:
            _run_writer()
        finally:
            ctx.master.shutdown()


addons = [_ReverseFlowWriterAddon()]
`;

interface MitmSyntheticFlowSpec {
	id?: string;
	websocket?: boolean;
	error_message?: string;
	request: {
		method: string;
		url: string;
		http_version?: string;
		headers?: Array<[string, string]>;
		body?: Buffer | string;
		content_missing?: boolean;
		preserve_headers?: boolean;
	};
	response?: {
		status: number;
		status_text?: string;
		http_version?: string;
		headers?: Array<[string, string]>;
		body?: Buffer | string;
		content_missing?: boolean;
		preserve_headers?: boolean;
	} | null;
}

async function writeMitmCaptureWithFlowWriter(options: {
	outputPath: string;
	flows: MitmSyntheticFlowSpec[];
	mitmdumpPath: string;
}): Promise<void> {
	const parentDir = path.dirname(path.resolve(options.outputPath));
	await fs.mkdir(parentDir, { recursive: true });
	const workDir = await fs.mkdtemp(path.join(parentDir, ".mitm_writer_tmp_"));

	try {
		const addonPath = path.join(workDir, "mitm_flow_writer_addon.py");
		const configPath = path.join(workDir, "writer_config.json");
		const serializedFlows = options.flows.map(f => {
			const reqBuf =
				f.request.body === undefined
					? Buffer.alloc(0)
					: typeof f.request.body === "string"
						? Buffer.from(f.request.body, "utf8")
						: f.request.body;
			const respBuf =
				f.response?.body === undefined
					? Buffer.alloc(0)
					: typeof f.response.body === "string"
						? Buffer.from(f.response.body, "utf8")
						: f.response.body;
			return {
				...(f.id ? { id: f.id } : {}),
				...(f.websocket ? { websocket: true } : {}),
				...(f.error_message ? { error_message: f.error_message } : {}),
				request: {
					method: f.request.method,
					url: f.request.url,
					...(f.request.http_version ? { http_version: f.request.http_version } : {}),
					headers: f.request.headers ?? [],
					body_base64: f.request.content_missing ? null : reqBuf.toString("base64"),
					...(f.request.content_missing ? { content_missing: true } : {}),
					...(f.request.preserve_headers ? { preserve_headers: true } : {}),
				},
				response:
					f.response === null
						? null
						: {
								status: f.response?.status ?? 200,
								status_text: f.response?.status_text ?? "OK",
								...(f.response?.http_version ? { http_version: f.response.http_version } : {}),
								headers: f.response?.headers ?? [],
								body_base64: f.response?.content_missing ? null : respBuf.toString("base64"),
								...(f.response?.content_missing ? { content_missing: true } : {}),
								...(f.response?.preserve_headers ? { preserve_headers: true } : {}),
							},
			};
		});

		await writePrivateRunArtifactFile(addonPath, MITM_FLOW_WRITER_ADDON_SOURCE);
		await writePrivateRunArtifactFile(
			configPath,
			JSON.stringify({
				output_path: path.resolve(options.outputPath),
				flows: serializedFlows,
			}),
		);

		const child = spawn(options.mitmdumpPath, ["-n", "-q", "-s", addonPath], {
			cwd: parentDir,
			stdio: ["ignore", "pipe", "pipe"],
			env: {
				PATH: process.env.PATH,
				HOME: process.env.HOME,
				TMPDIR: process.env.TMPDIR,
				LANG: process.env.LANG ?? "en_US.UTF-8",
				LC_ALL: process.env.LC_ALL,
				PYTHONPATH: process.env.PYTHONPATH,
				PYTHONUNBUFFERED: "1",
				REVERSE_MITM_WRITER_CONFIG: configPath,
			},
		});

		let stderr = "";
		child.stderr?.setEncoding("utf8");
		child.stderr?.on("data", (chunk: string) => {
			stderr += chunk;
		});

		const { promise, resolve, reject } = Promise.withResolvers<number | null>();
		child.once("error", reject);
		child.once("close", resolve);
		const exitCode = await promise;
		if (exitCode !== 0) {
			throw new Error(`FlowWriter mitmdump exited with code ${String(exitCode)}: ${stderr}`);
		}
	} finally {
		await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
	}
}

describe("app_experiment network_import (Step 2)", () => {
	it("enforces write approval tier and blocks execution in read-only Plan mode before touching files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-import-planmode-"));
		try {
			const normalTool = new AppExperimentTool(createTestSession(tempDir), {
				fetcher: NO_NETWORK_FETCHER,
			});
			expect(normalTool.approval({ action: "network_import" })).toBe("write");

			const planTool = new AppExperimentTool(createTestSession(tempDir, { planMode: true }), {
				fetcher: NO_NETWORK_FETCHER,
			});
			await expect(
				planTool.execute("call-plan", {
					action: "network_import",
					workflow_id: "wf_1",
					step_id: "step_1",
					run_id: "run_1",
					capture_path: "capture.har",
					capture_format: "har",
					entry_index: 0,
				}),
			).rejects.toThrow(/Plan mode/i);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("imports HAR and real .mitm (FlowWriter) captures with identical entity bytes, duplicate headers in wire order, non-UTF8/base64 and text_reencoded semantics, and mode 0600 files without mutating run.json", async () => {
		const mitmInfo = resolveMitmproxy();
		expect(mitmInfo.available).toBe(true);
		expect(mitmInfo.mitmdumpPath).toBeTruthy();
		if (!mitmInfo.mitmdumpPath) {
			throw new Error(
				"Required dependency 'mitmdump' is not available on PATH for real .mitm FlowWriter/FlowReader verification",
			);
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-import-parity-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		try {
			const targetFile = await createTargetFixture(tempDir);
			// 构造非 UTF-8 原始二进制请求体与响应体（含 0x00, 0xff, 0xfe, 0xfd, 0x80 等非法 UTF-8 字节序列）
			const binaryReqPayload = Buffer.from([
				0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff, 0xfe, 0xfd, 0x80, 0xc0, 0x42, 0x99,
			]);
			const binaryRespPayload = Buffer.from([
				0xca, 0xfe, 0xba, 0xbe, 0x00, 0x01, 0xff, 0x80, 0x7f, 0x10, 0x20, 0x30,
			]);
			// 构造 UTF-8 JSON 请求体与响应体（用于验证 HAR 文本 text_reencoded 与 .mitm captured_raw_bytes 提取出相同实体字节）
			const textReqPayload = '{"op":"query_version","client":"reverse-1.0","seq":7}';
			const textReqBuf = Buffer.from(textReqPayload, "utf8");
			const textRespPayload = '{"code":0,"server_version":"2.4.1"}';
			const textRespBuf = Buffer.from(textRespPayload, "utf8");

			const harPath = path.join(tempDir, "traffic.har");
			const mitmPath = path.join(tempDir, "traffic.mitm");

			const harDoc = {
				log: {
					version: "1.2",
					creator: { name: "reverse-test", version: "1.0" },
					entries: [
						// Entry 0: 非 UTF-8 二进制请求/响应（base64）+ 重复同名头 + 敏感头
						{
							_id: "flow-binary-01",
							startedDateTime: "2026-10-30T10:00:00.000Z",
							time: 18,
							request: {
								method: "POST",
								url: "https://api.example.com/v1/binary-frame?format=raw",
								httpVersion: "HTTP/1.1",
								headers: [
									{ name: "Host", value: "api.example.com" },
									{ name: "Content-Type", value: "application/octet-stream" },
									{ name: "X-Duplicate-Tag", value: "alpha" },
									{ name: "X-Duplicate-Tag", value: "beta" },
									{ name: "Authorization", value: "Bearer ghp_1234567890abcdefghijklmnopqrstuvwx" },
									{ name: "Cookie", value: "sid=secret_sid_value; theme=dark" },
									{ name: "content-length", value: String(binaryReqPayload.byteLength) },
								],
								cookies: [],
								queryString: [{ name: "format", value: "raw" }],
								headersSize: -1,
								bodySize: binaryReqPayload.byteLength,
								postData: {
									mimeType: "application/octet-stream",
									text: binaryReqPayload.toString("base64"),
									encoding: "base64",
								},
							},
							response: {
								status: 200,
								statusText: "OK",
								httpVersion: "HTTP/1.1",
								headers: [
									{ name: "Content-Type", value: "application/octet-stream" },
									{ name: "X-Server-Hop", value: "edge-1" },
									{ name: "X-Server-Hop", value: "core-2" },
									{ name: "Set-Cookie", value: "sid=rotated_secret_sid; HttpOnly" },
									{ name: "Set-Cookie", value: "csrf=rotated_secret_csrf; Secure" },
									{ name: "content-length", value: String(binaryRespPayload.byteLength) },
								],
								cookies: [],
								content: {
									size: binaryRespPayload.byteLength,
									mimeType: "application/octet-stream",
									text: binaryRespPayload.toString("base64"),
									encoding: "base64",
								},
								redirectURL: "",
								headersSize: -1,
								bodySize: binaryRespPayload.byteLength,
							},
							cache: {},
							timings: { send: 1, wait: 15, receive: 2 },
						},
						// Entry 1: UTF-8 纯文本 HAR（无 encoding: "base64" -> text_reencoded）
						{
							_id: "flow-text-02",
							startedDateTime: "2026-10-30T10:00:01.000Z",
							time: 12,
							request: {
								method: "POST",
								url: "https://api.example.com/v1/json-rpc",
								httpVersion: "HTTP/1.1",
								headers: [
									{ name: "Host", value: "api.example.com" },
									{ name: "Content-Type", value: "application/json" },
								],
								cookies: [],
								queryString: [],
								headersSize: -1,
								bodySize: textReqBuf.byteLength,
								postData: {
									mimeType: "application/json",
									text: textReqPayload,
								},
							},
							response: {
								status: 200,
								statusText: "OK",
								httpVersion: "HTTP/1.1",
								headers: [{ name: "Content-Type", value: "application/json" }],
								cookies: [],
								content: {
									size: textRespBuf.byteLength,
									mimeType: "application/json",
									text: textRespPayload,
								},
								redirectURL: "",
								headersSize: -1,
								bodySize: textRespBuf.byteLength,
							},
							cache: {},
							timings: { send: 1, wait: 10, receive: 1 },
						},
						// Entry 2: 空请求体 GET 与 204 空响应体
						{
							_id: "flow-empty-03",
							startedDateTime: "2026-10-30T10:00:02.000Z",
							time: 5,
							request: {
								method: "GET",
								url: "https://api.example.com/v1/ping",
								httpVersion: "HTTP/1.1",
								headers: [{ name: "Host", value: "api.example.com" }],
								cookies: [],
								queryString: [],
								headersSize: -1,
								bodySize: 0,
							},
							response: {
								status: 204,
								statusText: "No Content",
								httpVersion: "HTTP/1.1",
								headers: [],
								cookies: [],
								content: {
									size: 0,
									mimeType: "",
								},
								redirectURL: "",
								headersSize: -1,
								bodySize: 0,
							},
							cache: {},
							timings: { send: 1, wait: 3, receive: 1 },
						},
					],
				},
			};
			await fs.writeFile(harPath, JSON.stringify(harDoc, null, 2), "utf8");

			// 使用官方 FlowWriter 通过 mitmdump --no-server -n 生成包含相同 HTTP 请求的 .mitm 抓包文件
			await writeMitmCaptureWithFlowWriter({
				outputPath: mitmPath,
				mitmdumpPath: mitmInfo.mitmdumpPath,
				flows: [
					{
						id: "flow-binary-01",
						request: {
							method: "POST",
							url: "https://api.example.com/v1/binary-frame?format=raw",
							headers: [
								["Host", "api.example.com"],
								["Content-Type", "application/octet-stream"],
								["X-Duplicate-Tag", "alpha"],
								["X-Duplicate-Tag", "beta"],
								["Authorization", "Bearer ghp_1234567890abcdefghijklmnopqrstuvwx"],
								["Cookie", "sid=secret_sid_value; theme=dark"],
							],
							body: binaryReqPayload,
						},
						response: {
							status: 200,
							status_text: "OK",
							headers: [
								["Content-Type", "application/octet-stream"],
								["X-Server-Hop", "edge-1"],
								["X-Server-Hop", "core-2"],
								["Set-Cookie", "sid=rotated_secret_sid; HttpOnly"],
								["Set-Cookie", "csrf=rotated_secret_csrf; Secure"],
							],
							body: binaryRespPayload,
						},
					},
					{
						id: "flow-text-02",
						request: {
							method: "POST",
							url: "https://api.example.com/v1/json-rpc",
							headers: [
								["Host", "api.example.com"],
								["Content-Type", "application/json"],
							],
							body: textReqBuf,
						},
						response: {
							status: 200,
							status_text: "OK",
							headers: [["Content-Type", "application/json"]],
							body: textRespBuf,
						},
					},
					{
						id: "flow-empty-03",
						request: {
							method: "GET",
							url: "https://api.example.com/v1/ping",
							headers: [["Host", "api.example.com"]],
							body: Buffer.alloc(0),
						},
						response: {
							status: 204,
							status_text: "No Content",
							headers: [],
							body: Buffer.alloc(0),
						},
					},
				],
			});

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const appTool = new AppExperimentTool(session, { fetcher: NO_NETWORK_FETCHER });

			const wfRes = await wfTool.execute("wf-create", {
				action: "create",
				target: targetFile,
				format: "ELF",
				goal: "Verify HAR and mitm binary request fidelity",
			});
			const workflowId = wfRes.details.workflow!.id;
			const stepId = wfRes.details.workflow!.steps[0]!.id;

			const beginRes = await wsTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Import HTTP captures into ReplayCase v1",
				command: "app_experiment(action: 'network_import')",
				inputs: [harPath, mitmPath],
			});
			const runId = beginRes.details.run_id!;
			const runPaths = beginRes.details.paths!;

			// 1. 导入 HAR Entry 0 (binary + duplicate headers + sensitive headers)
			const harImport0 = await appTool.execute("har-import-0", {
				action: "network_import",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				capture_path: harPath,
				capture_format: "har",
				entry_index: 0,
			});
			expect(harImport0.details.status).toBe("ok");
			const harCase0 = harImport0.details.replayCase!;
			expect(harCase0.schema_version).toBe("1");
			expect(harCase0.source.format).toBe("har");
			expect(harCase0.source.entry_id).toBe("flow-binary-01");
			expect(harCase0.source.entry_index).toBe(0);
			expect(harCase0.replay_ready).toBe(true);
			expect(harCase0.blocked_prerequisites).toEqual([]);

			// 2. 导入 .mitm Flow 0 (通过 flow_id 选择同一请求)
			const mitmImport0 = await appTool.execute("mitm-import-0", {
				action: "network_import",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				capture_path: mitmPath,
				capture_format: "mitm",
				flow_id: "flow-binary-01",
			});
			expect(mitmImport0.details.status).toBe("ok");
			expect(mitmImport0.details.engineVersion).toContain("mitmproxy");
			const mitmCase0 = mitmImport0.details.replayCase!;
			expect(mitmCase0.source.format).toBe("mitm");
			expect(mitmCase0.source.entry_id).toBe("flow-binary-01");
			expect(mitmCase0.source.entry_index).toBe(0);
			expect(mitmCase0.replay_ready).toBe(true);

			// 3. 验证 HAR 与 .mitm 提取出完全一致的实体字节与 SHA-256，且严格区分表示层语义
			const expectedReqHash = hashBuffer(binaryReqPayload);
			const expectedRespHash = hashBuffer(binaryRespPayload);

			expect(harCase0.request.body.sha256).toBe(expectedReqHash.sha256);
			expect(mitmCase0.request.body.sha256).toBe(expectedReqHash.sha256);
			expect(harCase0.request.body.decoded_entity_sha256).toBe(expectedReqHash.sha256);
			expect(mitmCase0.request.body.decoded_entity_sha256).toBe(expectedReqHash.sha256);
			expect(harCase0.request.body.size_bytes).toBe(binaryReqPayload.byteLength);
			expect(mitmCase0.request.body.size_bytes).toBe(binaryReqPayload.byteLength);
			// HAR base64 为实体字节语义 (decoded_entity_bytes)，不因缺少 Content-Encoding 谎称原始包；.mitm 为捕获原始负载字节 (captured_raw_bytes)
			expect(harCase0.request.body.representation).toBe("decoded_entity_bytes");
			expect(mitmCase0.request.body.representation).toBe("captured_raw_bytes");
			expect(harCase0.request.body.completeness).toBe("complete");
			expect(mitmCase0.request.body.completeness).toBe("complete");

			expect(harCase0.recorded_response.body.sha256).toBe(expectedRespHash.sha256);
			expect(mitmCase0.recorded_response.body.sha256).toBe(expectedRespHash.sha256);
			expect(harCase0.recorded_response.body.decoded_entity_sha256).toBe(expectedRespHash.sha256);
			expect(mitmCase0.recorded_response.body.decoded_entity_sha256).toBe(expectedRespHash.sha256);
			expect(harCase0.recorded_response.body.representation).toBe("decoded_entity_bytes");
			expect(mitmCase0.recorded_response.body.representation).toBe("captured_raw_bytes");
			expect(harCase0.recorded_response.body.completeness).toBe("complete");
			expect(mitmCase0.recorded_response.body.completeness).toBe("complete");

			const harReqBytesOnDisk = await fs.readFile(harImport0.details.requestBodyPath!);
			const mitmReqBytesOnDisk = await fs.readFile(mitmImport0.details.requestBodyPath!);
			expect(Buffer.compare(harReqBytesOnDisk, binaryReqPayload)).toBe(0);
			expect(Buffer.compare(mitmReqBytesOnDisk, binaryReqPayload)).toBe(0);

			const harRespBytesOnDisk = await fs.readFile(harImport0.details.responseBodyPath!);
			const mitmRespBytesOnDisk = await fs.readFile(mitmImport0.details.responseBodyPath!);
			expect(Buffer.compare(harRespBytesOnDisk, binaryRespPayload)).toBe(0);
			expect(Buffer.compare(mitmRespBytesOnDisk, binaryRespPayload)).toBe(0);

			// 4. 验证重复同名 Header 保序，且敏感 Header 已剥离为 credential_slots（原文不出现在 case.json 或返回文本中）
			expect(harCase0.request.headers).toEqual([
				{ name: "Host", value: "api.example.com" },
				{ name: "Content-Type", value: "application/octet-stream" },
				{ name: "X-Duplicate-Tag", value: "alpha" },
				{ name: "X-Duplicate-Tag", value: "beta" },
				{ name: "content-length", value: String(binaryReqPayload.byteLength) },
			]);
			expect(mitmCase0.request.headers).toEqual(harCase0.request.headers);

			expect(
				harCase0.request.credential_slots.map(s => ({
					location: s.location,
					name: s.name,
					env_var: s.env_var,
					replay_binding: s.replay_binding,
					scheme: s.scheme,
					cookie_names: s.cookie_names,
				})),
			).toEqual([
				{
					location: "header",
					name: "Authorization",
					env_var: "REPLAY_AUTHORIZATION",
					replay_binding: "auth_header_env",
					scheme: "Bearer",
					cookie_names: undefined,
				},
				{
					location: "cookie",
					name: "Cookie",
					env_var: "REPLAY_COOKIE",
					replay_binding: "header_env_map",
					scheme: undefined,
					cookie_names: ["sid", "theme"],
				},
			]);
			expect(mitmCase0.request.credential_slots.map(s => s.env_var)).toEqual([
				"REPLAY_AUTHORIZATION",
				"REPLAY_COOKIE",
			]);

			// 响应头保序且 Set-Cookie 脱敏
			expect(harCase0.recorded_response.headers).toEqual([
				{ name: "Content-Type", value: "application/octet-stream" },
				{ name: "X-Server-Hop", value: "edge-1" },
				{ name: "X-Server-Hop", value: "core-2" },
				{ name: "Set-Cookie", value: "[REDACTED]" },
				{ name: "Set-Cookie", value: "[REDACTED]" },
				{ name: "content-length", value: String(binaryRespPayload.byteLength) },
			]);
			expect(mitmCase0.recorded_response.headers).toEqual(harCase0.recorded_response.headers);

			// 确保机密字符串未出现在 case.json 或工具输出文本中
			const harCaseRawText = await fs.readFile(harImport0.details.casePath!, "utf8");
			const mitmCaseRawText = await fs.readFile(mitmImport0.details.casePath!, "utf8");
			const persistedHarCase = JSON.parse(harCaseRawText) as ReplayCaseV1;
			const persistedMitmCase = JSON.parse(mitmCaseRawText) as ReplayCaseV1;
			expect(persistedHarCase).toEqual(harCase0);
			expect(persistedMitmCase).toEqual(mitmCase0);
			for (const secret of [
				"ghp_1234567890abcdefghijklmnopqrstuvwx",
				"secret_sid_value",
				"rotated_secret_sid",
				"rotated_secret_csrf",
			]) {
				expect(harCaseRawText).not.toContain(secret);
				expect(mitmCaseRawText).not.toContain(secret);
				expect(JSON.stringify(harImport0)).not.toContain(secret);
				expect(JSON.stringify(mitmImport0)).not.toContain(secret);
			}

			// 5. 验证 mode 0600 权限
			if (process.platform !== "win32") {
				for (const p of [...harImport0.details.outputPaths!, ...mitmImport0.details.outputPaths!]) {
					const st = await fs.stat(p);
					expect(st.mode & 0o777).toBe(0o600);
				}
			}

			// 6. 验证 Entry 1: HAR 纯文本 (text_reencoded) 与 .mitm (captured_raw_bytes) 提取出相同实体字节与 SHA-256
			const harImport1 = await appTool.execute("har-import-1", {
				action: "network_import",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				capture_path: harPath,
				capture_format: "har",
				entry_index: 1,
			});
			const mitmImport1 = await appTool.execute("mitm-import-1", {
				action: "network_import",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				capture_path: mitmPath,
				capture_format: "mitm",
				entry_index: 1,
			});
			expect(harImport1.details.replayCase!.request.body.sha256).toBe(hashBuffer(textReqBuf).sha256);
			expect(mitmImport1.details.replayCase!.request.body.sha256).toBe(hashBuffer(textReqBuf).sha256);
			expect(harImport1.details.replayCase!.request.body.representation).toBe("text_reencoded");
			expect(mitmImport1.details.replayCase!.request.body.representation).toBe("captured_raw_bytes");
			expect(harImport1.details.replayCase!.recorded_response.body.representation).toBe("text_reencoded");
			expect(mitmImport1.details.replayCase!.recorded_response.body.representation).toBe("captured_raw_bytes");

			// 7. 验证 Entry 2: 空请求体与空响应体 (completeness: "empty", representation: "none")
			const harImport2 = await appTool.execute("har-import-2", {
				action: "network_import",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				capture_path: harPath,
				capture_format: "har",
				flow_id: "flow-empty-03",
			});
			const mitmImport2 = await appTool.execute("mitm-import-2", {
				action: "network_import",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				capture_path: mitmPath,
				capture_format: "mitm",
				entry_index: 2,
			});
			expect(harImport2.details.replayCase!.request.body.completeness).toBe("empty");
			expect(harImport2.details.replayCase!.request.body.representation).toBe("none");
			expect(harImport2.details.replayCase!.recorded_response.body.completeness).toBe("empty");
			expect(mitmImport2.details.replayCase!.request.body.completeness).toBe("empty");
			expect(mitmImport2.details.replayCase!.recorded_response.body.completeness).toBe("empty");

			// 8. 验证 network_import 不自动修改或结束 run.json，且可由 reverse_workspace(action: "record") 正常收敛
			const runBeforeRecord = JSON.parse(await fs.readFile(runPaths.run_json, "utf8")) as AnalysisRunRecord;
			expect(runBeforeRecord.status).toBe("running");
			expect(runBeforeRecord.outputs).toEqual([]);

			const allOutputs = [
				...harImport0.details.outputPaths!,
				...mitmImport0.details.outputPaths!,
				...harImport1.details.outputPaths!,
				...mitmImport1.details.outputPaths!,
				...harImport2.details.outputPaths!,
				...mitmImport2.details.outputPaths!,
			];
			const recordRes = await wsTool.execute("ws-record", {
				action: "record",
				workflow_id: workflowId,
				run_id: runId,
				exit_code: 0,
				summary: "Imported HAR and mitm cases with identical entity hashes",
				output_paths: allOutputs,
			});
			expect(recordRes.details.run?.status).toBe("succeeded");
			expect(recordRes.details.run?.outputs).toHaveLength(allOutputs.length);
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	});

	it("preserves original sensitive request body bytes on disk while redacting URL/preview metadata and blocking active replay prerequisites", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-import-sensitive-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		try {
			const targetFile = await createTargetFixture(tempDir);
			const sensitiveBodyJson = JSON.stringify({
				username: "operator_alice",
				password: "super_secret_login_password_987",
				client_secret: "cs_live_abcdef1234567890",
				nested: {
					access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload",
				},
			});
			const sensitiveBodyBuf = Buffer.from(sensitiveBodyJson, "utf8");

			const harPath = path.join(tempDir, "sensitive.har");
			await fs.writeFile(
				harPath,
				JSON.stringify({
					log: {
						version: "1.2",
						entries: [
							{
								_id: "sens-entry-1",
								request: {
									method: "POST",
									url: "https://admin:url_pass_secret_111@api.example.com/v1/auth/token?access_token=query_tok_secret_222&normal=1",
									httpVersion: "HTTP/1.1",
									headers: [
										{ name: "Host", value: "api.example.com" },
										{ name: "Content-Type", value: "application/json" },
										{ name: "X-Api-Key", value: "x_api_secret_333" },
									],
									bodySize: sensitiveBodyBuf.byteLength,
									postData: {
										mimeType: "application/json",
										text: sensitiveBodyJson,
									},
								},
								response: {
									status: 200,
									statusText: "OK",
									httpVersion: "HTTP/1.1",
									headers: [
										{
											name: "Location",
											value: "https://api.example.com/callback?token=resp_loc_secret_444",
										},
									],
									content: {
										size: 27,
										mimeType: "application/json",
										text: '{"session":"resp_body_555"}',
									},
								},
							},
						],
					},
				}),
				"utf8",
			);

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const appTool = new AppExperimentTool(session, { fetcher: NO_NETWORK_FETCHER });

			const wf = (
				await wfTool.execute("wf-sens", {
					action: "create",
					target: targetFile,
					format: "ELF",
					goal: "Check sensitive URL/body prerequisite blocking",
				})
			).details.workflow!;

			const begin = await wsTool.execute("ws-begin-sens", {
				action: "begin",
				workflow_id: wf.id,
				step_id: wf.steps[0]!.id,
				purpose: "Test sensitive credential handling",
				command: "app_experiment(action: 'network_import')",
				inputs: [harPath],
			});

			const importRes = await appTool.execute("imp-sens", {
				action: "network_import",
				workflow_id: wf.id,
				step_id: wf.steps[0]!.id,
				run_id: begin.details.run_id!,
				capture_path: harPath,
				capture_format: "har",
				entry_index: 0,
			});

			const rc = importRes.details.replayCase!;
			// 因包含 URL userinfo、URL 敏感 query 与请求体敏感字段，replay_ready 必须为 false
			expect(rc.replay_ready).toBe(false);
			expect(rc.blocked_prerequisites.map(b => b.code)).toEqual([
				"sensitive_url_userinfo",
				"sensitive_url_query",
				"sensitive_request_body",
			]);

			// 原始字节文件必须原样保留，不能静默篡改
			const savedReqBody = await fs.readFile(importRes.details.requestBodyPath!);
			expect(Buffer.compare(savedReqBody, sensitiveBodyBuf)).toBe(0);
			expect(rc.request.body.sha256).toBe(hashBuffer(sensitiveBodyBuf).sha256);

			// 元数据与输出预览中不能泄露任何机密值或响应体原文
			const caseFileContent = await fs.readFile(importRes.details.casePath!, "utf8");
			for (const secret of [
				"super_secret_login_password_987",
				"cs_live_abcdef1234567890",
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload",
				"url_pass_secret_111",
				"query_tok_secret_222",
				"x_api_secret_333",
				"resp_loc_secret_444",
				"resp_body_555",
			]) {
				expect(caseFileContent).not.toContain(secret);
				expect(JSON.stringify(importRes)).not.toContain(secret);
			}

			// 校验 credential_slots 已完整登记 header / url_userinfo / query / body 槽位
			const slotLocations = rc.request.credential_slots.map(s => `${s.location}:${s.name}`);
			expect(slotLocations).toContain("header:X-Api-Key");
			expect(slotLocations).toContain("url_userinfo:userinfo");
			expect(slotLocations).toContain("query:access_token");
			expect(slotLocations).toContain("body:password");
			expect(slotLocations).toContain("body:client_secret");
			expect(slotLocations).toContain("body:access_token");
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	});

	it("records explicit missing and truncated body semantics, compares same-representation sizes under compression, and refuses guessing missing POST or response bodies", async () => {
		const mitmInfo = resolveMitmproxy();
		if (!mitmInfo.mitmdumpPath) {
			throw new Error("Required dependency 'mitmdump' is not available on PATH");
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-import-incomplete-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		try {
			const targetFile = await createTargetFixture(tempDir);
			const harPath = path.join(tempDir, "incomplete.har");
			const mitmPath = path.join(tempDir, "incomplete.mitm");

			await fs.writeFile(
				harPath,
				JSON.stringify({
					log: {
						version: "1.2",
						entries: [
							// Entry 0: 截断请求体 + 截断响应体
							{
								_id: "har-trunc",
								request: {
									method: "POST",
									url: "https://api.example.com/v1/upload",
									headers: [{ name: "Content-Length", value: "100" }],
									bodySize: 100,
									postData: {
										mimeType: "text/plain",
										text: "partial-req",
									},
								},
								response: {
									status: 200,
									statusText: "OK",
									headers: [{ name: "Content-Type", value: "text/plain" }],
									content: {
										size: 200,
										mimeType: "text/plain",
										text: "partial-resp",
									},
								},
							},
							// Entry 1: 缺失请求体（仅有 postData.params 无 text，禁止猜测拼凑请求体）+ 缺失响应体（size > 0 无 text）
							{
								_id: "har-missing",
								request: {
									method: "POST",
									url: "https://api.example.com/v1/form",
									headers: [{ name: "Content-Type", value: "application/x-www-form-urlencoded" }],
									bodySize: 32,
									postData: {
										mimeType: "application/x-www-form-urlencoded",
										params: [
											{ name: "a", value: "1" },
											{ name: "b", value: "2" },
										],
									},
								},
								response: {
									status: 200,
									statusText: "OK",
									headers: [{ name: "Content-Length", value: "64" }],
									content: {
										size: 64,
										mimeType: "application/json",
									},
								},
							},
							// Entry 2: 经浏览器解压后的 base64 响应体（传输层压缩 Content-Length: 48 > 解压后实体 content.size: 16，同表示层比对必须为 complete 而非误判 truncated）
							{
								_id: "har-gzip-entity",
								request: {
									method: "POST",
									url: "https://api.example.com/v1/compressed",
									headers: [
										{ name: "Content-Encoding", value: "gzip" },
										{ name: "Content-Length", value: "40" },
									],
									bodySize: 40,
									postData: {
										mimeType: "application/octet-stream",
										text: Buffer.from("req-payload-16b!", "utf8").toString("base64"),
										encoding: "base64",
									},
								},
								response: {
									status: 200,
									statusText: "OK",
									headers: [
										{ name: "Content-Encoding", value: "gzip" },
										{ name: "Content-Length", value: "48" },
									],
									bodySize: 48,
									content: {
										size: 16,
										compression: 8,
										mimeType: "application/octet-stream",
										text: Buffer.from("decompressed1234", "utf8").toString("base64"),
										encoding: "base64",
									},
								},
							},
							// Entry 3: POST 无 postData 且 bodySize: -1（未知长度）与 200 响应无 text 且 size: -1（未知长度），必须判定为 missing 而非猜测 empty
							{
								_id: "har-unknown-missing",
								request: {
									method: "POST",
									url: "https://api.example.com/v1/unknown-post",
									headers: [{ name: "Content-Type", value: "application/json" }],
									bodySize: -1,
								},
								response: {
									status: 200,
									statusText: "OK",
									headers: [{ name: "Content-Type", value: "application/json" }],
									bodySize: -1,
									content: {
										size: -1,
										mimeType: "application/json",
									},
								},
							},
							// Entry 4: POST 显式声明 bodySize: 0 无 postData，以及 200 显式声明 size: 0 无 text，判定为 empty
							{
								_id: "har-explicit-zero",
								request: {
									method: "POST",
									url: "https://api.example.com/v1/zero-post",
									headers: [{ name: "Content-Length", value: "0" }],
									bodySize: 0,
								},
								response: {
									status: 200,
									statusText: "OK",
									headers: [{ name: "Content-Length", value: "0" }],
									bodySize: 0,
									content: {
										size: 0,
										mimeType: "text/plain",
									},
								},
							},
						],
					},
				}),
				"utf8",
			);

			// .mitm 包含 content_missing (raw_content = None) 与 Content-Length 截断流（preserve_headers 保留广告的较大 Content-Length）
			await writeMitmCaptureWithFlowWriter({
				outputPath: mitmPath,
				mitmdumpPath: mitmInfo.mitmdumpPath,
				flows: [
					{
						id: "mitm-missing",
						request: {
							method: "POST",
							url: "https://api.example.com/v1/missing-body",
							headers: [["Content-Length", "48"]],
							content_missing: true,
							preserve_headers: true,
						},
						response: {
							status: 200,
							status_text: "OK",
							headers: [["Content-Length", "96"]],
							content_missing: true,
							preserve_headers: true,
						},
					},
					{
						id: "mitm-trunc",
						request: {
							method: "POST",
							url: "https://api.example.com/v1/trunc-body",
							headers: [["Content-Length", "80"]],
							body: Buffer.from("short-bytes", "utf8"),
							preserve_headers: true,
						},
						response: {
							status: 200,
							status_text: "OK",
							headers: [["Content-Length", "90"]],
							body: Buffer.from("short-resp", "utf8"),
							preserve_headers: true,
						},
					},
					{
						id: "mitm-chunked-error",
						error_message: "Peer closed connection before chunked terminator",
						request: {
							method: "GET",
							url: "https://api.example.com/v1/stream",
							headers: [["Host", "api.example.com"]],
							preserve_headers: true,
						},
						response: {
							status: 200,
							status_text: "OK",
							headers: [["Transfer-Encoding", "chunked"]],
							body: Buffer.from("partial-chunk-payload", "utf8"),
							preserve_headers: true,
						},
					},
				],
			});

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const appTool = new AppExperimentTool(session, { fetcher: NO_NETWORK_FETCHER });

			const wf = (
				await wfTool.execute("wf-inc", {
					action: "create",
					target: targetFile,
					format: "ELF",
					goal: "Test incomplete and missing body semantics",
				})
			).details.workflow!;

			const begin = await wsTool.execute("ws-begin-inc", {
				action: "begin",
				workflow_id: wf.id,
				step_id: wf.steps[0]!.id,
				purpose: "Import incomplete captures",
				command: "app_experiment(action: 'network_import')",
				inputs: [harPath, mitmPath],
			});
			const runId = begin.details.run_id!;

			// 1. HAR 截断条目
			const harTrunc = (
				await appTool.execute("har-trunc", {
					action: "network_import",
					workflow_id: wf.id,
					step_id: wf.steps[0]!.id,
					run_id: runId,
					capture_path: harPath,
					capture_format: "har",
					entry_index: 0,
				})
			).details.replayCase!;
			expect(harTrunc.request.body.completeness).toBe("truncated");
			expect(harTrunc.request.body.declared_size_bytes).toBe(100);
			expect(harTrunc.recorded_response.body.completeness).toBe("truncated");
			expect(harTrunc.recorded_response.body.declared_size_bytes).toBe(200);
			expect(harTrunc.replay_ready).toBe(false);
			expect(harTrunc.blocked_prerequisites.map(b => b.code)).toContain("incomplete_request_body");

			// 2. HAR 缺失条目（含 params 无 text，不猜测请求体）
			const harMissing = (
				await appTool.execute("har-missing", {
					action: "network_import",
					workflow_id: wf.id,
					step_id: wf.steps[0]!.id,
					run_id: runId,
					capture_path: harPath,
					capture_format: "har",
					entry_index: 1,
				})
			).details.replayCase!;
			expect(harMissing.request.body.completeness).toBe("missing");
			expect(harMissing.request.body.path).toBeNull();
			expect(harMissing.recorded_response.body.completeness).toBe("missing");
			expect(harMissing.recorded_response.body.path).toBeNull();
			expect(harMissing.replay_ready).toBe(false);
			expect(harMissing.blocked_prerequisites.map(b => b.code)).toContain("missing_request_body");

			// 3. HAR 压缩与解压同表示层长度比对（不因压缩后 Content-Length: 48 > 解压后实体 16 误判截断，也不凭请求 Content-Encoding 头臆断解压哈希）
			const harEntity = (
				await appTool.execute("har-entity", {
					action: "network_import",
					workflow_id: wf.id,
					step_id: wf.steps[0]!.id,
					run_id: runId,
					capture_path: harPath,
					capture_format: "har",
					entry_index: 2,
				})
			).details.replayCase!;
			expect(harEntity.request.body.representation).toBe("decoded_entity_bytes");
			expect(harEntity.request.body.completeness).toBe("complete");
			expect(harEntity.request.body.decoded_entity_sha256).toBeUndefined();
			expect(harEntity.recorded_response.body.representation).toBe("decoded_entity_bytes");
			expect(harEntity.recorded_response.body.completeness).toBe("complete");
			expect(harEntity.recorded_response.body.declared_size_bytes).toBe(16);

			// 4. HAR POST 未知长度无 postData 及 200 响应未知长度无 text -> 必须为 missing
			const harUnknownMissing = (
				await appTool.execute("har-unknown-missing", {
					action: "network_import",
					workflow_id: wf.id,
					step_id: wf.steps[0]!.id,
					run_id: runId,
					capture_path: harPath,
					capture_format: "har",
					entry_index: 3,
				})
			).details.replayCase!;
			expect(harUnknownMissing.request.body.completeness).toBe("missing");
			expect(harUnknownMissing.recorded_response.body.completeness).toBe("missing");
			expect(harUnknownMissing.replay_ready).toBe(false);
			expect(harUnknownMissing.blocked_prerequisites.map(b => b.code)).toContain("missing_request_body");

			// 5. HAR POST 显式声明 0 字节及 200 响应显式声明 0 字节 -> empty
			const harExplicitZero = (
				await appTool.execute("har-explicit-zero", {
					action: "network_import",
					workflow_id: wf.id,
					step_id: wf.steps[0]!.id,
					run_id: runId,
					capture_path: harPath,
					capture_format: "har",
					entry_index: 4,
				})
			).details.replayCase!;
			expect(harExplicitZero.request.body.completeness).toBe("empty");
			expect(harExplicitZero.recorded_response.body.completeness).toBe("empty");
			expect(harExplicitZero.replay_ready).toBe(true);

			// 6. .mitm content_missing 条目
			const mitmMissing = (
				await appTool.execute("mitm-missing", {
					action: "network_import",
					workflow_id: wf.id,
					step_id: wf.steps[0]!.id,
					run_id: runId,
					capture_path: mitmPath,
					capture_format: "mitm",
					flow_id: "mitm-missing",
				})
			).details.replayCase!;
			expect(mitmMissing.request.body.completeness).toBe("missing");
			expect(mitmMissing.recorded_response.body.completeness).toBe("missing");
			expect(mitmMissing.replay_ready).toBe(false);
			expect(mitmMissing.blocked_prerequisites.map(b => b.code)).toContain("missing_request_body");

			// 7. .mitm Content-Length 截断条目
			const mitmTrunc = (
				await appTool.execute("mitm-trunc", {
					action: "network_import",
					workflow_id: wf.id,
					step_id: wf.steps[0]!.id,
					run_id: runId,
					capture_path: mitmPath,
					capture_format: "mitm",
					flow_id: "mitm-trunc",
				})
			).details.replayCase!;
			expect(mitmTrunc.request.body.completeness).toBe("truncated");
			expect(mitmTrunc.request.body.declared_size_bytes).toBe(80);
			expect(mitmTrunc.recorded_response.body.completeness).toBe("truncated");
			expect(mitmTrunc.recorded_response.body.declared_size_bytes).toBe(90);
			expect(mitmTrunc.replay_ready).toBe(false);
			expect(mitmTrunc.blocked_prerequisites.map(b => b.code)).toContain("incomplete_request_body");

			// 8. .mitm 无 Content-Length 的 chunked 流传输中断（flow.error）-> 响应体判定为 truncated
			const mitmChunkedErr = (
				await appTool.execute("mitm-chunked-error", {
					action: "network_import",
					workflow_id: wf.id,
					step_id: wf.steps[0]!.id,
					run_id: runId,
					capture_path: mitmPath,
					capture_format: "mitm",
					flow_id: "mitm-chunked-error",
				})
			).details.replayCase!;
			expect(mitmChunkedErr.request.body.completeness).toBe("empty");
			expect(mitmChunkedErr.recorded_response.body.completeness).toBe("truncated");
			expect(mitmChunkedErr.recorded_response.body.note).toContain("Peer closed connection");
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	});

	it("refuses ambiguous selectors, WebSocket flows, unsupported missing response/corrupt data, symlinks, and undeclared external inputs while permitting run-local intermediates", async () => {
		const mitmInfo = resolveMitmproxy();
		if (!mitmInfo.mitmdumpPath) {
			throw new Error("Required dependency 'mitmdump' is not available on PATH");
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "net-import-boundaries-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		try {
			const targetFile = await createTargetFixture(tempDir);
			const harPath = path.join(tempDir, "edge.har");
			const mitmPath = path.join(tempDir, "edge.mitm");
			const undeclaredHarPath = path.join(tempDir, "undeclared.har");

			const edgeHarDoc = {
				log: {
					version: "1.2",
					entries: [
						// Entry 0 & Entry 1: 故意重复相同的 _id 以验证模糊 flow_id 拒绝
						{
							_id: "dup-id",
							request: { method: "GET", url: "https://api.example.com/a", headers: [] },
							response: { status: 200, statusText: "OK", headers: [], content: { size: 0, mimeType: "" } },
						},
						{
							_id: "dup-id",
							request: { method: "GET", url: "https://api.example.com/b", headers: [] },
							response: { status: 200, statusText: "OK", headers: [], content: { size: 0, mimeType: "" } },
						},
						// Entry 2: WebSocket 流
						{
							_id: "ws-flow",
							_resourceType: "websocket",
							_webSocketMessages: [{ type: "send", data: "hello" }],
							request: { method: "GET", url: "wss://api.example.com/ws", headers: [] },
							response: {
								status: 101,
								statusText: "Switching Protocols",
								headers: [],
								content: { size: 0, mimeType: "" },
							},
						},
						// Entry 3: 缺失 HTTP 响应状态 (status: 0)
						{
							_id: "no-resp-entry",
							request: { method: "GET", url: "https://api.example.com/aborted", headers: [] },
							response: { status: 0, statusText: "", headers: [], content: { size: 0, mimeType: "" } },
						},
						// Entry 4: 非法 base64 编码
						{
							_id: "bad-b64-entry",
							request: {
								method: "POST",
								url: "https://api.example.com/bad-b64",
								headers: [],
								postData: {
									mimeType: "application/octet-stream",
									text: "***not-valid-base64***",
									encoding: "base64",
								},
							},
							response: { status: 200, statusText: "OK", headers: [], content: { size: 0, mimeType: "" } },
						},
						// Entry 5: 未配对 UTF-16 代理项但未声明 base64
						{
							_id: "surrogate-entry",
							request: {
								method: "POST",
								url: "https://api.example.com/surrogate",
								headers: [],
								postData: {
									mimeType: "application/octet-stream",
									text: "prefix-\ud800-suffix",
								},
							},
							response: { status: 200, statusText: "OK", headers: [], content: { size: 0, mimeType: "" } },
						},
					],
				},
			};

			await fs.writeFile(harPath, JSON.stringify(edgeHarDoc), "utf8");
			await fs.writeFile(undeclaredHarPath, JSON.stringify(edgeHarDoc), "utf8");

			await writeMitmCaptureWithFlowWriter({
				outputPath: mitmPath,
				mitmdumpPath: mitmInfo.mitmdumpPath,
				flows: [
					{
						id: "mitm-dup",
						request: { method: "GET", url: "https://api.example.com/1" },
						response: { status: 200, status_text: "OK" },
					},
					{
						id: "mitm-dup",
						request: { method: "GET", url: "https://api.example.com/2" },
						response: { status: 200, status_text: "OK" },
					},
					{
						id: "mitm-ws",
						websocket: true,
						request: {
							method: "GET",
							url: "https://api.example.com/ws",
							headers: [["Upgrade", "websocket"]],
						},
						response: { status: 101, status_text: "Switching Protocols" },
					},
					{
						id: "mitm-no-resp",
						request: { method: "GET", url: "https://api.example.com/no-resp" },
						response: null,
					},
				],
			});

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const appTool = new AppExperimentTool(session, { fetcher: NO_NETWORK_FETCHER });

			const wf = (
				await wfTool.execute("wf-edge", {
					action: "create",
					target: targetFile,
					format: "ELF",
					goal: "Test boundary refusals",
				})
			).details.workflow!;

			const begin = await wsTool.execute("ws-begin-edge", {
				action: "begin",
				workflow_id: wf.id,
				step_id: wf.steps[0]!.id,
				purpose: "Boundary checks",
				command: "app_experiment(action: 'network_import')",
				inputs: [harPath, mitmPath],
			});
			const runId = begin.details.run_id!;
			const runPaths = begin.details.paths!;

			const baseArgs = {
				action: "network_import" as const,
				workflow_id: wf.id,
				step_id: wf.steps[0]!.id,
				run_id: runId,
				capture_path: harPath,
				capture_format: "har" as const,
			};

			// 1. 拒绝未提供选择器或同时提供 entry_index 与 flow_id
			await expect(appTool.execute("no-sel", baseArgs)).rejects.toThrow(/explicit selector/i);
			await expect(appTool.execute("both-sel", { ...baseArgs, entry_index: 0, flow_id: "dup-id" })).rejects.toThrow(
				/mutually exclusive/i,
			);
			await expect(appTool.execute("neg-sel", { ...baseArgs, entry_index: -1 })).rejects.toThrow(
				/non-negative integer/i,
			);
			await expect(appTool.execute("oob-sel", { ...baseArgs, entry_index: 99 })).rejects.toThrow(/out of range/i);
			await expect(appTool.execute("missing-id", { ...baseArgs, flow_id: "nonexistent-id" })).rejects.toThrow(
				/No HAR entry found/i,
			);

			// 2. 拒绝 HAR 与 .mitm 中的重复模糊 flow_id
			await expect(appTool.execute("ambig-har", { ...baseArgs, flow_id: "dup-id" })).rejects.toThrow(
				/Ambiguous flow_id/i,
			);
			await expect(
				appTool.execute("ambig-mitm", {
					...baseArgs,
					capture_path: mitmPath,
					capture_format: "mitm",
					flow_id: "mitm-dup",
				}),
			).rejects.toThrow(/Ambiguous flow_id/i);

			// 3. 拒绝 HAR 与 .mitm 中的 WebSocket 流
			await expect(appTool.execute("ws-har", { ...baseArgs, entry_index: 2 })).rejects.toThrow(/WebSocket/i);
			await expect(
				appTool.execute("ws-mitm", {
					...baseArgs,
					capture_path: mitmPath,
					capture_format: "mitm",
					flow_id: "mitm-ws",
				}),
			).rejects.toThrow(/WebSocket/i);

			// 4. 拒绝缺失响应、损坏 base64、未配对 UTF-16 代理项
			await expect(appTool.execute("no-resp-har", { ...baseArgs, entry_index: 3 })).rejects.toThrow(
				/invalid or missing HTTP response status/i,
			);
			await expect(
				appTool.execute("no-resp-mitm", {
					...baseArgs,
					capture_path: mitmPath,
					capture_format: "mitm",
					flow_id: "mitm-no-resp",
				}),
			).rejects.toThrow(/no recorded HTTP response/i);
			await expect(appTool.execute("bad-b64", { ...baseArgs, entry_index: 4 })).rejects.toThrow(/Invalid base64/i);
			await expect(appTool.execute("surrogate", { ...baseArgs, entry_index: 5 })).rejects.toThrow(
				/unpaired UTF-16 surrogates/i,
			);

			// 5. 拒绝未在 begin inputs 中声明的外部抓包文件
			await expect(
				appTool.execute("undeclared", {
					...baseArgs,
					capture_path: undeclaredHarPath,
					entry_index: 0,
				}),
			).rejects.toThrow(/was not declared in 'inputs' at 'begin'/i);

			// 6. 允许消费同一 run 目录内生成的中间抓包文件，且不修改 run.json 的 inputs
			const intermediateHar = path.join(runPaths.dumps_dir, "intermediate_capture.har");
			await fs.writeFile(intermediateHar, JSON.stringify(edgeHarDoc), "utf8");
			const interRes = await appTool.execute("intermediate-ok", {
				...baseArgs,
				capture_path: intermediateHar,
				entry_index: 0,
			});
			expect(interRes.details.status).toBe("ok");
			const runAfterInter = JSON.parse(await fs.readFile(runPaths.run_json, "utf8")) as AnalysisRunRecord;
			expect(runAfterInter.inputs.map(i => path.basename(i.path))).toEqual([
				path.basename(targetFile),
				"edge.har",
				"edge.mitm",
			]);

			// 7. 拒绝 capture_path 或 output_path 的符号链接逃逸与越界路径
			const symlinkCapture = path.join(tempDir, "symlink_edge.har");
			await fs.symlink(harPath, symlinkCapture);
			await expect(
				appTool.execute("symlink-in", {
					...baseArgs,
					capture_path: symlinkCapture,
					entry_index: 0,
				}),
			).rejects.toThrow(/Symlink escape violation/i);

			const symlinkOutDir = path.join(runPaths.dumps_dir, "linked_out");
			await fs.symlink(tempDir, symlinkOutDir);
			await expect(
				appTool.execute("symlink-out", {
					...baseArgs,
					entry_index: 0,
					output_path: path.join(symlinkOutDir, "escaped.json"),
				}),
			).rejects.toThrow(/Symlink escape violation/i);

			await expect(
				appTool.execute("outside-out", {
					...baseArgs,
					entry_index: 0,
					output_path: path.join(tempDir, "outside_case.json"),
				}),
			).rejects.toThrow(/Invalid output path/i);

			// 8. 当 mitmproxy 缺失时，mitm 导入返回结构化 missing_dependency，而 HAR 导入不受影响
			const noToolsWhich: SkillRequirementWhich = () => null;
			const toolWithoutMitm = new AppExperimentTool(session, {
				which: noToolsWhich,
				fetcher: NO_NETWORK_FETCHER,
			});
			const missingMitmRes = await toolWithoutMitm.execute("mitm-missing-dep", {
				...baseArgs,
				capture_path: mitmPath,
				capture_format: "mitm",
				entry_index: 0,
			});
			expect(missingMitmRes.details.status).toBe("missing_dependency");
			expect(missingMitmRes.details.missingTools).toEqual(["mitmproxy"]);
			expect(missingMitmRes.details.setupCommands).toEqual(["reverse setup reverse mitmproxy"]);

			const harWithoutMitmRes = await toolWithoutMitm.execute("har-no-mitm-ok", {
				...baseArgs,
				entry_index: 1,
			});
			expect(harWithoutMitmRes.details.status).toBe("ok");
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	});
});

import { spawn, type ChildProcess } from "node:child_process";
import { constants, type Stats } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { isRecord } from "@reverse/utils";
import { redactEvidenceText, type EvidenceAssuranceLevel } from "../evidence/contracts";
import { evaluateProtocolToolActionDependencies, resolveMitmproxy } from "../extensibility/protocol-toolchain";
import type { SkillRequirementWhich } from "../extensibility/skill-requirements";
import {
	deterministicJsonStringify,
	hashBuffer,
	loadAnalysisExecution,
	redactSecrets,
	resolveAnalysisOutputPath,
	type AnalysisFileRef,
	type AnalysisRunPaths,
} from "../reverse-workspace";
import { throwIfAborted } from "./tool-errors";

// ============================================================================
// ReplayCase v1 持久化私有协议契约（单一定式 Schema，供 Step 2 导入与 Step 3 回放/差分共用）
// ============================================================================

export type ReplayCaptureFormat = "har" | "mitm";
export type ReplayCaseSourceFormat = ReplayCaptureFormat | "generated";

export type ReplayBodyRepresentation = "none" | "captured_raw_bytes" | "decoded_entity_bytes" | "text_reencoded";
export type ReplayBodyCompleteness = "empty" | "complete" | "truncated" | "missing";

export interface ReplayHeaderEntry {
	name: string;
	value: string;
}

export interface ReplayBodyRef {
	/** 指向当前实验 run 目录内 mode-0600 私有字节文件的项目相对路径（completeness === "missing" 时为 null） */
	path: string | null;
	/** 已落盘字节文件的 SHA-256（completeness === "missing" 时为 null） */
	sha256: string | null;
	/** 已落盘字节数 */
	size_bytes: number;
	/** 抓包元数据或 Content-Length 声明的字节长度（若存在） */
	declared_size_bytes?: number;
	/** 若与传输层字节不同或可由引擎解压，记录解压后实体字节 SHA-256 */
	decoded_entity_sha256?: string;
	/** 若与传输层字节不同或可由引擎解压，记录解压后实体字节长度 */
	decoded_entity_size_bytes?: number;
	/** 字节表示层语义：捕获原始负载字节 / HTTP 解压后实体字节 / HAR 文本重编码 / 无 */
	representation: ReplayBodyRepresentation;
	/** 完整性语义：空 / 完整 / 截断 / 缺失 */
	completeness: ReplayBodyCompleteness;
	/** MIME 类型（不含敏感内容） */
	mime_type?: string;
	/** 原始 Content-Encoding 头（若存在，如 gzip, br, deflate） */
	content_encoding?: string;
	/** 诊断说明（如 text_reencoded、截断或缺失原因） */
	note?: string;
}

export interface ReplayCredentialSlot {
	/** 敏感凭据在原始请求中的位置 */
	location: "header" | "cookie" | "query" | "url_userinfo" | "body";
	/** 字段名（如 Authorization、Cookie、X-Api-Key、access_token、password） */
	name: string;
	/** 建议绑定的环境变量槽位名（不含任何真实机密值） */
	env_var: string;
	/** 在 network_replay 中的供给方式或阻断前置条件 */
	replay_binding: "auth_header_env" | "header_env_map" | "blocked_prerequisite";
	/** 是否为回放必需凭据 */
	required: boolean;
	/** 认证方案提示（如 Bearer、Basic，绝不包含凭据内容） */
	scheme?: string;
	/** 若为 Cookie 头，仅记录涉及的 Cookie 键名列表（绝不包含 Cookie 值） */
	cookie_names?: string[];
	/** 同名敏感头出现次数 */
	occurrences?: number;
	/** 前置条件说明 */
	reason: string;
}

export interface ReplayPrerequisiteBlock {
	code:
		| "sensitive_url_query"
		| "sensitive_url_userinfo"
		| "sensitive_request_body"
		| "incomplete_request_body"
		| "missing_request_body";
	message: string;
}

export interface ReplayCaseSource {
	/** 抓包文件项目相对路径 */
	path: string;
	/** 抓包文件 SHA-256 */
	sha256: string;
	/** 抓包文件字节大小 */
	size_bytes: number;
	/** 抓包格式 */
	format: ReplayCaseSourceFormat;
	/** 抓包内稳定条目 ID（如 mitm flow.id 或 HAR entry_id） */
	entry_id: string;
	/** 0 基条目索引 */
	entry_index: number;
	/** 导入时使用的显式选择器 */
	selector: {
		kind: "entry_index" | "flow_id";
		value: number | string;
	};
}

export interface ReplayCaseRequest {
	method: string;
	/**
	 * 脱敏后的安全 URL（若原 URL 含有敏感 query 参数或 userinfo，此处仅保留 [REDACTED] 占位，
	 * 同时将 replay_ready 置为 false 并写入 blocked_prerequisites，绝不静默篡改后放行主动回放）。
	 */
	url: string;
	http_version?: string;
	/**
	 * 有序非敏感请求头列表（完整保留重复同名头的原始顺序）。
	 * 敏感头（Cookie/Authorization/Token 等）不写入此列表，仅转为 credential_slots。
	 */
	headers: ReplayHeaderEntry[];
	/** 请求体私有字节文件引用 */
	body: ReplayBodyRef;
	/** 必须在回放时通过环境变量供给或解决的凭据槽位列表 */
	credential_slots: ReplayCredentialSlot[];
}

export interface ReplayCaseRecordedResponse {
	status: number;
	status_text: string;
	http_version?: string;
	/** 有序响应头列表（保留重复项，敏感值如 Set-Cookie 已脱敏为 [REDACTED]） */
	headers: ReplayHeaderEntry[];
	/** 历史响应体私有字节文件引用 */
	body: ReplayBodyRef;
}

export interface ReplayCaseV1 {
	schema_version: "1";
	case_id: string;
	workflow_id: string;
	step_id: string;
	run_id: string;
	created_at: string;
	source: ReplayCaseSource;
	request: ReplayCaseRequest;
	recorded_response: ReplayCaseRecordedResponse;
	/** 是否满足主动回放前置条件（无截断/缺失请求体，且无禁止回放的 URL/Body 内联敏感值） */
	replay_ready: boolean;
	/** 阻断主动回放的显式前置条件列表 */
	blocked_prerequisites: ReplayPrerequisiteBlock[];
}

// ============================================================================
// 常量与安全模式匹配
// ============================================================================

export const MAX_CAPTURE_FILE_BYTES = 32 * 1024 * 1024; // 32 MiB 抓包文件读取上限
export const DEFAULT_MAX_IMPORT_BODY_BYTES = 10 * 1024 * 1024; // 10 MiB 单消息体上限
export const MAX_IMPORT_BODY_BYTES = 10 * 1024 * 1024;

const ALLOWED_HTTP_METHODS: Record<string, true> = {
	GET: true,
	POST: true,
	PUT: true,
	DELETE: true,
	PATCH: true,
	HEAD: true,
	OPTIONS: true,
};

export const SENSITIVE_HEADER_NAME_PATTERN =
	/(authorization|cookie|set-cookie|proxy-authorization|proxy-authenticate|www-authenticate|x-api-key|api[-_]?key|x-auth-token|x-access-token|x-csrf-token|csrf[-_]?token|xsrf[-_]?token|token|secret|password|passwd|credential|session[-_]?key|session[-_]?id)/i;

export const SENSITIVE_QUERY_PARAM_PATTERN =
	/(token|access_token|refresh_token|id_token|auth_token|key|api[-_]?key|auth|secret|client_secret|password|passwd|credential|session[-_]?id|session[-_]?key|sig|signature|sign)/i;
const SENSITIVE_BODY_FIELD_PATTERN =
	/(password|passwd|passcode|secret|client_secret|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|private[-_]?key|session[-_]?key|credential|^token$|^auth$|^sign$|^signature$)/i;

// ============================================================================
// mitmdump 官方 FlowReader 受控 Addon 脚本（静态常量，经配置文件通信，零命令注入面）
// ============================================================================

const MITM_FLOW_IMPORT_ADDON_SOURCE = `import hashlib
import json
import os
import sys
from mitmproxy import ctx, http, version
from mitmproxy.exceptions import FlowReadException
from mitmproxy.io import FlowReader


def _decode_header_bytes(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _write_json_private(target_path: str, payload: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(target_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False)


def _write_bytes_private(target_path: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(target_path, flags, 0o600)
    with os.fdopen(fd, "wb") as fp:
        fp.write(data)


def _run_import() -> None:
    cfg_path = os.environ.get("REVERSE_MITM_IMPORT_CONFIG", "").strip()
    if not cfg_path:
        return
    with open(cfg_path, "r", encoding="utf-8") as fp:
        cfg = json.load(fp)

    result_path = cfg["result_json_path"]
    capture_path = cfg["capture_path"]
    selector_kind = cfg["selector_kind"]
    selector_value = cfg["selector_value"]
    req_body_path = cfg["request_body_path"]
    resp_body_path = cfg["response_body_path"]
    max_body_bytes = int(cfg.get("max_body_bytes", 10485760))
    mitm_ver = getattr(version, "VERSION", "unknown")

    matches = []
    total_flows = 0

    try:
        with open(capture_path, "rb") as fp:
            reader = FlowReader(fp)
            for idx, flow in enumerate(reader.stream()):
                total_flows += 1
                flow_id = str(getattr(flow, "id", "") or f"flow_{idx}")
                if selector_kind == "entry_index":
                    if idx == int(selector_value):
                        matches.append((idx, flow_id, flow))
                elif selector_kind == "flow_id":
                    if flow_id == str(selector_value):
                        matches.append((idx, flow_id, flow))
    except FlowReadException as exc:
        _write_json_private(result_path, {
            "ok": False,
            "error_code": "corrupt_capture",
            "error": f"Failed to read mitm capture via official FlowReader: {exc}",
            "mitmproxy_version": mitm_ver,
        })
        return
    except Exception as exc:
        _write_json_private(result_path, {
            "ok": False,
            "error_code": "read_error",
            "error": f"Failed to open or stream mitm capture: {exc}",
            "mitmproxy_version": mitm_ver,
        })
        return

    if len(matches) == 0:
        if selector_kind == "entry_index":
            err_msg = f"mitm capture entry_index {selector_value} is out of range (capture has {total_flows} flow(s))."
        else:
            err_msg = f"No flow found matching flow_id '{selector_value}' in mitm capture ({total_flows} flow(s) scanned)."
        _write_json_private(result_path, {
            "ok": False,
            "error_code": "not_found",
            "error": err_msg,
            "mitmproxy_version": mitm_ver,
        })
        return

    if len(matches) > 1:
        indices = ", ".join(str(m[0]) for m in matches)
        _write_json_private(result_path, {
            "ok": False,
            "error_code": "ambiguous_selector",
            "error": f"Ambiguous flow_id '{selector_value}': matched {len(matches)} flows at indices [{indices}]. Specify explicit 'entry_index' instead.",
            "mitmproxy_version": mitm_ver,
        })
        return

    matched_idx, matched_id, flow = matches[0]

    if getattr(flow, "websocket", None) is not None or getattr(flow, "type", "") == "websocket":
        _write_json_private(result_path, {
            "ok": False,
            "error_code": "websocket_flow",
            "error": f"Flow '{matched_id}' (entry_index {matched_idx}) is a WebSocket flow; WebSocket flows are refused for HTTP network_import and active replay.",
            "mitmproxy_version": mitm_ver,
        })
        return

    if not isinstance(flow, http.HTTPFlow) or getattr(flow, "request", None) is None:
        _write_json_private(result_path, {
            "ok": False,
            "error_code": "unsupported_flow",
            "error": f"Flow '{matched_id}' (entry_index {matched_idx}) is not an HTTPFlow.",
            "mitmproxy_version": mitm_ver,
        })
        return

    req = flow.request
    resp = getattr(flow, "response", None)
    if resp is None:
        _write_json_private(result_path, {
            "ok": False,
            "error_code": "missing_response",
            "error": f"HTTP flow '{matched_id}' (entry_index {matched_idx}) has no recorded HTTP response; unsupported incomplete flow.",
            "mitmproxy_version": mitm_ver,
        })
        return

    req_headers = [
        [_decode_header_bytes(k), _decode_header_bytes(v)]
        for k, v in req.headers.fields
    ]
    req_raw = req.raw_content
    req_missing = req_raw is None
    req_total_bytes = 0 if req_raw is None else len(req_raw)
    req_truncated_cap = False
    if req_raw is not None:
        if len(req_raw) > max_body_bytes:
            _write_bytes_private(req_body_path, req_raw[:max_body_bytes])
            req_truncated_cap = True
        else:
            _write_bytes_private(req_body_path, req_raw)

    req_entity_sha256 = None
    req_entity_size = None
    if req_raw is not None and not req_truncated_cap:
        try:
            dec_req = req.get_content(strict=False)
            if dec_req is not None:
                req_entity_sha256 = hashlib.sha256(dec_req).hexdigest()
                req_entity_size = len(dec_req)
        except Exception:
            pass

    resp_headers = [
        [_decode_header_bytes(k), _decode_header_bytes(v)]
        for k, v in resp.headers.fields
    ]
    resp_raw = resp.raw_content
    resp_missing = resp_raw is None
    resp_total_bytes = 0 if resp_raw is None else len(resp_raw)
    resp_truncated_cap = False
    if resp_raw is not None:
        if len(resp_raw) > max_body_bytes:
            _write_bytes_private(resp_body_path, resp_raw[:max_body_bytes])
            resp_truncated_cap = True
        else:
            _write_bytes_private(resp_body_path, resp_raw)

    resp_entity_sha256 = None
    resp_entity_size = None
    if resp_raw is not None and not resp_truncated_cap:
        try:
            dec_resp = resp.get_content(strict=False)
            if dec_resp is not None:
                resp_entity_sha256 = hashlib.sha256(dec_resp).hexdigest()
                resp_entity_size = len(dec_resp)
        except Exception:
            pass

    req_url = getattr(req, "pretty_url", None) or getattr(req, "url", "")
    flow_err_obj = getattr(flow, "error", None)
    flow_error_msg = None if flow_err_obj is None else str(getattr(flow_err_obj, "msg", flow_err_obj))

    _write_json_private(result_path, {
        "ok": True,
        "mitmproxy_version": mitm_ver,
        "entry_index": matched_idx,
        "entry_id": matched_id,
        "flow_error": flow_error_msg,
        "request": {
            "method": str(req.method or ""),
            "url": str(req_url or ""),
            "http_version": str(getattr(req, "http_version", "HTTP/1.1") or "HTTP/1.1"),
            "headers": req_headers,
            "content_missing": req_missing,
            "raw_total_bytes": req_total_bytes,
            "truncated_by_cap": req_truncated_cap,
            "decoded_entity_sha256": req_entity_sha256,
            "decoded_entity_size_bytes": req_entity_size,
        },
        "response": {
            "status": int(getattr(resp, "status_code", 0) or 0),
            "status_text": str(getattr(resp, "reason", "") or ""),
            "http_version": str(getattr(resp, "http_version", "HTTP/1.1") or "HTTP/1.1"),
            "headers": resp_headers,
            "content_missing": resp_missing,
            "raw_total_bytes": resp_total_bytes,
            "truncated_by_cap": resp_truncated_cap,
            "decoded_entity_sha256": resp_entity_sha256,
            "decoded_entity_size_bytes": resp_entity_size,
        },
    })


class _ReverseFlowImportAddon:
    def running(self) -> None:
        try:
            _run_import()
        except Exception as exc:
            cfg_path = os.environ.get("REVERSE_MITM_IMPORT_CONFIG", "").strip()
            if cfg_path and os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8") as fp:
                        cfg = json.load(fp)
                    _write_json_private(cfg["result_json_path"], {
                        "ok": False,
                        "error_code": "internal_error",
                        "error": f"Unhandled mitmproxy import error: {exc}",
                    })
                except Exception:
                    pass
        finally:
            ctx.master.shutdown()


addons = [_ReverseFlowImportAddon()]
`;

// ============================================================================
// 辅助函数：有界子进程执行与进程树清理
// ============================================================================

async function terminateProcessGroup(child: ChildProcess | undefined, timeoutMs = 2000): Promise<void> {
	if (!child || child.pid === undefined || child.pid <= 0) return;
	if (child.exitCode !== null || child.signalCode !== null) return;

	const pid = child.pid;
	const { promise: exitPromise, resolve: exitResolve } = Promise.withResolvers<void>();
	const onExit = () => exitResolve();
	child.once("exit", onExit);
	child.once("close", onExit);

	try {
		process.kill(-pid, "SIGTERM");
	} catch {
		try {
			process.kill(pid, "SIGTERM");
		} catch {}
	}

	const escalationTimer = setTimeout(() => {
		if (child.exitCode === null && child.signalCode === null) {
			try {
				process.kill(-pid, "SIGKILL");
			} catch {
				try {
					process.kill(pid, "SIGKILL");
				} catch {}
			}
		}
	}, 250);
	escalationTimer.unref?.();

	const timeoutTimer = setTimeout(() => exitResolve(), timeoutMs);
	timeoutTimer.unref?.();

	try {
		await exitPromise;
	} finally {
		clearTimeout(escalationTimer);
		clearTimeout(timeoutTimer);
		child.off("exit", onExit);
		child.off("close", onExit);
	}
}

interface BoundedCommandResult {
	exitCode: number | null;
	stdout: string;
	stderr: string;
	timedOut: boolean;
}

async function runBoundedMitmdumpAddon(options: {
	mitmdumpPath: string;
	addonPath: string;
	env: Record<string, string | undefined>;
	cwd: string;
	timeoutMs: number;
	signal?: AbortSignal;
}): Promise<BoundedCommandResult> {
	throwIfAborted(options.signal);

	const child = spawn(options.mitmdumpPath, ["-n", "-q", "-s", options.addonPath], {
		cwd: options.cwd,
		detached: true,
		stdio: ["ignore", "pipe", "pipe"],
		env: options.env,
	});

	let stdout = "";
	let stderr = "";
	let timedOut = false;
	const maxLogChars = 65536;

	child.stdout?.setEncoding("utf8");
	child.stdout?.on("data", (chunk: string) => {
		if (stdout.length < maxLogChars) {
			stdout = (stdout + chunk).slice(0, maxLogChars);
		}
	});
	child.stderr?.setEncoding("utf8");
	child.stderr?.on("data", (chunk: string) => {
		if (stderr.length < maxLogChars) {
			stderr = (stderr + chunk).slice(0, maxLogChars);
		}
	});

	const { promise: donePromise, resolve: doneResolve, reject: doneReject } = Promise.withResolvers<number | null>();
	child.once("error", err => doneReject(err));
	child.once("close", code => doneResolve(code));

	const onAbort = () => {
		void terminateProcessGroup(child);
		doneReject(new ToolError("network_import mitmdump execution aborted by caller signal"));
	};
	options.signal?.addEventListener("abort", onAbort, { once: true });

	const timer = setTimeout(() => {
		timedOut = true;
		void terminateProcessGroup(child);
	}, options.timeoutMs);
	timer.unref?.();

	try {
		const exitCode = await donePromise;
		return { exitCode, stdout, stderr, timedOut };
	} finally {
		clearTimeout(timer);
		options.signal?.removeEventListener("abort", onAbort);
		await terminateProcessGroup(child);
	}
}

// ============================================================================
// 私有文件安全读写（mode 0600，O_NOFOLLOW 防软链逃逸）
// ============================================================================

export async function readRegularFileBoundedNoFollow(
	filePath: string,
	maxBytes: number,
	label: string,
): Promise<Buffer> {
	let st: Stats;
	try {
		st = await fs.lstat(filePath);
	} catch (err) {
		throw new ToolError(`Failed to stat ${label} '${filePath}': ${err instanceof Error ? err.message : String(err)}`);
	}
	if (st.isSymbolicLink()) {
		throw new ToolError(`Symlink escape violation: ${label} '${filePath}' is a symbolic link`);
	}
	if (!st.isFile()) {
		throw new ToolError(`${label} '${filePath}' is not a regular file`);
	}
	if (st.size > maxBytes) {
		throw new ToolError(`${label} '${filePath}' exceeds maximum allowed size (${maxBytes} bytes)`);
	}

	let fh: fs.FileHandle;
	try {
		fh = await fs.open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
	} catch (err) {
		throw new ToolError(`Failed to open ${label} '${filePath}': ${err instanceof Error ? err.message : String(err)}`);
	}

	try {
		const fstat = await fh.stat();
		if (!fstat.isFile()) {
			throw new ToolError(`${label} '${filePath}' is not a regular file`);
		}
		if (fstat.size > maxBytes) {
			throw new ToolError(`${label} '${filePath}' exceeds maximum allowed size (${maxBytes} bytes)`);
		}
		const buf = Buffer.alloc(fstat.size);
		let offset = 0;
		while (offset < fstat.size) {
			const { bytesRead } = await fh.read(buf, offset, fstat.size - offset, offset);
			if (bytesRead === 0) break;
			offset += bytesRead;
		}
		return offset === fstat.size ? buf : buf.subarray(0, offset);
	} finally {
		await fh.close().catch(() => {});
	}
}

export async function writePrivateRunArtifactFile(
	targetPath: string,
	data: Buffer | string,
): Promise<{ sha256: string; size_bytes: number }> {
	const dir = path.dirname(targetPath);
	await fs.mkdir(dir, { recursive: true, mode: 0o700 });

	// 确保目标路径若已存在则不是符号链接
	try {
		const existing = await fs.lstat(targetPath);
		if (existing.isSymbolicLink()) {
			throw new ToolError(`Symlink escape violation: target path '${targetPath}' is a symbolic link`);
		}
		if (!existing.isFile()) {
			throw new ToolError(`Target path '${targetPath}' exists and is not a regular file`);
		}
	} catch (err) {
		if (err instanceof ToolError) throw err;
		if (!(err && typeof err === "object" && "code" in err && err.code === "ENOENT")) {
			throw err;
		}
	}

	const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
	const tempPath = `${targetPath}.tmp.${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;

	try {
		await fs.writeFile(tempPath, buf, { mode: 0o600, flag: "wx" });
		if (process.platform !== "win32") {
			await fs.chmod(tempPath, 0o600);
		}
		await fs.rename(tempPath, targetPath);
		if (process.platform !== "win32") {
			await fs.chmod(targetPath, 0o600);
		}
	} catch (err) {
		await fs.unlink(tempPath).catch(() => {});
		throw err;
	}

	const hashed = hashBuffer(buf);
	return { sha256: hashed.sha256, size_bytes: hashed.size };
}

// ============================================================================
// 编码、敏感字段检测与元数据脱敏辅助函数
// ============================================================================

function sanitizeEnvIdentifier(raw: string): string {
	const cleaned = raw
		.toUpperCase()
		.replace(/[^A-Z0-9]+/g, "_")
		.replace(/^_+|_+$/g, "");
	return cleaned.length > 0 ? cleaned.slice(0, 64) : "CREDENTIAL";
}

function hasUnpairedSurrogate(str: string): boolean {
	for (let i = 0; i < str.length; i++) {
		const code = str.charCodeAt(i);
		if (code >= 0xd800 && code <= 0xdbff) {
			const next = i + 1 < str.length ? str.charCodeAt(i + 1) : 0;
			if (next >= 0xdc00 && next <= 0xdfff) {
				i++;
				continue;
			}
			return true;
		}
		if (code >= 0xdc00 && code <= 0xdfff) {
			return true;
		}
	}
	return false;
}

function decodeStrictBase64(raw: string, label: string): Buffer {
	const stripped = raw.replace(/[\r\n\s]+/g, "");
	if (stripped.length === 0) {
		return Buffer.alloc(0);
	}
	if (stripped.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(stripped)) {
		throw new ToolError(`Invalid base64 payload in ${label}`);
	}
	return Buffer.from(stripped, "base64");
}

function parseCookieNamesFromHeader(cookieHeaderValue: string): string[] {
	const names: string[] = [];
	const seen = new Set<string>();
	for (const part of cookieHeaderValue.split(";")) {
		const trimmed = part.trim();
		if (!trimmed) continue;
		const eqIdx = trimmed.indexOf("=");
		const rawName = (eqIdx >= 0 ? trimmed.slice(0, eqIdx) : trimmed).trim();
		if (rawName && !seen.has(rawName)) {
			seen.add(rawName);
			names.push(rawName);
		}
	}
	return names;
}

function detectAuthScheme(value: string): string | undefined {
	const trimmed = value.trim();
	const match = trimmed.match(/^([A-Za-z0-9_-]+)\s+\S+/);
	if (!match) return undefined;
	const scheme = match[1];
	if (/^(Bearer|Basic|Digest|Token|HOBA|Mutual|AWS4-HMAC-SHA256)$/i.test(scheme)) {
		return scheme;
	}
	return undefined;
}

function findHeaderValueCaseInsensitive(headers: ReplayHeaderEntry[], targetName: string): string | undefined {
	const lower = targetName.toLowerCase();
	for (const h of headers) {
		if (h.name.toLowerCase() === lower) {
			return h.value;
		}
	}
	return undefined;
}

function parseDeclaredContentLength(headers: ReplayHeaderEntry[]): number | undefined {
	const raw = findHeaderValueCaseInsensitive(headers, "content-length");
	if (raw === undefined) return undefined;
	const trimmed = raw.trim();
	if (!/^\d+$/.test(trimmed)) return undefined;
	const parsed = Number(trimmed);
	return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

export function normalizeContentEncoding(headers: ReplayHeaderEntry[]): string | undefined {
	const raw = findHeaderValueCaseInsensitive(headers, "content-encoding");
	if (!raw) return undefined;
	const trimmed = raw.trim().toLowerCase();
	if (!trimmed || trimmed === "identity" || trimmed === "none") return undefined;
	return trimmed;
}

function normalizeMimeType(rawMime: string | undefined, headers: ReplayHeaderEntry[]): string | undefined {
	const source =
		rawMime && rawMime.trim().length > 0 ? rawMime.trim() : findHeaderValueCaseInsensitive(headers, "content-type");
	if (!source) return undefined;
	return source.split(";")[0]?.trim().toLowerCase() || undefined;
}

function inspectUrlSensitivityAndRedact(rawUrl: string): {
	parsedUrl: URL;
	redactedUrl: string;
	hasUserinfo: boolean;
	sensitiveQueryKeys: string[];
} {
	let parsed: URL;
	try {
		parsed = new URL(rawUrl);
	} catch {
		throw new ToolError(`Invalid request URL in capture entry: '${redactEvidenceText(rawUrl.slice(0, 128))}'`);
	}

	if (parsed.protocol === "ws:" || parsed.protocol === "wss:") {
		throw new ToolError(
			`Capture entry uses WebSocket scheme '${parsed.protocol}'; WebSocket flows are refused for HTTP network_import and active replay.`,
		);
	}

	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		throw new ToolError(
			`Unsupported URL scheme '${parsed.protocol}' in capture entry; only http: and https: are supported.`,
		);
	}

	const hasUserinfo = Boolean(parsed.username || parsed.password);
	const sensitiveQueryKeys: string[] = [];
	const seenKeys = new Set<string>();

	const redactedClone = new URL(parsed.toString());
	if (hasUserinfo) {
		redactedClone.username = "REDACTED";
		redactedClone.password = "";
	}

	for (const [k, v] of parsed.searchParams.entries()) {
		const isSensitiveKey = SENSITIVE_QUERY_PARAM_PATTERN.test(k);
		const isSensitiveVal = Boolean(v && redactEvidenceText(v) !== v);
		if (isSensitiveKey || isSensitiveVal) {
			if (!seenKeys.has(k)) {
				seenKeys.add(k);
				sensitiveQueryKeys.push(k);
			}
			redactedClone.searchParams.set(k, "[REDACTED]");
		}
	}

	if (redactedClone.hash && redactEvidenceText(redactedClone.hash) !== redactedClone.hash) {
		redactedClone.hash = "#[REDACTED]";
	}

	return {
		parsedUrl: parsed,
		redactedUrl: redactedClone.toString(),
		hasUserinfo,
		sensitiveQueryKeys,
	};
}

function collectSensitiveJsonKeys(value: unknown, out: Set<string>, depth = 0): void {
	if (depth > 8 || !value || typeof value !== "object") return;
	if (Array.isArray(value)) {
		for (let i = 0; i < Math.min(value.length, 50); i++) {
			collectSensitiveJsonKeys(value[i], out, depth + 1);
		}
		return;
	}
	for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
		if (SENSITIVE_BODY_FIELD_PATTERN.test(k)) {
			out.add(k);
		} else if (typeof v === "string" && v.length > 0 && redactEvidenceText(v) !== v) {
			out.add(k);
		}
		if (v && typeof v === "object") {
			collectSensitiveJsonKeys(v, out, depth + 1);
		}
	}
}

function detectSensitiveRequestBodyFields(bodyBuffer: Buffer, mimeType: string | undefined): string[] {
	if (bodyBuffer.byteLength === 0) return [];
	// 仅对不超过 1 MiB 的请求体尝试 UTF-8 语法级敏感字段扫描（不修改原始字节）
	const scanSlice = bodyBuffer.byteLength <= 1024 * 1024 ? bodyBuffer : bodyBuffer.subarray(0, 1024 * 1024);
	let decodedText: string;
	try {
		decodedText = new TextDecoder("utf-8", { fatal: true }).decode(scanSlice);
	} catch {
		return [];
	}

	const found = new Set<string>();
	const trimmed = decodedText.trim();

	// 1. JSON 对象或数组字段名检测
	if (
		mimeType?.includes("json") ||
		(trimmed.startsWith("{") && trimmed.endsWith("}")) ||
		(trimmed.startsWith("[") && trimmed.endsWith("]"))
	) {
		try {
			const parsed = JSON.parse(trimmed);
			collectSensitiveJsonKeys(parsed, found);
		} catch {}
	}

	// 2. application/x-www-form-urlencoded 键名检测
	if (
		mimeType?.includes("x-www-form-urlencoded") ||
		(!trimmed.startsWith("{") && !trimmed.includes("\n") && trimmed.includes("="))
	) {
		try {
			const params = new URLSearchParams(trimmed);
			for (const [k, v] of params.entries()) {
				if (SENSITIVE_BODY_FIELD_PATTERN.test(k)) {
					found.add(k);
				} else if (v && redactEvidenceText(v) !== v) {
					found.add(k);
				}
			}
		} catch {}
	}

	// 3. 通用高置信度机密文本特征检测（如 ghp_ / sk- / 私钥 PEM / Bearer Token）
	if (found.size === 0 && redactEvidenceText(decodedText) !== decodedText) {
		found.add("embedded_secret_token");
	}

	return Array.from(found);
}

function sanitizeResponseHeaders(rawHeaders: ReplayHeaderEntry[], requestUrl: string): ReplayHeaderEntry[] {
	const sanitized: ReplayHeaderEntry[] = [];
	for (const h of rawHeaders) {
		const name = String(h.name);
		const rawVal = String(h.value);
		const lower = name.toLowerCase();

		if (SENSITIVE_HEADER_NAME_PATTERN.test(lower)) {
			sanitized.push({ name, value: "[REDACTED]" });
			continue;
		}

		if (lower === "location") {
			try {
				const locUrl = new URL(rawVal, requestUrl);
				locUrl.username = "";
				locUrl.password = "";
				for (const [qk, qv] of Array.from(locUrl.searchParams.entries())) {
					if (SENSITIVE_QUERY_PARAM_PATTERN.test(qk) || redactEvidenceText(qv) !== qv) {
						locUrl.searchParams.set(qk, "[REDACTED]");
					}
				}
				if (locUrl.hash && redactEvidenceText(locUrl.hash) !== locUrl.hash) {
					locUrl.hash = "#[REDACTED]";
				}
				sanitized.push({ name, value: redactEvidenceText(locUrl.toString()) });
			} catch {
				sanitized.push({ name, value: "[REDACTED LOCATION]" });
			}
			continue;
		}

		sanitized.push({ name, value: redactEvidenceText(rawVal) });
	}
	return sanitized;
}

// ============================================================================
// 中间提取结构（由 HAR 读取器或 mitmdump FlowReader 产出，经统一构建器生成 ReplayCaseV1）
// ============================================================================

interface ExtractedBodyData {
	bytes: Buffer | null;
	representation: ReplayBodyRepresentation;
	completeness: ReplayBodyCompleteness;
	declaredSizeBytes?: number;
	decodedEntitySha256?: string;
	decodedEntitySizeBytes?: number;
	mimeType?: string;
	contentEncoding?: string;
	note?: string;
}

interface ExtractedCaptureEntry {
	entryId: string;
	entryIndex: number;
	engineVersion: string;
	argv: string[];
	request: {
		method: string;
		url: string;
		httpVersion?: string;
		headers: ReplayHeaderEntry[];
		explicitCookieNames?: string[];
		body: ExtractedBodyData;
	};
	response: {
		status: number;
		statusText: string;
		httpVersion?: string;
		headers: ReplayHeaderEntry[];
		body: ExtractedBodyData;
	};
}

// ============================================================================
// 原生有界 HAR 1.2 读取器
// ============================================================================

async function extractHarEntry(options: {
	captureAbsPath: string;
	selector: { kind: "entry_index"; value: number } | { kind: "flow_id"; value: string };
	maxBodyBytes: number;
}): Promise<ExtractedCaptureEntry> {
	const rawHarBuf = await readRegularFileBoundedNoFollow(
		options.captureAbsPath,
		MAX_CAPTURE_FILE_BYTES,
		"HAR capture_path",
	);

	let harText: string;
	try {
		harText = new TextDecoder("utf-8", { fatal: true }).decode(rawHarBuf);
	} catch {
		throw new ToolError(`HAR capture '${options.captureAbsPath}' is not valid UTF-8 text`);
	}

	let parsedHar: unknown;
	try {
		parsedHar = JSON.parse(harText);
	} catch (err) {
		throw new ToolError(
			`Failed to parse HAR JSON '${options.captureAbsPath}': ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	if (!isRecord(parsedHar) || !isRecord(parsedHar.log) || !Array.isArray(parsedHar.log.entries)) {
		throw new ToolError(`Invalid HAR structure in '${options.captureAbsPath}': missing 'log.entries' array`);
	}

	const entries = parsedHar.log.entries;
	if (entries.length === 0) {
		throw new ToolError(`HAR capture '${options.captureAbsPath}' contains 0 entries`);
	}

	const resolveEntryId = (entry: Record<string, unknown>, idx: number): string => {
		for (const key of ["_id", "id", "_requestId", "flow_id"]) {
			const val = entry[key];
			if (typeof val === "string" && val.trim().length > 0) {
				return val.trim();
			}
		}
		return `entry_${idx}`;
	};

	let matchedIdx = -1;
	let matchedEntry: Record<string, unknown> | undefined;
	let matchedId = "";

	if (options.selector.kind === "entry_index") {
		const idx = options.selector.value;
		if (idx < 0 || idx >= entries.length) {
			throw new ToolError(
				`HAR entry_index ${idx} is out of range (capture has ${entries.length} entries, valid indices: 0..${entries.length - 1}).`,
			);
		}
		const candidate = entries[idx];
		if (!isRecord(candidate)) {
			throw new ToolError(`HAR entry at index ${idx} is not an object`);
		}
		matchedIdx = idx;
		matchedEntry = candidate;
		matchedId = resolveEntryId(candidate, idx);
	} else {
		const targetId = options.selector.value;
		const matchedIndices: number[] = [];
		for (let i = 0; i < entries.length; i++) {
			const candidate = entries[i];
			if (!isRecord(candidate)) continue;
			const cid = resolveEntryId(candidate, i);
			if (cid === targetId || `entry_${i}` === targetId) {
				matchedIndices.push(i);
			}
		}
		if (matchedIndices.length === 0) {
			throw new ToolError(
				`No HAR entry found matching flow_id '${targetId}' in capture (${entries.length} entries scanned).`,
			);
		}
		if (matchedIndices.length > 1) {
			throw new ToolError(
				`Ambiguous flow_id '${targetId}': matched ${matchedIndices.length} HAR entries at indices [${matchedIndices.join(", ")}]. Specify explicit 'entry_index' instead.`,
			);
		}
		matchedIdx = matchedIndices[0];
		matchedEntry = entries[matchedIdx] as Record<string, unknown>;
		matchedId = resolveEntryId(matchedEntry, matchedIdx);
	}

	// WebSocket 流检测与显式拒绝
	if (matchedEntry._resourceType === "websocket" || Array.isArray(matchedEntry._webSocketMessages)) {
		throw new ToolError(
			`HAR entry '${matchedId}' (entry_index ${matchedIdx}) is a WebSocket flow; WebSocket flows are refused for HTTP network_import and active replay.`,
		);
	}

	const rawReq = matchedEntry.request;
	if (!isRecord(rawReq)) {
		throw new ToolError(`HAR entry '${matchedId}' (entry_index ${matchedIdx}) is missing 'request' object`);
	}

	if (typeof rawReq.method !== "string" || rawReq.method.trim().length === 0) {
		throw new ToolError(`HAR entry '${matchedId}' (entry_index ${matchedIdx}) is missing 'request.method'`);
	}
	const method = rawReq.method.trim().toUpperCase();
	if (!Object.hasOwn(ALLOWED_HTTP_METHODS, method)) {
		throw new ToolError(
			`Unsupported HTTP method '${method}' in HAR entry '${matchedId}'. Allowed: ${Object.keys(ALLOWED_HTTP_METHODS).join(", ")}`,
		);
	}

	if (typeof rawReq.url !== "string" || rawReq.url.trim().length === 0) {
		throw new ToolError(`HAR entry '${matchedId}' (entry_index ${matchedIdx}) is missing 'request.url'`);
	}
	const reqUrl = rawReq.url.trim();

	const parseHeadersArray = (rawList: unknown, label: string): ReplayHeaderEntry[] => {
		if (rawList === undefined) return [];
		if (!Array.isArray(rawList)) {
			throw new ToolError(`Invalid headers list in ${label}: expected array of {name, value}`);
		}
		const result: ReplayHeaderEntry[] = [];
		for (const item of rawList) {
			if (!isRecord(item) || typeof item.name !== "string" || typeof item.value !== "string") {
				throw new ToolError(`Invalid header item in ${label}: each header must have string 'name' and 'value'`);
			}
			// 过滤 HTTP/2 伪头（如 :method, :path, :authority, :scheme, :status），保留标准 HTTP 头与顺序
			if (item.name.startsWith(":")) continue;
			if (/[\r\n\0]/.test(item.name) || /[\r\n\0]/.test(item.value)) {
				throw new ToolError(`Header '${item.name}' in ${label} contains prohibited control characters`);
			}
			result.push({ name: item.name, value: item.value });
		}
		return result;
	};

	const reqHeaders = parseHeadersArray(rawReq.headers, `HAR entry ${matchedIdx} request.headers`);
	const upgradeHeader = findHeaderValueCaseInsensitive(reqHeaders, "upgrade");
	if (upgradeHeader && upgradeHeader.trim().toLowerCase() === "websocket") {
		throw new ToolError(
			`HAR entry '${matchedId}' (entry_index ${matchedIdx}) contains 'Upgrade: websocket'; WebSocket flows are refused for HTTP network_import and active replay.`,
		);
	}

	const explicitCookieNames: string[] = [];
	if (Array.isArray(rawReq.cookies)) {
		for (const c of rawReq.cookies) {
			if (isRecord(c) && typeof c.name === "string" && c.name.trim().length > 0) {
				explicitCookieNames.push(c.name.trim());
			}
		}
	}

	const rawResp = matchedEntry.response;
	if (!isRecord(rawResp)) {
		throw new ToolError(`HAR entry '${matchedId}' (entry_index ${matchedIdx}) is missing 'response' object`);
	}
	const status = typeof rawResp.status === "number" && Number.isInteger(rawResp.status) ? rawResp.status : 0;
	if (status < 100 || status > 599) {
		throw new ToolError(
			`HAR entry '${matchedId}' (entry_index ${matchedIdx}) has invalid or missing HTTP response status (${String(rawResp.status)}); unsupported incomplete transaction.`,
		);
	}
	const statusText = typeof rawResp.statusText === "string" ? rawResp.statusText : "";
	const respHeaders = parseHeadersArray(rawResp.headers, `HAR entry ${matchedIdx} response.headers`);

	// 解析 Request Body
	const reqBodySizeField =
		typeof rawReq.bodySize === "number" && Number.isInteger(rawReq.bodySize) && rawReq.bodySize >= 0
			? rawReq.bodySize
			: undefined;
	const reqDeclaredCL = parseDeclaredContentLength(reqHeaders);
	const reqDeclaredSize = reqBodySizeField ?? reqDeclaredCL;
	const reqContentEncoding = normalizeContentEncoding(reqHeaders);
	const postData = isRecord(rawReq.postData) ? rawReq.postData : undefined;
	const reqMimeType = normalizeMimeType(
		typeof postData?.mimeType === "string" ? postData.mimeType : undefined,
		reqHeaders,
	);

	const methodExpectsBody = method === "POST" || method === "PUT" || method === "PATCH";
	const reqKnownZeroSize =
		(reqBodySizeField === 0 || reqDeclaredCL === 0) &&
		(reqBodySizeField === undefined || reqBodySizeField === 0) &&
		(reqDeclaredCL === undefined || reqDeclaredCL === 0);

	let reqBody: ExtractedBodyData;
	if (!postData) {
		if ((reqDeclaredSize !== undefined && reqDeclaredSize > 0) || (methodExpectsBody && !reqKnownZeroSize)) {
			reqBody = {
				bytes: null,
				representation: "none",
				completeness: "missing",
				declaredSizeBytes: reqDeclaredSize,
				mimeType: reqMimeType,
				contentEncoding: reqContentEncoding,
				note:
					reqDeclaredSize !== undefined && reqDeclaredSize > 0
						? `HAR request declared ${reqDeclaredSize} body bytes but 'postData' is absent.`
						: `HAR ${method} request has unknown body size and no 'postData'; refusing to guess empty request body.`,
			};
		} else {
			reqBody = {
				bytes: Buffer.alloc(0),
				representation: "none",
				completeness: "empty",
				declaredSizeBytes: 0,
				mimeType: reqMimeType,
				contentEncoding: reqContentEncoding,
			};
		}
	} else if (typeof postData.text !== "string") {
		const hasParams = Array.isArray(postData.params) && postData.params.length > 0;
		const isMissing =
			hasParams ||
			(reqDeclaredSize !== undefined && reqDeclaredSize > 0) ||
			postData._missing === true ||
			(methodExpectsBody && !reqKnownZeroSize);
		if (isMissing) {
			reqBody = {
				bytes: null,
				representation: "none",
				completeness: "missing",
				declaredSizeBytes: reqDeclaredSize,
				mimeType: reqMimeType,
				contentEncoding: reqContentEncoding,
				note: hasParams
					? "HAR postData contains parsed params without raw 'text'; refusing to guess or synthesize request body."
					: "HAR postData is missing 'text' payload.",
			};
		} else {
			reqBody = {
				bytes: Buffer.alloc(0),
				representation: "none",
				completeness: "empty",
				declaredSizeBytes: 0,
				mimeType: reqMimeType,
				contentEncoding: reqContentEncoding,
			};
		}
	} else {
		const rawEncoding = typeof postData.encoding === "string" ? postData.encoding.trim().toLowerCase() : "";
		const isExplicitRawReq = postData._rawBytes === true || postData._representation === "captured_raw_bytes";
		let rawBuf: Buffer;
		let representation: ReplayBodyRepresentation;
		let note: string | undefined;

		if (rawEncoding === "base64") {
			rawBuf = decodeStrictBase64(postData.text, `HAR entry ${matchedIdx} request.postData`);
			representation =
				rawBuf.byteLength === 0 ? "none" : isExplicitRawReq ? "captured_raw_bytes" : "decoded_entity_bytes";
			if (reqContentEncoding && !isExplicitRawReq && rawBuf.byteLength > 0) {
				note = `HAR request has Content-Encoding '${reqContentEncoding}'; HAR base64 indicates binary JSON encoding and does not disambiguate pre/post-compression from Content-Encoding alone.`;
			}
		} else if (rawEncoding === "" || rawEncoding === "utf8" || rawEncoding === "utf-8") {
			if (hasUnpairedSurrogate(postData.text)) {
				throw new ToolError(
					`HAR entry '${matchedId}' request.postData.text contains unpaired UTF-16 surrogates; binary payloads in HAR must use encoding: 'base64' to preserve exact bytes.`,
				);
			}
			rawBuf = Buffer.from(postData.text, "utf8");
			representation = rawBuf.byteLength === 0 ? "none" : "text_reencoded";
			if (rawBuf.byteLength > 0) {
				note =
					"HAR plain-text postData was UTF-8 encoded into bytes (text_reencoded); original transfer encoding bytes are not guaranteed by HAR text.";
			}
		} else {
			throw new ToolError(`Unsupported HAR request.postData.encoding '${rawEncoding}' in entry '${matchedId}'`);
		}

		const explicitTrunc =
			postData._truncated === true ||
			rawReq._truncated === true ||
			rawReq.bodyTruncated === true ||
			(typeof postData.comment === "string" && /truncat/i.test(postData.comment));
		// 仅在同一表示层下比对声明长度（当存在 Content-Encoding 且非显式原始字节时，禁止拿压缩后的 Content-Length 比对实体字节）
		const sameRepReqDeclaredSize = isExplicitRawReq || !reqContentEncoding ? reqDeclaredSize : undefined;
		const declaredTrunc =
			sameRepReqDeclaredSize !== undefined &&
			sameRepReqDeclaredSize > 0 &&
			rawBuf.byteLength < sameRepReqDeclaredSize;
		const capTrunc = rawBuf.byteLength > options.maxBodyBytes;
		const finalBuf = capTrunc ? rawBuf.subarray(0, options.maxBodyBytes) : rawBuf;

		if (explicitTrunc || declaredTrunc || capTrunc) {
			reqBody = {
				bytes: finalBuf,
				representation: finalBuf.byteLength === 0 ? "none" : representation,
				completeness: "truncated",
				declaredSizeBytes: sameRepReqDeclaredSize ?? rawBuf.byteLength,
				mimeType: reqMimeType,
				contentEncoding: reqContentEncoding,
				note: capTrunc
					? `Request body truncated at max_bytes cap (${options.maxBodyBytes} bytes).`
					: `Request body in HAR is truncated (captured ${finalBuf.byteLength} of ${sameRepReqDeclaredSize ?? "unknown"} declared bytes).`,
			};
		} else if (finalBuf.byteLength === 0) {
			reqBody = {
				bytes: finalBuf,
				representation: "none",
				completeness: "empty",
				declaredSizeBytes: 0,
				mimeType: reqMimeType,
				contentEncoding: reqContentEncoding,
			};
		} else {
			const hashed = hashBuffer(finalBuf);
			const canEstablishDecodedEntity =
				(representation === "decoded_entity_bytes" || representation === "captured_raw_bytes") &&
				!reqContentEncoding;
			reqBody = {
				bytes: finalBuf,
				representation,
				completeness: "complete",
				declaredSizeBytes: sameRepReqDeclaredSize ?? finalBuf.byteLength,
				...(canEstablishDecodedEntity
					? { decodedEntitySha256: hashed.sha256, decodedEntitySizeBytes: hashed.size }
					: {}),
				mimeType: reqMimeType,
				contentEncoding: reqContentEncoding,
				note,
			};
		}
	}

	// 解析 Recorded Response Body
	const respContent = isRecord(rawResp.content) ? rawResp.content : undefined;
	if (!respContent) {
		throw new ToolError(`HAR entry '${matchedId}' (entry_index ${matchedIdx}) is missing 'response.content' object`);
	}

	const respContentSize =
		typeof respContent.size === "number" && Number.isInteger(respContent.size) && respContent.size >= 0
			? respContent.size
			: undefined;
	const respBodySizeField =
		typeof rawResp.bodySize === "number" && Number.isInteger(rawResp.bodySize) && rawResp.bodySize >= 0
			? rawResp.bodySize
			: undefined;
	const respDeclaredCL = parseDeclaredContentLength(respHeaders);
	const respContentEncoding = normalizeContentEncoding(respHeaders);
	const respCompression =
		typeof respContent.compression === "number" && respContent.compression > 0 ? respContent.compression : 0;
	const respMimeType = normalizeMimeType(
		typeof respContent.mimeType === "string" ? respContent.mimeType : undefined,
		respHeaders,
	);

	// HAR response.content.size 为解压后实体大小；仅在无 Content-Encoding 且无 compression 时才可回退参考传输层 bodySize / Content-Length
	const respSameRepEntityDeclaredSize =
		respContentSize ??
		(!respContentEncoding && respCompression === 0 ? (respBodySizeField ?? respDeclaredCL) : undefined);

	let respBody: ExtractedBodyData;
	if (typeof respContent.text !== "string") {
		const isBodylessStatus = method === "HEAD" || status === 204 || status === 304 || (status >= 100 && status < 200);
		const respKnownZeroSize =
			(respContentSize === 0 || respBodySizeField === 0 || respDeclaredCL === 0) &&
			(respContentSize === undefined || respContentSize === 0) &&
			(respBodySizeField === undefined || respBodySizeField === 0) &&
			(respDeclaredCL === undefined || respDeclaredCL === 0);
		const isExplicitMissing = respContent._missing === true || rawResp._bodyMissing === true;

		if (!isExplicitMissing && (isBodylessStatus || respKnownZeroSize)) {
			respBody = {
				bytes: Buffer.alloc(0),
				representation: "none",
				completeness: "empty",
				declaredSizeBytes: 0,
				mimeType: respMimeType,
				contentEncoding: respContentEncoding,
			};
		} else {
			const fallbackDeclared = respSameRepEntityDeclaredSize ?? respBodySizeField ?? respDeclaredCL;
			respBody = {
				bytes: null,
				representation: "none",
				completeness: "missing",
				...(fallbackDeclared !== undefined ? { declaredSizeBytes: fallbackDeclared } : {}),
				mimeType: respMimeType,
				contentEncoding: respContentEncoding,
				note: `HAR response.content.text is absent on HTTP ${status} without known 0 body size.`,
			};
		}
	} else {
		const rawEncoding = typeof respContent.encoding === "string" ? respContent.encoding.trim().toLowerCase() : "";
		const isExplicitRawResp = respContent._rawBytes === true || respContent._representation === "captured_raw_bytes";
		let rawBuf: Buffer;
		let representation: ReplayBodyRepresentation;
		let note: string | undefined;

		if (rawEncoding === "base64") {
			rawBuf = decodeStrictBase64(respContent.text, `HAR entry ${matchedIdx} response.content`);
			representation =
				rawBuf.byteLength === 0 ? "none" : isExplicitRawResp ? "captured_raw_bytes" : "decoded_entity_bytes";
			if (representation === "decoded_entity_bytes") {
				note = "HAR response.content stores HTTP entity bytes (base64 binary encoding).";
			}
		} else if (rawEncoding === "" || rawEncoding === "utf8" || rawEncoding === "utf-8") {
			if (hasUnpairedSurrogate(respContent.text)) {
				throw new ToolError(
					`HAR entry '${matchedId}' response.content.text contains unpaired UTF-16 surrogates; binary payloads in HAR must use encoding: 'base64' to preserve exact bytes.`,
				);
			}
			rawBuf = Buffer.from(respContent.text, "utf8");
			representation = rawBuf.byteLength === 0 ? "none" : "text_reencoded";
			if (rawBuf.byteLength > 0) {
				note = "HAR plain-text response.content.text was UTF-8 encoded into bytes (text_reencoded).";
			}
		} else {
			throw new ToolError(`Unsupported HAR response.content.encoding '${rawEncoding}' in entry '${matchedId}'`);
		}

		const explicitTrunc =
			respContent._truncated === true ||
			rawResp._truncated === true ||
			rawResp.bodyTruncated === true ||
			(typeof respContent.comment === "string" && /truncat/i.test(respContent.comment));
		// 同一表示层长度校验：HAR response.content 为实体字节，仅与同表示层的 content.size（或无压缩时的传输大小）比对，绝不用压缩后的 Content-Length 误判解压后的实体截断
		const sameRepRespDeclaredSize = isExplicitRawResp
			? (respBodySizeField ?? respDeclaredCL ?? respContentSize)
			: respSameRepEntityDeclaredSize;
		const declaredTrunc =
			sameRepRespDeclaredSize !== undefined &&
			sameRepRespDeclaredSize > 0 &&
			rawBuf.byteLength < sameRepRespDeclaredSize;
		const capTrunc = rawBuf.byteLength > options.maxBodyBytes;
		const finalBuf = capTrunc ? rawBuf.subarray(0, options.maxBodyBytes) : rawBuf;

		if (explicitTrunc || declaredTrunc || capTrunc) {
			respBody = {
				bytes: finalBuf,
				representation: finalBuf.byteLength === 0 ? "none" : representation,
				completeness: "truncated",
				declaredSizeBytes: sameRepRespDeclaredSize ?? rawBuf.byteLength,
				mimeType: respMimeType,
				contentEncoding: respContentEncoding,
				note: capTrunc
					? `Response body truncated at max_bytes cap (${options.maxBodyBytes} bytes).`
					: `Response body in HAR is truncated (captured ${finalBuf.byteLength} of ${sameRepRespDeclaredSize ?? "unknown"} declared entity bytes).`,
			};
		} else if (finalBuf.byteLength === 0) {
			respBody = {
				bytes: finalBuf,
				representation: "none",
				completeness: "empty",
				declaredSizeBytes: 0,
				mimeType: respMimeType,
				contentEncoding: respContentEncoding,
			};
		} else {
			const hashed = hashBuffer(finalBuf);
			respBody = {
				bytes: finalBuf,
				representation,
				completeness: "complete",
				declaredSizeBytes: sameRepRespDeclaredSize ?? finalBuf.byteLength,
				...(representation === "decoded_entity_bytes" ||
				(representation === "captured_raw_bytes" && !respContentEncoding)
					? { decodedEntitySha256: hashed.sha256, decodedEntitySizeBytes: hashed.size }
					: {}),
				mimeType: respMimeType,
				contentEncoding: respContentEncoding,
				note,
			};
		}
	}

	return {
		entryId: matchedId,
		entryIndex: matchedIdx,
		engineVersion: "native-har-1.2",
		argv: [],
		request: {
			method,
			url: reqUrl,
			httpVersion: typeof rawReq.httpVersion === "string" ? rawReq.httpVersion : undefined,
			headers: reqHeaders,
			explicitCookieNames,
			body: reqBody,
		},
		response: {
			status,
			statusText,
			httpVersion: typeof rawResp.httpVersion === "string" ? rawResp.httpVersion : undefined,
			headers: respHeaders,
			body: respBody,
		},
	};
}

// ============================================================================
// mitmdump 官方 FlowReader 读取器（--no-server -n 受控 Addon）
// ============================================================================

async function extractMitmEntry(options: {
	captureAbsPath: string;
	selector: { kind: "entry_index"; value: number } | { kind: "flow_id"; value: string };
	mitmdumpPath: string;
	runTmpDir: string;
	projectDir: string;
	maxBodyBytes: number;
	timeoutMs: number;
	signal?: AbortSignal;
}): Promise<ExtractedCaptureEntry> {
	// 预先校验文件不是符号链接且尺寸在上限内
	await readRegularFileBoundedNoFollow(options.captureAbsPath, MAX_CAPTURE_FILE_BYTES, "mitm capture_path");

	await fs.mkdir(options.runTmpDir, { recursive: true, mode: 0o700 });
	const workDir = await fs.mkdtemp(path.join(options.runTmpDir, "mitm_import_"));

	try {
		if (process.platform !== "win32") {
			await fs.chmod(workDir, 0o700);
		}
		const addonPath = path.join(workDir, "mitm_flow_import_addon.py");
		const configPath = path.join(workDir, "config.json");
		const resultJsonPath = path.join(workDir, "result.json");
		const reqBodyTmpPath = path.join(workDir, "req_body.bin");
		const respBodyTmpPath = path.join(workDir, "resp_body.bin");

		await writePrivateRunArtifactFile(addonPath, MITM_FLOW_IMPORT_ADDON_SOURCE);
		await writePrivateRunArtifactFile(
			configPath,
			JSON.stringify({
				capture_path: options.captureAbsPath,
				selector_kind: options.selector.kind,
				selector_value: options.selector.value,
				result_json_path: resultJsonPath,
				request_body_path: reqBodyTmpPath,
				response_body_path: respBodyTmpPath,
				max_body_bytes: options.maxBodyBytes,
			}),
		);

		const childEnv: Record<string, string | undefined> = {
			PATH: process.env.PATH,
			HOME: process.env.HOME,
			TMPDIR: process.env.TMPDIR,
			LANG: process.env.LANG ?? "en_US.UTF-8",
			LC_ALL: process.env.LC_ALL,
			PYTHONPATH: process.env.PYTHONPATH,
			PYTHONUNBUFFERED: "1",
			REVERSE_MITM_IMPORT_CONFIG: configPath,
		};

		const runRes = await runBoundedMitmdumpAddon({
			mitmdumpPath: options.mitmdumpPath,
			addonPath,
			env: childEnv,
			cwd: options.projectDir,
			timeoutMs: options.timeoutMs,
			signal: options.signal,
		});

		if (runRes.timedOut) {
			throw new ToolError(`mitmdump FlowReader timed out after ${Math.round(options.timeoutMs / 1000)}s`);
		}

		let resultRaw: Buffer;
		try {
			resultRaw = await readRegularFileBoundedNoFollow(resultJsonPath, 4 * 1024 * 1024, "mitm import result");
		} catch {
			const diag = redactSecrets((runRes.stderr || runRes.stdout || `exit code ${String(runRes.exitCode)}`).trim());
			throw new ToolError(`mitmdump FlowReader failed to produce import result: ${diag}`);
		}

		let parsedResult: Record<string, unknown>;
		try {
			parsedResult = JSON.parse(resultRaw.toString("utf8")) as Record<string, unknown>;
		} catch {
			throw new ToolError("mitmdump FlowReader produced malformed JSON output");
		}

		if (parsedResult.ok !== true) {
			const errMsg = typeof parsedResult.error === "string" ? parsedResult.error : "mitm flow import failed";
			throw new ToolError(errMsg);
		}

		const entryIndex = Number(parsedResult.entry_index ?? 0);
		const entryId = String(parsedResult.entry_id ?? `flow_${entryIndex}`);
		const engineVersion = `mitmproxy ${String(parsedResult.mitmproxy_version ?? "unknown")}`;

		const rawReq = parsedResult.request as Record<string, unknown>;
		const rawResp = parsedResult.response as Record<string, unknown>;

		const method = String(rawReq.method ?? "")
			.trim()
			.toUpperCase();
		if (!Object.hasOwn(ALLOWED_HTTP_METHODS, method)) {
			throw new ToolError(
				`Unsupported HTTP method '${method}' in mitm flow '${entryId}'. Allowed: ${Object.keys(ALLOWED_HTTP_METHODS).join(", ")}`,
			);
		}
		const reqUrl = String(rawReq.url ?? "").trim();

		const parseTupleHeaders = (tuples: unknown, label: string): ReplayHeaderEntry[] => {
			if (!Array.isArray(tuples)) return [];
			const out: ReplayHeaderEntry[] = [];
			for (const item of tuples) {
				if (!Array.isArray(item) || item.length < 2) continue;
				const name = String(item[0]);
				const value = String(item[1]);
				if (name.startsWith(":")) continue;
				if (/[\r\n\0]/.test(name) || /[\r\n\0]/.test(value)) {
					throw new ToolError(`Header '${name}' in ${label} contains prohibited control characters`);
				}
				out.push({ name, value });
			}
			return out;
		};

		const reqHeaders = parseTupleHeaders(rawReq.headers, `mitm flow ${entryId} request.headers`);
		const upgradeHeader = findHeaderValueCaseInsensitive(reqHeaders, "upgrade");
		if (upgradeHeader && upgradeHeader.trim().toLowerCase() === "websocket") {
			throw new ToolError(
				`Flow '${entryId}' (entry_index ${entryIndex}) contains 'Upgrade: websocket'; WebSocket flows are refused for HTTP network_import and active replay.`,
			);
		}

		const respHeaders = parseTupleHeaders(rawResp.headers, `mitm flow ${entryId} response.headers`);
		const status = Number(rawResp.status ?? 0);
		if (!Number.isInteger(status) || status < 100 || status > 599) {
			throw new ToolError(`Flow '${entryId}' has invalid HTTP response status (${String(rawResp.status)})`);
		}
		const statusText = String(rawResp.status_text ?? "");

		// 构建 Request Body
		const reqDeclaredCL = parseDeclaredContentLength(reqHeaders);
		const reqContentEncoding = normalizeContentEncoding(reqHeaders);
		const reqMimeType = normalizeMimeType(undefined, reqHeaders);
		const reqContentMissing = rawReq.content_missing === true;
		const reqRawTotalBytes = Number(rawReq.raw_total_bytes ?? 0);
		const reqTruncByCap = rawReq.truncated_by_cap === true;

		let reqBody: ExtractedBodyData;
		if (reqContentMissing) {
			reqBody = {
				bytes: null,
				representation: "none",
				completeness: "missing",
				declaredSizeBytes: reqDeclaredCL,
				mimeType: reqMimeType,
				contentEncoding: reqContentEncoding,
				note: "mitmproxy flow.request.raw_content is None (content_missing).",
			};
		} else {
			const buf = await readRegularFileBoundedNoFollow(
				reqBodyTmpPath,
				options.maxBodyBytes,
				"extracted mitm request body",
			);
			const declaredTrunc = reqDeclaredCL !== undefined && reqDeclaredCL > 0 && buf.byteLength < reqDeclaredCL;
			if (reqTruncByCap || declaredTrunc) {
				reqBody = {
					bytes: buf,
					representation: buf.byteLength === 0 ? "none" : "captured_raw_bytes",
					completeness: buf.byteLength === 0 && (reqDeclaredCL ?? 0) > 0 ? "missing" : "truncated",
					declaredSizeBytes: reqDeclaredCL ?? reqRawTotalBytes,
					mimeType: reqMimeType,
					contentEncoding: reqContentEncoding,
					note: reqTruncByCap
						? `Request body truncated at max_bytes cap (${options.maxBodyBytes} bytes).`
						: `Request body in mitm flow is shorter than declared Content-Length (${buf.byteLength} < ${reqDeclaredCL}).`,
				};
			} else if (buf.byteLength === 0) {
				reqBody = {
					bytes: buf,
					representation: "none",
					completeness: "empty",
					declaredSizeBytes: 0,
					mimeType: reqMimeType,
					contentEncoding: reqContentEncoding,
				};
			} else {
				const hashed = hashBuffer(buf);
				reqBody = {
					bytes: buf,
					representation: "captured_raw_bytes",
					completeness: "complete",
					declaredSizeBytes: reqDeclaredCL ?? buf.byteLength,
					decodedEntitySha256:
						typeof rawReq.decoded_entity_sha256 === "string" ? rawReq.decoded_entity_sha256 : hashed.sha256,
					decodedEntitySizeBytes:
						typeof rawReq.decoded_entity_size_bytes === "number" ? rawReq.decoded_entity_size_bytes : hashed.size,
					mimeType: reqMimeType,
					contentEncoding: reqContentEncoding,
				};
			}
		}

		// 构建 Response Body
		const respDeclaredCL = parseDeclaredContentLength(respHeaders);
		const respContentEncoding = normalizeContentEncoding(respHeaders);
		const respMimeType = normalizeMimeType(undefined, respHeaders);
		const respContentMissing = rawResp.content_missing === true;
		const respRawTotalBytes = Number(rawResp.raw_total_bytes ?? 0);
		const respTruncByCap = rawResp.truncated_by_cap === true;
		const flowErrorMsg =
			typeof parsedResult.flow_error === "string" && parsedResult.flow_error.trim().length > 0
				? parsedResult.flow_error.trim()
				: undefined;

		let respBody: ExtractedBodyData;
		if (respContentMissing) {
			respBody = {
				bytes: null,
				representation: "none",
				completeness: "missing",
				declaredSizeBytes: respDeclaredCL,
				mimeType: respMimeType,
				contentEncoding: respContentEncoding,
				note: "mitmproxy flow.response.raw_content is None (content_missing).",
			};
		} else {
			const buf = await readRegularFileBoundedNoFollow(
				respBodyTmpPath,
				options.maxBodyBytes,
				"extracted mitm response body",
			);
			const isBodylessStatus =
				method === "HEAD" || status === 204 || status === 304 || (status >= 100 && status < 200);
			const declaredTrunc =
				!isBodylessStatus && respDeclaredCL !== undefined && respDeclaredCL > 0 && buf.byteLength < respDeclaredCL;
			const streamErrorTrunc = !isBodylessStatus && Boolean(flowErrorMsg);

			if (respTruncByCap || declaredTrunc || streamErrorTrunc) {
				const isZeroMissing = buf.byteLength === 0 && ((respDeclaredCL ?? 0) > 0 || Boolean(flowErrorMsg));
				respBody = {
					bytes: isZeroMissing ? null : buf,
					representation: buf.byteLength === 0 ? "none" : "captured_raw_bytes",
					completeness: isZeroMissing ? "missing" : "truncated",
					...(respDeclaredCL !== undefined
						? { declaredSizeBytes: respDeclaredCL }
						: respTruncByCap
							? { declaredSizeBytes: respRawTotalBytes }
							: {}),
					mimeType: respMimeType,
					contentEncoding: respContentEncoding,
					note: respTruncByCap
						? `Response body truncated at max_bytes cap (${options.maxBodyBytes} bytes).`
						: declaredTrunc
							? `Response body in mitm flow is shorter than declared Content-Length (${buf.byteLength} < ${respDeclaredCL}).`
							: `mitmproxy recorded transport/stream error on flow: ${flowErrorMsg}`,
				};
			} else if (buf.byteLength === 0) {
				respBody = {
					bytes: buf,
					representation: "none",
					completeness: "empty",
					declaredSizeBytes: 0,
					mimeType: respMimeType,
					contentEncoding: respContentEncoding,
				};
			} else {
				const hashed = hashBuffer(buf);
				respBody = {
					bytes: buf,
					representation: "captured_raw_bytes",
					completeness: "complete",
					declaredSizeBytes: respDeclaredCL ?? buf.byteLength,
					decodedEntitySha256:
						typeof rawResp.decoded_entity_sha256 === "string" ? rawResp.decoded_entity_sha256 : hashed.sha256,
					decodedEntitySizeBytes:
						typeof rawResp.decoded_entity_size_bytes === "number"
							? rawResp.decoded_entity_size_bytes
							: hashed.size,
					mimeType: respMimeType,
					contentEncoding: respContentEncoding,
				};
			}
		}

		return {
			entryId,
			entryIndex,
			engineVersion,
			argv: [options.mitmdumpPath, "-n", "-q", "-s", "<run_tmp>/mitm_flow_import_addon.py"],
			request: {
				method,
				url: reqUrl,
				httpVersion: typeof rawReq.http_version === "string" ? rawReq.http_version : undefined,
				headers: reqHeaders,
				body: reqBody,
			},
			response: {
				status,
				statusText,
				httpVersion: typeof rawResp.http_version === "string" ? rawResp.http_version : undefined,
				headers: respHeaders,
				body: respBody,
			},
		};
	} finally {
		await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
	}
}

// ============================================================================
// 主入口：执行 network_import 并持久化 ReplayCase v1 与 mode-0600 字节体文件
// ============================================================================

export interface ExecuteNetworkImportParams {
	projectDir: string;
	workspacePath?: string;
	workflowId?: string;
	stepId?: string;
	runId?: string;
	capturePath?: string;
	captureFormat?: "har" | "mitm";
	entryIndex?: number;
	flowId?: string;
	outputPath?: string;
	maxBytes?: number;
	timeout?: number;
	which?: SkillRequirementWhich;
	signal?: AbortSignal;
}

export type ExecuteNetworkImportOutcome =
	| {
			status: "missing_dependency";
			error: string;
			missingTools: string[];
			setupCommands: string[];
	  }
	| {
			status: "ok";
			workflowId: string;
			stepId: string;
			runId: string;
			runDir: string;
			paths: AnalysisRunPaths;
			casePath: string;
			caseRelativePath: string;
			caseSha256: string;
			requestBodyPath?: string;
			requestBodyRelativePath?: string;
			responseBodyPath?: string;
			responseBodyRelativePath?: string;
			outputPaths: string[];
			relativeOutputPaths: string[];
			replayCase: ReplayCaseV1;
			argv: string[];
			exitCode: number;
			engineVersion: string;
			observations: string[];
			evidenceCandidates: Array<{
				kind: "fact";
				target: string;
				locator: string;
				sourceTool: "app_experiment";
				content: string;
				assurance?: EvidenceAssuranceLevel;
			}>;
	  };

export async function executeNetworkImport(params: ExecuteNetworkImportParams): Promise<ExecuteNetworkImportOutcome> {
	throwIfAborted(params.signal);

	const workflowId = params.workflowId?.trim() ?? "";
	if (!workflowId) {
		throw new ToolError("network_import requires explicit 'workflow_id'");
	}
	const stepId = params.stepId?.trim() ?? "";
	if (!stepId) {
		throw new ToolError("network_import requires explicit 'step_id'");
	}
	const runId = params.runId?.trim() ?? "";
	if (!runId) {
		throw new ToolError("network_import requires explicit 'run_id' from reverse_workspace(action: 'begin')");
	}
	const capturePath = params.capturePath?.trim() ?? "";
	if (!capturePath) {
		throw new ToolError("network_import requires explicit 'capture_path'");
	}

	const captureFormat = params.captureFormat;
	if (captureFormat !== "har" && captureFormat !== "mitm") {
		throw new ToolError("network_import requires explicit 'capture_format' ('har' or 'mitm')");
	}

	// 校验选择器互斥且必填
	const hasEntryIndex = params.entryIndex !== undefined;
	const hasFlowId = params.flowId !== undefined;
	if (!hasEntryIndex && !hasFlowId) {
		throw new ToolError(
			"network_import requires an explicit selector: provide either 'entry_index' (0-based integer) or 'flow_id' (non-empty string); automatic selection of the first entry is prohibited.",
		);
	}
	if (hasEntryIndex && hasFlowId) {
		throw new ToolError(
			"network_import selector conflict: 'entry_index' and 'flow_id' are mutually exclusive; specify only one.",
		);
	}

	let selector: { kind: "entry_index"; value: number } | { kind: "flow_id"; value: string };
	if (hasEntryIndex) {
		if (typeof params.entryIndex !== "number" || !Number.isInteger(params.entryIndex) || params.entryIndex < 0) {
			throw new ToolError("entry_index must be a non-negative integer (0-based)");
		}
		selector = { kind: "entry_index", value: params.entryIndex };
	} else {
		const trimmedFlowId = String(params.flowId ?? "").trim();
		if (trimmedFlowId.length === 0 || /[\r\n\0]/.test(trimmedFlowId)) {
			throw new ToolError("flow_id must be a non-empty string without control characters");
		}
		selector = { kind: "flow_id", value: trimmedFlowId };
	}

	if (params.maxBytes !== undefined) {
		if (
			typeof params.maxBytes !== "number" ||
			!Number.isSafeInteger(params.maxBytes) ||
			params.maxBytes < 1 ||
			params.maxBytes > MAX_IMPORT_BODY_BYTES
		) {
			throw new ToolError(`max_bytes must be a positive integer between 1 and ${MAX_IMPORT_BODY_BYTES} (10 MiB)`);
		}
	}
	const maxBodyBytes = params.maxBytes ?? DEFAULT_MAX_IMPORT_BODY_BYTES;

	if (params.timeout !== undefined) {
		if (
			typeof params.timeout !== "number" ||
			!Number.isFinite(params.timeout) ||
			params.timeout < 1 ||
			params.timeout > 120
		) {
			throw new ToolError("timeout must be a positive number between 1 and 120 seconds");
		}
	}
	const timeoutMs = Math.min(Math.max(params.timeout ?? 30, 1), 120) * 1000;

	// 在调用 loadAnalysisExecution 前检查 capture_path 本身是否为符号链接（拒绝包括项目内部软链在内的任何符号链接）
	const resolvedProjectDir = path.resolve(params.projectDir);
	const candidateCaptureAbs = path.resolve(resolvedProjectDir, capturePath);
	try {
		const st = await fs.lstat(candidateCaptureAbs);
		if (st.isSymbolicLink()) {
			throw new ToolError(`Symlink escape violation: capture_path '${capturePath}' is a symbolic link.`);
		}
	} catch (err) {
		if (err instanceof ToolError) throw err;
		// 若文件不存在或越界，交由 loadAnalysisExecution 给出统一安全错误
	}

	// 1. 绑定并校验活跃实验 run 与已登记输入哈希（不改写 run.json）
	const execution = await loadAnalysisExecution({
		projectDir: resolvedProjectDir,
		workspaceDir: params.workspacePath,
		workflowId,
		stepId,
		runId,
		inputPaths: [capturePath],
		outputPaths: params.outputPath ? [params.outputPath] : undefined,
	});

	const sourceRef: AnalysisFileRef | undefined = execution.inputRefs[0];
	if (!sourceRef) {
		throw new ToolError(`Failed to resolve input file reference for capture_path '${capturePath}'`);
	}
	const captureAbsPath = path.resolve(resolvedProjectDir, sourceRef.path);

	// 2. 按动作与 capture_format 检查可选外部依赖（HAR 原生读无需 mitmproxy；.mitm 需 mitmdump）
	let mitmdumpPath: string | null = null;
	if (captureFormat === "mitm") {
		const depEval = evaluateProtocolToolActionDependencies({
			toolName: "app_experiment",
			action: "network_import",
			captureFormat: "mitm",
			capturePath,
			which: params.which,
		});
		const mitmResolved = depEval.details?.mitmproxy ?? resolveMitmproxy({ which: params.which });
		mitmdumpPath = mitmResolved.mitmdumpPath;
		if (!depEval.ready || !mitmdumpPath) {
			return {
				status: "missing_dependency",
				error:
					depEval.reason ??
					"Importing .mitm flow captures requires 'mitmdump' (mitmproxy) on PATH; HAR imports work without mitmproxy.",
				missingTools: depEval.missingTools.length > 0 ? depEval.missingTools : ["mitmproxy"],
				setupCommands:
					depEval.setupCommands.length > 0 ? depEval.setupCommands : ["reverse setup reverse mitmproxy"],
			};
		}
	}

	// 3. 提取指定条目（HAR 原生有界读取；.mitm 通过官方 FlowReader 受控 addon 读取）
	const extracted =
		captureFormat === "har"
			? await extractHarEntry({
					captureAbsPath,
					selector,
					maxBodyBytes,
				})
			: await extractMitmEntry({
					captureAbsPath,
					selector,
					mitmdumpPath: mitmdumpPath!,
					runTmpDir: execution.paths.tmp_dir,
					projectDir: resolvedProjectDir,
					maxBodyBytes,
					timeoutMs,
					signal: params.signal,
				});

	// 4. URL 安全检查与脱敏（禁止静默重写内联敏感 query/userinfo 后继续回放）
	const urlInspection = inspectUrlSensitivityAndRedact(extracted.request.url);

	// 5. 提取请求头与凭据槽位（绝不将 Cookie / Authorization / API Key 等机密值写入 ReplayCase）
	const safeRequestHeaders: ReplayHeaderEntry[] = [];
	const credentialSlots: ReplayCredentialSlot[] = [];
	const headerSlotIndexByKey = new Map<string, number>();

	for (const h of extracted.request.headers) {
		const lower = h.name.toLowerCase();
		const isSensitiveName = SENSITIVE_HEADER_NAME_PATTERN.test(lower);
		const isSensitiveVal = Boolean(h.value && redactEvidenceText(h.value) !== h.value);

		if (isSensitiveName || isSensitiveVal) {
			const isCookie = lower === "cookie";
			const cookieNames = isCookie ? parseCookieNamesFromHeader(h.value) : undefined;
			const scheme = lower === "authorization" ? detectAuthScheme(h.value) : undefined;
			const existingIdx = headerSlotIndexByKey.get(lower);

			if (existingIdx !== undefined) {
				const slot = credentialSlots[existingIdx];
				slot.occurrences = (slot.occurrences ?? 1) + 1;
				if (cookieNames && cookieNames.length > 0) {
					const merged = new Set([...(slot.cookie_names ?? []), ...cookieNames]);
					slot.cookie_names = Array.from(merged);
				}
			} else {
				const envVar = `REPLAY_${sanitizeEnvIdentifier(h.name)}`;
				const replayBinding = lower === "authorization" ? "auth_header_env" : "header_env_map";
				headerSlotIndexByKey.set(lower, credentialSlots.length);
				credentialSlots.push({
					location: isCookie ? "cookie" : "header",
					name: h.name,
					env_var: envVar,
					replay_binding: replayBinding,
					required: true,
					...(scheme ? { scheme } : {}),
					...(cookieNames && cookieNames.length > 0 ? { cookie_names: cookieNames } : {}),
					occurrences: 1,
					reason: `Sensitive request ${isCookie ? "Cookie" : `header '${h.name}'`} stripped from ReplayCase metadata; provide via ${replayBinding} (${envVar}) during active replay.`,
				});
			}
			continue;
		}

		safeRequestHeaders.push({ name: h.name, value: h.value });
	}

	// 若 HAR 显式提供了 request.cookies 但未包含在 Cookie 头中，同样记入凭据槽位
	if (extracted.request.explicitCookieNames && extracted.request.explicitCookieNames.length > 0) {
		const existingCookieIdx = headerSlotIndexByKey.get("cookie");
		if (existingCookieIdx !== undefined) {
			const slot = credentialSlots[existingCookieIdx];
			const merged = new Set([...(slot.cookie_names ?? []), ...extracted.request.explicitCookieNames]);
			slot.cookie_names = Array.from(merged);
		} else {
			headerSlotIndexByKey.set("cookie", credentialSlots.length);
			credentialSlots.push({
				location: "cookie",
				name: "Cookie",
				env_var: "REPLAY_COOKIE",
				replay_binding: "header_env_map",
				required: true,
				cookie_names: Array.from(new Set(extracted.request.explicitCookieNames)),
				occurrences: 1,
				reason:
					"Sensitive request cookies stripped from ReplayCase metadata; provide via header_env_map (REPLAY_COOKIE) during active replay.",
			});
		}
	}

	// 6. 检查阻断主动回放的前置条件（URL userinfo、URL 敏感 query、请求体敏感字段、请求体缺失/截断）
	const blockedPrerequisites: ReplayPrerequisiteBlock[] = [];

	if (urlInspection.hasUserinfo) {
		credentialSlots.push({
			location: "url_userinfo",
			name: "userinfo",
			env_var: "REPLAY_URL_USERINFO",
			replay_binding: "blocked_prerequisite",
			required: true,
			reason: "Embedded URL username/password is prohibited in active replay and cannot be silently removed.",
		});
		blockedPrerequisites.push({
			code: "sensitive_url_userinfo",
			message:
				"Request URL contains embedded userinfo credentials. Active replay prohibits URL userinfo and refuses to silently alter execution-critical URL components.",
		});
	}

	if (urlInspection.sensitiveQueryKeys.length > 0) {
		for (const qKey of urlInspection.sensitiveQueryKeys) {
			credentialSlots.push({
				location: "query",
				name: qKey,
				env_var: `REPLAY_QUERY_${sanitizeEnvIdentifier(qKey)}`,
				replay_binding: "blocked_prerequisite",
				required: true,
				reason: `URL query parameter '${qKey}' holds a sensitive credential/token value; silent URL rewriting is prohibited.`,
			});
		}
		blockedPrerequisites.push({
			code: "sensitive_url_query",
			message: `Request URL contains sensitive query parameter(s) [${urlInspection.sensitiveQueryKeys.join(", ")}]. Active replay prohibits inline URL query credentials and refuses to silently replace execution-critical URL parameters.`,
		});
	}

	if (extracted.request.body.bytes && extracted.request.body.bytes.byteLength > 0) {
		const sensitiveBodyFields = detectSensitiveRequestBodyFields(
			extracted.request.body.bytes,
			extracted.request.body.mimeType,
		);
		if (sensitiveBodyFields.length > 0) {
			for (const fieldName of sensitiveBodyFields) {
				credentialSlots.push({
					location: "body",
					name: fieldName,
					env_var: `REPLAY_BODY_${sanitizeEnvIdentifier(fieldName)}`,
					replay_binding: "blocked_prerequisite",
					required: true,
					reason: `Request body contains execution-critical sensitive field '${fieldName}'; original bytes are preserved in the mode-0600 body file without silent replacement.`,
				});
			}
			blockedPrerequisites.push({
				code: "sensitive_request_body",
				message: `Request body contains sensitive credential field(s) [${sensitiveBodyFields.join(", ")}]. Original bytes are preserved in the mode-0600 body file without silent replacement; explicit prerequisite handling is required before active replay.`,
			});
		}
	}

	if (extracted.request.body.completeness === "missing") {
		blockedPrerequisites.push({
			code: "missing_request_body",
			message:
				extracted.request.body.note ??
				"Request body bytes are missing from the capture; active replay is refused because guessing or synthesizing a request body is prohibited.",
		});
	} else if (extracted.request.body.completeness === "truncated") {
		blockedPrerequisites.push({
			code: "incomplete_request_body",
			message:
				extracted.request.body.note ??
				"Request body in capture is truncated; active replay is refused because sending an incomplete request body is prohibited.",
		});
	}

	// 7. 计算并校验 run 目录内的受控输出路径（mode 0600）
	const safeCaseId = `case_${captureFormat}_${extracted.entryIndex}_${sourceRef.sha256.slice(0, 8)}`;
	const defaultCaseOutput = path.join(execution.paths.dumps_dir, `${safeCaseId}.case.json`);
	const resolvedCaseOut = await resolveAnalysisOutputPath({
		projectDir: resolvedProjectDir,
		runDir: execution.paths.run_dir,
		outputPath: params.outputPath ?? defaultCaseOutput,
	});

	const caseDir = path.dirname(resolvedCaseOut.resolvedPath);
	const caseStem = path.basename(resolvedCaseOut.resolvedPath).replace(/(\.case)?\.json$/i, "") || safeCaseId;

	const resolvedReqBodyOut = await resolveAnalysisOutputPath({
		projectDir: resolvedProjectDir,
		runDir: execution.paths.run_dir,
		outputPath: path.join(caseDir, `${caseStem}.request.body.bin`),
	});
	const resolvedRespBodyOut = await resolveAnalysisOutputPath({
		projectDir: resolvedProjectDir,
		runDir: execution.paths.run_dir,
		outputPath: path.join(caseDir, `${caseStem}.response.body.bin`),
	});

	const outputPaths: string[] = [];
	const relativeOutputPaths: string[] = [];

	// 8. 持久化请求体与历史响应体字节文件（mode 0600，绝不修改原始字节）
	let reqBodyRef: ReplayBodyRef;
	let requestBodyPath: string | undefined;
	let requestBodyRelativePath: string | undefined;

	if (extracted.request.body.bytes !== null) {
		const writtenReq = await writePrivateRunArtifactFile(
			resolvedReqBodyOut.resolvedPath,
			extracted.request.body.bytes,
		);
		requestBodyPath = resolvedReqBodyOut.resolvedPath;
		requestBodyRelativePath = resolvedReqBodyOut.relativePath;
		reqBodyRef = {
			path: resolvedReqBodyOut.relativePath,
			sha256: writtenReq.sha256,
			size_bytes: writtenReq.size_bytes,
			...(extracted.request.body.declaredSizeBytes !== undefined
				? { declared_size_bytes: extracted.request.body.declaredSizeBytes }
				: {}),
			...(extracted.request.body.decodedEntitySha256 !== undefined
				? { decoded_entity_sha256: extracted.request.body.decodedEntitySha256 }
				: {}),
			...(extracted.request.body.decodedEntitySizeBytes !== undefined
				? { decoded_entity_size_bytes: extracted.request.body.decodedEntitySizeBytes }
				: {}),
			representation: extracted.request.body.representation,
			completeness: extracted.request.body.completeness,
			...(extracted.request.body.mimeType ? { mime_type: extracted.request.body.mimeType } : {}),
			...(extracted.request.body.contentEncoding
				? { content_encoding: extracted.request.body.contentEncoding }
				: {}),
			...(extracted.request.body.note ? { note: extracted.request.body.note } : {}),
		};
	} else {
		reqBodyRef = {
			path: null,
			sha256: null,
			size_bytes: 0,
			...(extracted.request.body.declaredSizeBytes !== undefined
				? { declared_size_bytes: extracted.request.body.declaredSizeBytes }
				: {}),
			representation: "none",
			completeness: "missing",
			...(extracted.request.body.mimeType ? { mime_type: extracted.request.body.mimeType } : {}),
			...(extracted.request.body.contentEncoding
				? { content_encoding: extracted.request.body.contentEncoding }
				: {}),
			...(extracted.request.body.note ? { note: extracted.request.body.note } : {}),
		};
	}

	let respBodyRef: ReplayBodyRef;
	let responseBodyPath: string | undefined;
	let responseBodyRelativePath: string | undefined;

	if (extracted.response.body.bytes !== null) {
		const writtenResp = await writePrivateRunArtifactFile(
			resolvedRespBodyOut.resolvedPath,
			extracted.response.body.bytes,
		);
		responseBodyPath = resolvedRespBodyOut.resolvedPath;
		responseBodyRelativePath = resolvedRespBodyOut.relativePath;
		respBodyRef = {
			path: resolvedRespBodyOut.relativePath,
			sha256: writtenResp.sha256,
			size_bytes: writtenResp.size_bytes,
			...(extracted.response.body.declaredSizeBytes !== undefined
				? { declared_size_bytes: extracted.response.body.declaredSizeBytes }
				: {}),
			...(extracted.response.body.decodedEntitySha256 !== undefined
				? { decoded_entity_sha256: extracted.response.body.decodedEntitySha256 }
				: {}),
			...(extracted.response.body.decodedEntitySizeBytes !== undefined
				? { decoded_entity_size_bytes: extracted.response.body.decodedEntitySizeBytes }
				: {}),
			representation: extracted.response.body.representation,
			completeness: extracted.response.body.completeness,
			...(extracted.response.body.mimeType ? { mime_type: extracted.response.body.mimeType } : {}),
			...(extracted.response.body.contentEncoding
				? { content_encoding: extracted.response.body.contentEncoding }
				: {}),
			...(extracted.response.body.note ? { note: extracted.response.body.note } : {}),
		};
	} else {
		respBodyRef = {
			path: null,
			sha256: null,
			size_bytes: 0,
			...(extracted.response.body.declaredSizeBytes !== undefined
				? { declared_size_bytes: extracted.response.body.declaredSizeBytes }
				: {}),
			representation: "none",
			completeness: "missing",
			...(extracted.response.body.mimeType ? { mime_type: extracted.response.body.mimeType } : {}),
			...(extracted.response.body.contentEncoding
				? { content_encoding: extracted.response.body.contentEncoding }
				: {}),
			...(extracted.response.body.note ? { note: extracted.response.body.note } : {}),
		};
	}

	const sanitizedRespHeaders = sanitizeResponseHeaders(
		extracted.response.headers,
		`${urlInspection.parsedUrl.origin}${urlInspection.parsedUrl.pathname}`,
	);

	const replayReady = blockedPrerequisites.length === 0;

	const replayCase: ReplayCaseV1 = {
		schema_version: "1",
		case_id: safeCaseId,
		workflow_id: workflowId,
		step_id: stepId,
		run_id: runId,
		created_at: new Date().toISOString(),
		source: {
			path: sourceRef.path,
			sha256: sourceRef.sha256,
			size_bytes: sourceRef.size_bytes,
			format: captureFormat,
			entry_id: extracted.entryId,
			entry_index: extracted.entryIndex,
			selector,
		},
		request: {
			method: extracted.request.method,
			url: urlInspection.redactedUrl,
			...(extracted.request.httpVersion ? { http_version: extracted.request.httpVersion } : {}),
			headers: safeRequestHeaders,
			body: reqBodyRef,
			credential_slots: credentialSlots,
		},
		recorded_response: {
			status: extracted.response.status,
			status_text: redactEvidenceText(extracted.response.statusText),
			...(extracted.response.httpVersion ? { http_version: extracted.response.httpVersion } : {}),
			headers: sanitizedRespHeaders,
			body: respBodyRef,
		},
		replay_ready: replayReady,
		blocked_prerequisites: blockedPrerequisites,
	};

	const caseJsonText = `${deterministicJsonStringify(replayCase)}\n`;
	const writtenCase = await writePrivateRunArtifactFile(resolvedCaseOut.resolvedPath, caseJsonText);

	outputPaths.push(resolvedCaseOut.resolvedPath);
	relativeOutputPaths.push(resolvedCaseOut.relativePath);
	if (requestBodyPath && requestBodyRelativePath) {
		outputPaths.push(requestBodyPath);
		relativeOutputPaths.push(requestBodyRelativePath);
	}
	if (responseBodyPath && responseBodyRelativePath) {
		outputPaths.push(responseBodyPath);
		relativeOutputPaths.push(responseBodyRelativePath);
	}

	const sanitizedArgv = extracted.argv.map(arg => redactSecrets(arg));
	const locator = `${sourceRef.path}#entry=${extracted.entryIndex}(${extracted.entryId})`;
	const observations: string[] = [
		`Imported ${captureFormat.toUpperCase()} entry #${extracted.entryIndex} (${extracted.entryId}): ${replayCase.request.method} ${urlInspection.parsedUrl.origin}${urlInspection.parsedUrl.pathname} -> HTTP ${replayCase.recorded_response.status}`,
		`Request body: ${reqBodyRef.size_bytes} bytes (representation: ${reqBodyRef.representation}, completeness: ${reqBodyRef.completeness}${reqBodyRef.sha256 ? `, sha256: ${reqBodyRef.sha256.slice(0, 16)}...` : ""})`,
		`Recorded response body: ${respBodyRef.size_bytes} bytes (representation: ${respBodyRef.representation}, completeness: ${respBodyRef.completeness}${respBodyRef.sha256 ? `, sha256: ${respBodyRef.sha256.slice(0, 16)}...` : ""})`,
		`Credential slots extracted: ${credentialSlots.length}; Replay ready: ${replayReady}`,
	];
	if (blockedPrerequisites.length > 0) {
		for (const blk of blockedPrerequisites) {
			observations.push(`Blocked prerequisite [${blk.code}]: ${blk.message}`);
		}
	}

	return {
		status: "ok",
		workflowId,
		stepId,
		runId,
		runDir: execution.paths.run_dir,
		paths: execution.paths,
		casePath: resolvedCaseOut.resolvedPath,
		caseRelativePath: resolvedCaseOut.relativePath,
		caseSha256: writtenCase.sha256,
		requestBodyPath,
		requestBodyRelativePath,
		responseBodyPath,
		responseBodyRelativePath,
		outputPaths,
		relativeOutputPaths,
		replayCase,
		argv: sanitizedArgv,
		exitCode: 0,
		engineVersion: extracted.engineVersion,
		observations,
		evidenceCandidates: [
			{
				kind: "fact",
				target: sourceRef.path,
				locator,
				sourceTool: "app_experiment",
				assurance: "static_candidate",
				content: `Imported ${captureFormat.toUpperCase()} HTTP transaction ${replayCase.request.method} ${urlInspection.parsedUrl.origin}${urlInspection.parsedUrl.pathname} (status ${replayCase.recorded_response.status}, req_sha256=${reqBodyRef.sha256 ?? "missing"}, resp_sha256=${respBodyRef.sha256 ?? "missing"}) into ${resolvedCaseOut.relativePath}`,
			},
		],
	};
}

import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { hashBuffer } from "../reverse-workspace";
import { readRegularFileBoundedNoFollow, writePrivateRunArtifactFile } from "./network-import";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { approvalTargetKey } from "./approval-targets";
import { throwIfAborted } from "./tool-errors";

const MAX_INPUT_BYTES = 1024 * 1024;
const MAX_ITEMS = 4096;
const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;
const integerFieldSchema = type({
	offset: "number.integer >= 0",
	type: type.enumerated("u1", "u2le", "u2be", "u4le", "u4be"),
});
const framingSchema = type({
	header_bytes: "number.integer >= 1",
	length_field: integerFieldSchema,
	"length_kind?": type.enumerated("payload", "frame"),
	"type_field?": integerFieldSchema,
	"max_frame_bytes?": "number.integer >= 1",
});
const chunkSchema = type({
	data_hex: "string",
	"session_id?": "string",
	"direction?": type.enumerated("in", "out"),
	"reset?": "boolean",
});
const payloadSchema = type({
	payload_hex: "string",
	"header_hex?": "string",
	"session_id?": "string",
	"direction?": type.enumerated("in", "out"),
});
const messageSchema = type({
	"message_type?": "string",
	"session_id?": "string",
	"direction?": type.enumerated("in", "out"),
	"reset?": "boolean",
});
const modelSchema = type({
	initial_state: "string",
	transitions: type({
		from: "string",
		message_type: "string",
		to: "string",
		"direction?": type.enumerated("in", "out"),
	}).array(),
	"terminal_states?": "string[]",
});
export const protocolSequenceSchema = type({
	action: type.enumerated("reassemble", "build", "validate"),
	"framing?": framingSchema,
	"chunks?": chunkSchema.array(),
	"chunks_path?": type("string").describe("本地 JSON 数组，与 chunks 同形；字节顺序、TCP 去重与重传处理由上游保证"),
	"payloads?": payloadSchema.array(),
	"messages?": messageSchema.array(),
	"model?": modelSchema,
	"export_artifact?": "boolean",
	"max_output_bytes?": "number.integer >= 1024",
});
export type ProtocolSequenceParams = typeof protocolSequenceSchema.infer;
export type ProtocolSequenceAction = ProtocolSequenceParams["action"];
export type ProtocolFraming = typeof framingSchema.infer;
export type ProtocolChunk = typeof chunkSchema.infer;
export type ProtocolPayload = typeof payloadSchema.infer;
export type ProtocolOrderedMessage = typeof messageSchema.infer;
export type ProtocolTransitionModel = typeof modelSchema.infer;
type Direction = "in" | "out" | "unknown";

export const PROTOCOL_SEQUENCE_DESCRIPTION = `离线长度字段编解码与显式会话模型校验，无网络或代码执行。
reassemble: framing + chunks（或 chunks_path 本地 JSON 数组），按输入数组顺序拼接应用层字节；各 session_id/direction 独立缓存。
framing={header_bytes,length_field:{offset,type},length_kind?:"payload"|"frame",type_field?:{offset,type},max_frame_bytes?:number}。
整数类型沿用 Kaitai 命名 u1/u2le/u2be/u4le/u4be；length_kind 默认 payload，长度不含额外尾部或调整量；type_field 的十进制值为 message_type，无该字段时为 frame。
chunks=[{data_hex,session_id?:string,direction?:"in"|"out",reset?:boolean}]。reset 在该条字节前关闭当前会话实例（所有方向），新实例从零开始；不同 session_id 可交错。
build: framing + payloads=[{payload_hex,header_hex?,session_id?,direction?}]。header_hex 可提供固定头模板，长度字段总是重算且校验范围；输出完整帧至私有 artifact，分配不可用时明确报错。
validate: model={initial_state,transitions:[{from,message_type,to,direction?}],terminal_states?:string[]} + messages 或 framing/chunks。messages=[{message_type?,session_id?,direction?,reset?}]；省略 message_type 仅用于 reset 标记。
未指定方向的规则匹配所有方向；同一状态/类型的规则不可重叠；非法消息保持当前状态并记录失败。terminal_states 提供时逐会话检查结束状态。
字节来源标记保留 chunk_index、chunk 字节区间与每方向流偏移；跨方向按帧完成顺序校验，真实应用因果顺序由调用方保证。
上限：输入字节/单帧 1 MiB，条目/消息/规则 4096；输出默认 256 KiB、最高 4 MiB，省略条目有计数。export_artifact 保存完整字节/溯源报告（0600，最高 8 MiB）；会含原始敏感数据，按私有证据处理。普通输出仅含字节长度/摘要。
只检查显式模型及有限输入；assurance_level=static_candidate。TCP 重排/重传、PCAP 解流、WebSocket 控制帧/分片、校验和、压缩、解密及自动状态推断由其他工具处理。
例：protocol_sequence(action:"reassemble",framing:{header_bytes:2,length_field:{offset:0,type:"u2be"}},chunks:[{data_hex:"0003"},{data_hex:"616263000164"}])`;

export interface ProtocolSpan {
	chunk_index: number;
	chunk_start: number;
	chunk_end: number;
}
export interface ProtocolFrame {
	index: number;
	session_id: string;
	session_instance: number;
	direction: Direction;
	stream_start: number;
	stream_end: number;
	message_type: string;
	declared_length: number;
	frame_hex: string;
	payload_hex: string;
	frame_bytes: number;
	payload_bytes: number;
	frame_sha256: string;
	payload_sha256: string;
	spans: ProtocolSpan[];
}
export interface ProtocolIssue {
	session_id: string;
	session_instance: number;
	direction: Direction;
	stream_start: number;
	remaining_bytes: number;
	spans: ProtocolSpan[];
	kind: "incomplete_header" | "incomplete_frame" | "invalid_length" | "frame_too_large" | "message_limit";
}
export interface ProtocolSession {
	session_id: string;
	session_instance: number;
}
export interface ProtocolReassembly {
	frames: ProtocolFrame[];
	issues: ProtocolIssue[];
	sessions: ProtocolSession[];
	input_bytes: number;
}
export interface ProtocolTransitionTrace extends ProtocolSession {
	message_index: number;
	message_type: string;
	direction: Direction;
	state_before: string;
	state_after: string;
	valid: boolean;
}
export interface ProtocolValidation {
	valid: boolean;
	trace: ProtocolTransitionTrace[];
	sessions: Array<ProtocolSession & { final_state: string; valid: boolean }>;
}
export interface ProtocolSequenceDetails {
	action: ProtocolSequenceAction;
	status: "ok" | "invalid";
	assurance_level: "static_candidate";
	claim_scope: "explicit_framing_and_supplied_sequences_only";
	input_bytes: number;
	frames: Array<Omit<ProtocolFrame, "frame_hex" | "payload_hex">>;
	issues: ProtocolIssue[];
	validation?: ProtocolValidation;
	artifactId?: string;
	artifactPath?: string;
	artifactSha256?: string;
	truncated: boolean;
	omitted: { frames: number; issues: number; trace: number; sessions: number };
}

function boundedInteger(n: number, min: number, max: number, label: string): number {
	if (!Number.isSafeInteger(n) || n < min || n > max)
		throw new ToolError(`${label} must be an integer in [${min}, ${max}]`);
	return n;
}
function checkItems(items: readonly unknown[], label: string): void {
	if (!items.length || items.length > MAX_ITEMS) throw new ToolError(`${label} requires 1..${MAX_ITEMS} entries`);
}
function hexBytes(hex: string, label: string): Buffer {
	if (typeof hex !== "string" || hex.length > MAX_INPUT_BYTES * 2 || !/^(?:[a-fA-F0-9]{2})*$/.test(hex)) {
		throw new ToolError(`${label} must be even-length hexadecimal (at most 1 MiB)`);
	}
	return Buffer.from(hex, "hex");
}
function sessionId(id?: string): string {
	const value = id ?? "default";
	if (!value.length || value.length > 128 || /[\x00-\x1f]/.test(value))
		throw new ToolError("session_id requires 1..128 printable characters");
	return value;
}
function direction(value?: string): Direction {
	if (value === undefined || value === "unknown") return "unknown";
	if (value !== "in" && value !== "out") throw new ToolError("direction must be in or out");
	return value;
}
type IntegerField = typeof integerFieldSchema.infer;
function fieldSize(field: IntegerField): number {
	if (!["u1", "u2le", "u2be", "u4le", "u4be"].includes(field.type))
		throw new ToolError("Unsupported integer field type");
	return field.type === "u1" ? 1 : Number(field.type[1]);
}
function readInteger(bytes: Buffer, field: IntegerField): number {
	const size = fieldSize(field);
	return field.type.endsWith("le") ? bytes.readUIntLE(field.offset, size) : bytes.readUIntBE(field.offset, size);
}
function checkedFraming(config: ProtocolFraming): ProtocolFraming {
	const header = boundedInteger(config.header_bytes, 1, 4096, "header_bytes");
	const max = boundedInteger(config.max_frame_bytes ?? MAX_INPUT_BYTES, header, MAX_INPUT_BYTES, "max_frame_bytes");
	const fields = [config.length_field, ...(config.type_field ? [config.type_field] : [])];
	for (const field of fields) boundedInteger(field.offset, 0, header - fieldSize(field), "field offset");
	if (
		fields.length === 2 &&
		fields[0]!.offset < fields[1]!.offset + fieldSize(fields[1]!) &&
		fields[1]!.offset < fields[0]!.offset + fieldSize(fields[0]!)
	) {
		throw new ToolError("length_field and type_field must not overlap");
	}
	if (config.length_kind !== undefined && config.length_kind !== "payload" && config.length_kind !== "frame")
		throw new ToolError("length_kind must be payload or frame");
	return { ...config, max_frame_bytes: max };
}

/** 输入已完成传输层排序；遇到非法长度后保留整段剩余来源，直到显式 reset，避免猜测重同步。 */
export function reassembleProtocolMessages(chunks: ProtocolChunk[], framing: ProtocolFraming): ProtocolReassembly {
	checkItems(chunks, "chunks");
	const config = checkedFraming(framing);
	let inputBytes = 0;
	for (const chunk of chunks) {
		if (typeof chunk.data_hex !== "string") throw new ToolError("data_hex must be hexadecimal");
		inputBytes += chunk.data_hex.length / 2;
		boundedInteger(inputBytes, 0, MAX_INPUT_BYTES, "total input bytes");
	}
	const decoded = chunks.map((chunk, index) => ({
		...chunk,
		bytes: hexBytes(chunk.data_hex, `chunks[${index}].data_hex`),
	}));
	type Segment = { bytes: Buffer; index: number; start: number };
	type Stream = {
		direction: Direction;
		segments: Segment[];
		offset: number;
		bytes: number;
		halted?: ProtocolIssue["kind"];
	};
	type Session = ProtocolSession & { streams: Map<Direction, Stream> };
	const current = new Map<string, Session>();
	const sessions: Session[] = [];
	const frames: ProtocolFrame[] = [];
	const issues: ProtocolIssue[] = [];
	const spansFor = (stream: Stream, length: number): ProtocolSpan[] => {
		const spans: ProtocolSpan[] = [];
		for (const seg of stream.segments) {
			const used = Math.min(length, seg.bytes.length - seg.start);
			if (used) spans.push({ chunk_index: seg.index, chunk_start: seg.start, chunk_end: seg.start + used });
			length -= used;
			if (!length) break;
		}
		return spans;
	};
	const finish = (session: Session) => {
		for (const stream of session.streams.values()) {
			if (!stream.bytes) continue;
			issues.push({
				session_id: session.session_id,
				session_instance: session.session_instance,
				direction: stream.direction,
				stream_start: stream.offset,
				remaining_bytes: stream.bytes,
				spans: spansFor(stream, stream.bytes),
				kind: stream.halted ?? (stream.bytes < config.header_bytes ? "incomplete_header" : "incomplete_frame"),
			});
		}
	};
	for (const [chunkIndex, chunk] of decoded.entries()) {
		const id = sessionId(chunk.session_id);
		let session = current.get(id);
		if (!session || chunk.reset) {
			if (session) finish(session);
			session = { session_id: id, session_instance: (session?.session_instance ?? -1) + 1, streams: new Map() };
			current.set(id, session);
			sessions.push(session);
		}
		const dir = direction(chunk.direction);
		let stream = session.streams.get(dir);
		if (!stream) {
			stream = { direction: dir, segments: [], offset: 0, bytes: 0 };
			session.streams.set(dir, stream);
		}
		if (chunk.bytes.length) {
			stream.segments.push({ bytes: chunk.bytes, index: chunkIndex, start: 0 });
			stream.bytes += chunk.bytes.length;
		}
		const peek = (length: number): Buffer => {
			const parts: Buffer[] = [];
			for (const seg of stream.segments) {
				const used = Math.min(length, seg.bytes.length - seg.start);
				parts.push(seg.bytes.subarray(seg.start, seg.start + used));
				length -= used;
				if (!length) break;
			}
			return Buffer.concat(parts);
		};
		while (!stream.halted && stream.bytes >= config.header_bytes) {
			// 只读取固定头部，确认完整帧到齐后才聚合；从不按声明长度预分配。
			const declared = readInteger(peek(config.header_bytes), config.length_field);
			const frameBytes = config.length_kind === "frame" ? declared : config.header_bytes + declared;
			if (frameBytes < config.header_bytes) {
				stream.halted = "invalid_length";
				break;
			}
			if (frameBytes > config.max_frame_bytes!) {
				stream.halted = "frame_too_large";
				break;
			}
			if (stream.bytes < frameBytes) break;
			if (frames.length === MAX_ITEMS) {
				stream.halted = "message_limit";
				break;
			}
			const frame = peek(frameBytes);
			const payload = frame.subarray(config.header_bytes);
			frames.push({
				index: frames.length,
				session_id: id,
				session_instance: session.session_instance,
				direction: dir,
				stream_start: stream.offset,
				stream_end: stream.offset + frameBytes,
				message_type: config.type_field ? String(readInteger(frame, config.type_field)) : "frame",
				declared_length: declared,
				frame_hex: frame.toString("hex"),
				payload_hex: payload.toString("hex"),
				frame_bytes: frameBytes,
				payload_bytes: payload.length,
				frame_sha256: hashBuffer(frame).sha256,
				payload_sha256: hashBuffer(payload).sha256,
				spans: spansFor(stream, frameBytes),
			});
			let left = frameBytes;
			while (left) {
				const seg = stream.segments[0]!;
				const used = Math.min(left, seg.bytes.length - seg.start);
				seg.start += used;
				left -= used;
				if (seg.start === seg.bytes.length) stream.segments.shift();
			}
			stream.offset += frameBytes;
			stream.bytes -= frameBytes;
		}
	}
	for (const session of current.values()) finish(session);
	return {
		frames,
		issues,
		sessions: sessions.map(({ session_id, session_instance }) => ({ session_id, session_instance })),
		input_bytes: inputBytes,
	};
}

export function buildProtocolFrames(payloads: ProtocolPayload[], framing: ProtocolFraming): ProtocolReassembly {
	checkItems(payloads, "payloads");
	const config = checkedFraming(framing);
	let total = 0;
	const chunks = payloads.map((payload, index): ProtocolChunk => {
		const bytes = hexBytes(payload.payload_hex, `payloads[${index}].payload_hex`);
		const size = config.header_bytes + bytes.length;
		boundedInteger(size, config.header_bytes, config.max_frame_bytes!, "frame bytes");
		total += size;
		boundedInteger(total, 0, MAX_INPUT_BYTES, "total built bytes");
		const header =
			payload.header_hex === undefined
				? Buffer.alloc(config.header_bytes)
				: hexBytes(payload.header_hex, "header_hex");
		if (header.length !== config.header_bytes) throw new ToolError("header_hex must match header_bytes exactly");
		const declared = config.length_kind === "frame" ? size : bytes.length;
		const width = fieldSize(config.length_field);
		if (declared >= 2 ** (width * 8)) throw new ToolError("payload/frame length does not fit length_field");
		if (config.length_field.type.endsWith("le")) header.writeUIntLE(declared, config.length_field.offset, width);
		else header.writeUIntBE(declared, config.length_field.offset, width);
		return {
			data_hex: Buffer.concat([header, bytes]).toString("hex"),
			session_id: payload.session_id,
			direction: payload.direction,
		};
	});
	const result = reassembleProtocolMessages(chunks, config);
	if (
		result.issues.length ||
		result.frames.length !== payloads.length ||
		result.frames.some((frame, index) => frame.payload_hex !== payloads[index]!.payload_hex.toLowerCase())
	) {
		throw new ToolError("Internal codec roundtrip verification failed");
	}
	return result;
}

function modelName(value: string): void {
	if (typeof value !== "string" || !value.length || value.length > 128 || /[\x00-\x1f]/.test(value))
		throw new ToolError("model states/types require 1..128 printable characters");
}
/** 只执行用户显式列出的转移，失败后保留状态；不进行状态推断、规则优先级或错误恢复猜测。 */
export function validateProtocolSessions(
	messages: ProtocolOrderedMessage[],
	model: ProtocolTransitionModel,
): ProtocolValidation {
	checkItems(messages, "messages");
	checkItems(model.transitions, "transitions");
	modelName(model.initial_state);
	if ((model.terminal_states?.length ?? 0) > MAX_ITEMS) throw new ToolError("Too many terminal states");
	for (const state of model.terminal_states ?? []) modelName(state);
	const rules = new Map<string, typeof model.transitions>();
	for (const transition of model.transitions) {
		modelName(transition.from);
		modelName(transition.to);
		modelName(transition.message_type);
		if (transition.direction !== undefined) direction(transition.direction);
		const key = JSON.stringify([transition.from, transition.message_type]);
		const siblings = rules.get(key) ?? [];
		if (siblings.some(rule => !rule.direction || !transition.direction || rule.direction === transition.direction))
			throw new ToolError("Overlapping transitions are ambiguous");
		siblings.push(transition);
		rules.set(key, siblings);
	}
	const current = new Map<string, ProtocolValidation["sessions"][number]>();
	const sessions: ProtocolValidation["sessions"] = [];
	const trace: ProtocolTransitionTrace[] = [];
	for (const [index, message] of messages.entries()) {
		const id = sessionId(message.session_id);
		let session = current.get(id);
		if (!session || message.reset) {
			session = {
				session_id: id,
				session_instance: (session?.session_instance ?? -1) + 1,
				final_state: model.initial_state,
				valid: true,
			};
			current.set(id, session);
			sessions.push(session);
		}
		if (message.message_type === undefined) {
			if (!message.reset) throw new ToolError("message_type may be omitted only on reset markers");
			continue;
		}
		modelName(message.message_type);
		const dir = direction(message.direction);
		const before = session.final_state;
		const rule = rules
			.get(JSON.stringify([before, message.message_type]))
			?.find(candidate => !candidate.direction || candidate.direction === dir);
		if (rule) session.final_state = rule.to;
		else session.valid = false;
		trace.push({
			session_id: id,
			session_instance: session.session_instance,
			message_index: index,
			message_type: message.message_type,
			direction: dir,
			state_before: before,
			state_after: session.final_state,
			valid: Boolean(rule),
		});
	}
	if (model.terminal_states)
		for (const session of sessions) session.valid &&= model.terminal_states.includes(session.final_state);
	return { valid: sessions.every(session => session.valid), trace, sessions };
}

export class ProtocolSequenceTool implements AgentTool<typeof protocolSequenceSchema, ProtocolSequenceDetails> {
	readonly name = "protocol_sequence";
	readonly approval: ToolTier = "read";
	readonly label = "协议序列与编解码";
	readonly summary = "离线长度前缀消息重组、帧构造和显式有序会话模型校验";
	readonly description = PROTOCOL_SEQUENCE_DESCRIPTION;
	readonly parameters = protocolSequenceSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approvalCacheTargets = (args: unknown): readonly string[] | undefined => {
		if (!args || typeof args !== "object" || !("chunks_path" in args) || typeof args.chunks_path !== "string")
			return undefined;
		const target = approvalTargetKey(this.session.cwd, args.chunks_path);
		return target ? [target] : undefined;
	};
	constructor(private readonly session: ToolSession) {}

	async execute(
		_id: string,
		params: ProtocolSequenceParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<ProtocolSequenceDetails> & { details: ProtocolSequenceDetails }> {
		throwIfAborted(signal);
		const cap = boundedInteger(params.max_output_bytes ?? 256 * 1024, 1024, 4 * 1024 * 1024, "max_output_bytes");
		if (!["reassemble", "build", "validate"].includes(params.action)) throw new ToolError("Unsupported action");
		if (params.chunks && params.chunks_path) throw new ToolError("Use chunks or chunks_path, not both");
		let chunks = params.chunks;
		if (params.chunks_path !== undefined) {
			if (!params.chunks_path.trim() || /^[a-z][a-z0-9+.-]*:/i.test(params.chunks_path))
				throw new ToolError("chunks_path must be a local JSON file");
			const bytes = await readRegularFileBoundedNoFollow(
				resolveReadPath(params.chunks_path, this.session.cwd),
				4 * MAX_INPUT_BYTES,
				"ordered chunks",
			);
			let parsed: unknown;
			try {
				parsed = JSON.parse(bytes.toString("utf8"));
			} catch {
				throw new ToolError("chunks_path must contain a JSON array of chunks");
			}
			const checked = chunkSchema.array()(parsed);
			if (checked instanceof type.errors) throw new ToolError("chunks_path does not match ordered chunk schema");
			chunks = checked;
		}
		throwIfAborted(signal);
		const hasChunks = chunks !== undefined;
		if (params.action !== "validate" && (params.messages !== undefined || params.model !== undefined))
			throw new ToolError("messages/model require validate");
		if (params.action !== "build" && params.payloads !== undefined) throw new ToolError("payloads require build");
		if (params.action === "build" && hasChunks) throw new ToolError("build accepts payloads, not chunks");
		if (params.messages !== undefined && (hasChunks || params.framing !== undefined))
			throw new ToolError("validate accepts messages or framing/chunks, not both");
		let report: ProtocolReassembly = { frames: [], issues: [], sessions: [], input_bytes: 0 };
		let validation: ProtocolValidation | undefined;
		if (params.action === "build") {
			if (!params.framing || !params.payloads) throw new ToolError("build requires framing and payloads");
			report = buildProtocolFrames(params.payloads, params.framing);
		} else if (hasChunks) {
			if (!params.framing) throw new ToolError("reassembly requires framing");
			report = reassembleProtocolMessages(chunks!, params.framing);
		} else if (params.action !== "validate")
			throw new ToolError("reassemble requires framing and chunks/chunks_path");
		if (params.action === "validate") {
			if (!params.model) throw new ToolError("validate requires an explicit model");
			if (params.messages !== undefined) validation = validateProtocolSessions(params.messages, params.model);
			else {
				if (!hasChunks) throw new ToolError("validate requires messages or framing/chunks");
				// 帧完成顺序是唯一可观察的跨方向顺序；包含无完整消息的会话，避免空流被误报为通过。
				const ordered: ProtocolOrderedMessage[] = [];
				const ids = new Map<string, string>();
				for (const session of report.sessions) {
					const key = JSON.stringify([session.session_id, session.session_instance]);
					ids.set(key, `session-${ids.size}`);
					ordered.push({ session_id: ids.get(key)!, reset: true });
				}
				for (const frame of report.frames) {
					const key = JSON.stringify([frame.session_id, frame.session_instance]);
					ordered.push({
						session_id: ids.get(key)!,
						message_type: frame.message_type,
						...(frame.direction === "unknown" ? {} : { direction: frame.direction }),
					});
				}
				if (ordered.length > MAX_ITEMS) throw new ToolError("Validation event limit exceeded; split input");
				validation = validateProtocolSessions(ordered, params.model);
				const restore = <T extends ProtocolSession>(value: T): T => {
					const source = report.sessions[Number(value.session_id.slice("session-".length))]!;
					return { ...value, ...source };
				};
				validation.trace = validation.trace.map(entry => ({
					...restore(entry),
					message_index: entry.message_index - report.sessions.length,
				}));
				validation.sessions = validation.sessions.map(session => {
					const restored = restore(session);
					return {
						...restored,
						valid:
							session.valid &&
							!report.issues.some(
								issue =>
									issue.session_id === restored.session_id &&
									issue.session_instance === restored.session_instance,
							),
					};
				});
				validation.valid = !report.issues.length && validation.sessions.every(session => session.valid);
			}
		}
		throwIfAborted(signal);
		const details: ProtocolSequenceDetails = {
			action: params.action,
			status: report.issues.length || validation?.valid === false ? "invalid" : "ok",
			assurance_level: "static_candidate",
			claim_scope: "explicit_framing_and_supplied_sequences_only",
			input_bytes: report.input_bytes,
			frames: report.frames.map(({ frame_hex: _frame, payload_hex: _payload, ...metadata }) => metadata),
			issues: report.issues,
			...(validation ? { validation } : {}),
			truncated: false,
			omitted: { frames: 0, issues: 0, trace: 0, sessions: 0 },
		};
		if (params.export_artifact || params.action === "build") {
			const full = JSON.stringify({
				...details,
				frames: report.frames,
				sessions: report.sessions,
				...(params.framing ? { framing: params.framing } : {}),
				...(params.model ? { model: params.model } : {}),
				...(chunks ? { source_chunks: chunks } : {}),
			});
			if (Buffer.byteLength(full) > MAX_ARTIFACT_BYTES)
				throw new ToolError("Private artifact exceeds 8 MiB; split input");
			const allocation = await this.session.allocateOutputArtifact?.("protocol_sequence");
			if (!allocation?.path || !allocation.id)
				throw new ToolError("Private artifact storage unavailable; build/export requires artifact storage");
			const written = await writePrivateRunArtifactFile(allocation.path, full);
			details.artifactId = allocation.id;
			details.artifactPath = allocation.path;
			details.artifactSha256 = written.sha256;
		}
		// details 与文本共同受限，省略完整条目而非截断 JSON/字节，避免隐藏巨量结构化输出。
		while (Buffer.byteLength(JSON.stringify(details)) > cap) {
			details.truncated = true;
			const trim = <T>(items: T[], kind: keyof ProtocolSequenceDetails["omitted"]) => {
				const count = Math.ceil(items.length / 2);
				items.splice(items.length - count, count);
				details.omitted[kind] += count;
			};
			if (details.frames.length) trim(details.frames, "frames");
			else if (details.validation?.trace.length) trim(details.validation.trace, "trace");
			else if (details.issues.length) trim(details.issues, "issues");
			else if (details.validation?.sessions.length) trim(details.validation.sessions, "sessions");
			else throw new ToolError("Output envelope exceeds max_output_bytes");
		}
		return { content: [{ type: "text", text: JSON.stringify(details) }], details };
	}
}

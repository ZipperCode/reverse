import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { validateToolArguments } from "@reverse/ai";
import { type } from "@reverse/reversetype";
import { Settings } from "../../src/config/settings";
import { resolveApproval } from "../../src/tools/approval";
import type { ToolSession } from "../../src/tools/index";
import {
	ProtocolSequenceTool,
	buildProtocolFrames,
	reassembleProtocolMessages,
	type ProtocolFraming,
	type ProtocolSequenceParams,
	type ProtocolTransitionModel,
} from "../../src/tools/protocol-sequence";

let root: string;
let counter = 0;
const framing: ProtocolFraming = {
	header_bytes: 3,
	length_field: { offset: 0, type: "u2be" },
	type_field: { offset: 2, type: "u1" },
};
const model: ProtocolTransitionModel = {
	initial_state: "idle",
	terminal_states: ["done"],
	transitions: [
		{ from: "idle", message_type: "1", direction: "out", to: "waiting" },
		{ from: "waiting", message_type: "2", direction: "in", to: "done" },
	],
};
function session(artifacts = true): ToolSession {
	return {
		cwd: root,
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		...(artifacts
			? {
					allocateOutputArtifact: async () => ({
						id: `protocol-${++counter}`,
						path: path.join(root, `protocol-${counter}.json`),
					}),
				}
			: {}),
	};
}
async function run(params: ProtocolSequenceParams, target = session()) {
	const tool = new ProtocolSequenceTool(target);
	// 与实际工具一样先执行公开 schema，再执行真实边界；不是仅测试 helper。
	const parsed = tool.parameters(params);
	if (parsed instanceof type.errors) throw new Error(parsed.summary);
	return tool.execute("test", parsed);
}
beforeAll(async () => {
	root = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-protocol-sequence-"));
});
afterAll(async () => {
	await fs.rm(root, { recursive: true, force: true });
});

describe("protocol_sequence framing", () => {
	it("reassembles split headers/payloads and coalesced frames with byte provenance", async () => {
		const result = await run({
			action: "reassemble",
			framing,
			export_artifact: true,
			chunks: [{ data_hex: "00" }, { data_hex: "030161" }, { data_hex: "626300010264" }],
		});
		expect(result.details.status).toBe("ok");
		expect(
			result.details.frames.map(frame => [
				frame.message_type,
				frame.frame_bytes,
				frame.payload_bytes,
				frame.stream_start,
				frame.stream_end,
			]),
		).toEqual([
			["1", 6, 3, 0, 6],
			["2", 4, 1, 6, 10],
		]);
		expect(result.details.frames[0]!.spans).toEqual([
			{ chunk_index: 0, chunk_start: 0, chunk_end: 1 },
			{ chunk_index: 1, chunk_start: 0, chunk_end: 3 },
			{ chunk_index: 2, chunk_start: 0, chunk_end: 2 },
		]);
		expect(result.details.frames[1]!.spans).toEqual([{ chunk_index: 2, chunk_start: 2, chunk_end: 6 }]);
		const artifact = JSON.parse(await fs.readFile(result.details.artifactPath!, "utf8"));
		expect(artifact.frames.map((frame: { payload_hex: string }) => frame.payload_hex)).toEqual(["616263", "64"]);
		expect(JSON.stringify(result.details)).not.toContain("payload_hex");
		expect(result.details.frames[0]!.payload_sha256).toBe(
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		);
	});

	it("keeps directions and interleaved independent sessions separate", async () => {
		const result = await run({
			action: "reassemble",
			framing,
			chunks: [
				{ session_id: "A", direction: "out", data_hex: "00020161" },
				{ session_id: "A", direction: "in", data_hex: "00010262" },
				{ session_id: "B", direction: "out", data_hex: "00010163" },
				{ session_id: "A", direction: "out", data_hex: "64" },
			],
		});
		expect(
			result.details.frames.map(frame => [
				frame.session_id,
				frame.direction,
				frame.message_type,
				frame.stream_start,
			]),
		).toEqual([
			["A", "in", "2", 0],
			["B", "out", "1", 0],
			["A", "out", "1", 0],
		]);
		expect(result.details.issues).toEqual([]);
	});

	it("reports incomplete headers and frames rather than discarding tails", async () => {
		const result = await run({
			action: "reassemble",
			framing,
			chunks: [
				{ session_id: "header", data_hex: "00" },
				{ session_id: "body", data_hex: "00040161" },
			],
		});
		expect(result.details.status).toBe("invalid");
		expect(result.details.issues.map(issue => [issue.kind, issue.remaining_bytes])).toEqual([
			["incomplete_header", 1],
			["incomplete_frame", 4],
		]);
		expect(result.details.issues[1]!.spans).toEqual([{ chunk_index: 1, chunk_start: 0, chunk_end: 4 }]);
	});

	it("rejects undersized total length and oversized length without guessing resynchronization", async () => {
		const invalid = await run({
			action: "reassemble",
			framing: { ...framing, length_kind: "frame" },
			chunks: [{ data_hex: "000101000301" }],
		});
		expect(invalid.details.frames).toEqual([]);
		expect(invalid.details.issues[0]!.kind).toBe("invalid_length");
		expect(invalid.details.issues[0]!.remaining_bytes).toBe(6);
		const oversized = await run({
			action: "reassemble",
			framing: { ...framing, max_frame_bytes: 8 },
			chunks: [{ data_hex: "ffff01" }],
		});
		expect(oversized.details.issues[0]!.kind).toBe("frame_too_large");
	});

	it("reset closes all directions, reports old fragments and starts clean stream offsets", async () => {
		const result = await run({
			action: "reassemble",
			framing,
			chunks: [
				{ direction: "out", data_hex: "00020161" },
				{ direction: "in", data_hex: "00" },
				{ direction: "out", data_hex: "00010162", reset: true },
			],
		});
		expect(result.details.issues.map(issue => [issue.direction, issue.session_instance, issue.kind])).toEqual([
			["out", 0, "incomplete_frame"],
			["in", 0, "incomplete_header"],
		]);
		expect(result.details.frames[0]!.session_instance).toBe(1);
		expect(result.details.frames[0]!.stream_start).toBe(0);
	});
});

describe("protocol_sequence codec", () => {
	it("builds exact bytes and verifies payload roundtrip for each integer width/endian and length meaning", async () => {
		for (const integerType of ["u1", "u2le", "u2be", "u4le", "u4be"] as const) {
			const size = integerType === "u1" ? 1 : Number(integerType[1]);
			for (const kind of ["payload", "frame"] as const) {
				const config: ProtocolFraming = {
					header_bytes: size + 1,
					length_field: { offset: 1, type: integerType },
					length_kind: kind,
				};
				const result = await run({
					action: "build",
					framing: config,
					payloads: [{ payload_hex: "AaBb", header_hex: `7f${"ff".repeat(size)}` }, { payload_hex: "" }],
				});
				expect(result.details.status).toBe("ok");
				const artifact = JSON.parse(await fs.readFile(result.details.artifactPath!, "utf8"));
				const frame = Buffer.from(artifact.frames[0].frame_hex, "hex");
				expect(frame[0]).toBe(127);
				const declared = integerType.endsWith("le") ? frame.readUIntLE(1, size) : frame.readUIntBE(1, size);
				expect(declared).toBe(kind === "payload" ? 2 : size + 3);
				expect(artifact.frames.map((item: { payload_hex: string }) => item.payload_hex)).toEqual(["aabb", ""]);
				if (process.platform !== "win32")
					expect((await fs.stat(result.details.artifactPath!)).mode & 0o777).toBe(0o600);
			}
		}
	});

	it("actually decodes lengths above 255 using the configured byte order", () => {
		for (const integerType of ["u2le", "u2be", "u4le", "u4be"] as const) {
			const size = Number(integerType[1]);
			const payload = "ab".repeat(258);
			const built = buildProtocolFrames([{ payload_hex: payload }], {
				header_bytes: size,
				length_field: { offset: 0, type: integerType },
			});
			const expectedPrefix =
				integerType === "u2le"
					? "0201"
					: integerType === "u2be"
						? "0102"
						: integerType === "u4le"
							? "02010000"
							: "00000102";
			expect(built.frames[0]!.frame_hex.startsWith(expectedPrefix)).toBe(true);
			expect(built.frames[0]!.payload_hex).toBe(payload);
		}
	});

	it("rejects malformed bytes, overlapping/out-of-header fields, invalid bounds and length overflow", async () => {
		for (const data_hex of ["0", "zz", "aa bb"])
			await expect(run({ action: "reassemble", framing, chunks: [{ data_hex }] })).rejects.toThrow();
		await expect(
			run({
				action: "reassemble",
				framing: { ...framing, type_field: { offset: 1, type: "u1" } },
				chunks: [{ data_hex: "" }],
			}),
		).rejects.toThrow("overlap");
		await expect(
			run({
				action: "reassemble",
				framing: { ...framing, length_field: { offset: 2, type: "u2be" } },
				chunks: [{ data_hex: "" }],
			}),
		).rejects.toThrow("offset");
		await expect(
			run({
				action: "build",
				framing: { header_bytes: 1, length_field: { offset: 0, type: "u1" } },
				payloads: [{ payload_hex: "ff".repeat(256) }],
			}),
		).rejects.toThrow("does not fit");
		await expect(
			run({ action: "build", framing, payloads: [{ payload_hex: "", header_hex: "00" }] }),
		).rejects.toThrow("header_bytes");
		await expect(run({ action: "build", framing, payloads: [{ payload_hex: "" }] }, session(false))).rejects.toThrow(
			"artifact storage",
		);
		expect(() =>
			reassembleProtocolMessages([{ data_hex: "ff".repeat(1024 * 1024) }, { data_hex: "00" }], framing),
		).toThrow("total input bytes");
	});
});

describe("protocol_sequence explicit state validation", () => {
	it("validates ordered request/response types with direction guards and independent sessions", async () => {
		const result = await run({
			action: "validate",
			model,
			messages: [
				{ session_id: "A", direction: "out", message_type: "1" },
				{ session_id: "B", direction: "out", message_type: "1" },
				{ session_id: "B", direction: "in", message_type: "2" },
				{ session_id: "A", direction: "in", message_type: "2" },
			],
		});
		expect(result.details.validation?.valid).toBe(true);
		expect(result.details.validation?.sessions.map(item => [item.session_id, item.final_state, item.valid])).toEqual([
			["A", "done", true],
			["B", "done", true],
		]);
	});

	it("invalid messages keep state, wrong directions fail, incomplete terminal states fail", async () => {
		const result = await run({
			action: "validate",
			model,
			messages: [
				{ direction: "in", message_type: "2" },
				{ direction: "in", message_type: "1" },
				{ direction: "out", message_type: "1" },
			],
		});
		expect(result.details.status).toBe("invalid");
		expect(result.details.validation?.trace.map(item => [item.valid, item.state_before, item.state_after])).toEqual([
			[false, "idle", "idle"],
			[false, "idle", "idle"],
			[true, "idle", "waiting"],
		]);
		expect(result.details.validation?.sessions[0]!.valid).toBe(false);
	});

	it("reset boundaries create independent instances and do not hide a failed previous instance", async () => {
		const result = await run({
			action: "validate",
			model,
			messages: [
				{ message_type: "1", direction: "out" },
				{ reset: true },
				{ message_type: "1", direction: "out" },
				{ message_type: "2", direction: "in" },
			],
		});
		expect(result.details.validation?.sessions.map(item => [item.session_instance, item.valid])).toEqual([
			[0, false],
			[1, true],
		]);
		expect(result.details.validation?.valid).toBe(false);
	});

	it("validates reassembled types, restores original session names, and includes framing failures", async () => {
		const result = await run({
			action: "validate",
			framing,
			model,
			chunks: [
				{ session_id: "A", direction: "out", data_hex: "000001" },
				{ session_id: "A", direction: "in", data_hex: "000002" },
				{ session_id: "A", reset: true, direction: "out", data_hex: "000001" },
				{ session_id: "A", direction: "in", data_hex: "000002" },
				{ session_id: "broken", data_hex: "00" },
			],
		});
		expect(
			result.details.validation?.trace.map(item => [item.session_id, item.session_instance, item.message_index]),
		).toEqual([
			["A", 0, 0],
			["A", 0, 1],
			["A", 1, 2],
			["A", 1, 3],
		]);
		expect(
			result.details.validation?.sessions.map(item => [item.session_id, item.session_instance, item.valid]),
		).toEqual([
			["A", 0, true],
			["A", 1, true],
			["broken", 0, false],
		]);
		expect(result.details.status).toBe("invalid");
	});

	it("rejects ambiguous models rather than inventing rule precedence", async () => {
		await expect(
			run({
				action: "validate",
				messages: [{ message_type: "1" }],
				model: {
					initial_state: "idle",
					transitions: [
						{ from: "idle", message_type: "1", to: "A" },
						{ from: "idle", message_type: "1", direction: "out", to: "B" },
					],
				},
			}),
		).rejects.toThrow("ambiguous");
		await expect(run({ action: "validate", messages: [{}], model })).rejects.toThrow("reset markers");
	});
});

describe("protocol_sequence boundary", () => {
	it("loads local ordered chunk JSON and rejects URL, symlink and malformed schema inputs", async () => {
		await fs.writeFile(path.join(root, "chunks.json"), JSON.stringify([{ data_hex: "00010161" }]));
		const result = await run({ action: "reassemble", framing, chunks_path: "chunks.json" });
		expect(result.details.frames[0]!.payload_bytes).toBe(1);
		await expect(
			run({ action: "reassemble", framing, chunks_path: "https://example.invalid/chunks" }),
		).rejects.toThrow("local");
		await fs.symlink(path.join(root, "chunks.json"), path.join(root, "chunks-link.json"));
		await expect(run({ action: "reassemble", framing, chunks_path: "chunks-link.json" })).rejects.toThrow(
			"symbolic link",
		);
		await fs.writeFile(path.join(root, "bad.json"), JSON.stringify([{ data_hex: 42 }]));
		await expect(run({ action: "reassemble", framing, chunks_path: "bad.json" })).rejects.toThrow("schema");
	});

	it("public schema preserves nested inputs and rejects unsupported integer formats", () => {
		const tool = new ProtocolSequenceTool(session());
		const args = {
			action: "reassemble",
			framing,
			chunks: [{ data_hex: "000001", session_id: "A", direction: "out", reset: true }],
		};
		const validated = validateToolArguments(tool, {
			type: "toolCall",
			id: "schema",
			name: tool.name,
			arguments: args,
		});
		const parsed = tool.parameters(validated);
		expect(parsed instanceof type.errors).toBe(false);
		if (!(parsed instanceof type.errors))
			expect(parsed.chunks?.[0]).toEqual({ data_hex: "000001", session_id: "A", direction: "out", reset: true });
		expect(
			tool.parameters({
				action: "reassemble",
				framing: { ...framing, length_field: { offset: 0, type: "u8be" } },
			}) instanceof type.errors,
		).toBe(true);
	});

	it("bounds both structured and rendered results, retains failure status and accounts for omissions", async () => {
		const result = await run({
			action: "reassemble",
			framing,
			max_output_bytes: 1024,
			chunks: [{ data_hex: `${"000001".repeat(100)}ff` }],
		});
		expect(result.details.truncated).toBe(true);
		expect(result.details.status).toBe("invalid");
		expect(result.details.frames.length + result.details.omitted.frames).toBe(100);
		expect(Buffer.byteLength(JSON.stringify(result.details))).toBeLessThanOrEqual(1024);
		expect(Buffer.byteLength(result.content[0]!.type === "text" ? result.content[0]!.text : "")).toBeLessThanOrEqual(
			1024,
		);
	});

	it("caps frame counts with honest remaining-byte provenance and bounds input item counts", async () => {
		const result = await run({ action: "reassemble", framing, chunks: [{ data_hex: "000001".repeat(4097) }] });
		expect(result.details.status).toBe("invalid");
		expect(result.details.frames.length + result.details.omitted.frames).toBe(4096);
		expect(result.details.issues[0]?.kind).toBe("message_limit");
		expect(result.details.issues[0]?.remaining_bytes).toBe(3);
		await expect(
			run({ action: "reassemble", framing, chunks: Array.from({ length: 4097 }, () => ({ data_hex: "" })) }),
		).rejects.toThrow("4096");
	});

	it("requires central per-call approval for restricted chunks paths, including parent-directory symlinks", async () => {
		const restricted = path.join(root, "restricted");
		await fs.mkdir(restricted);
		await fs.writeFile(path.join(restricted, "chunks.json"), "[]");
		await fs.symlink(restricted, path.join(root, "restricted-link"));
		const tool = new ProtocolSequenceTool(session());
		for (const chunks_path of ["restricted/chunks.json", "restricted-link/chunks.json"]) {
			expect(
				resolveApproval(tool, { chunks_path }, "yolo", {}, undefined, {
					restrictedFolders: [restricted],
					cwd: root,
				}),
			).toMatchObject({ policy: "prompt", source: "restriction" });
		}
		expect(
			resolveApproval(tool, { chunks_path: "chunks.json" }, "yolo", {}, undefined, {
				restrictedFolders: [restricted],
				cwd: root,
			}).policy,
		).toBe("allow");
	});

	it("an explicit empty terminal state list rejects every completed session", async () => {
		const result = await run({
			action: "validate",
			model: { ...model, terminal_states: [] },
			messages: [
				{ message_type: "1", direction: "out" },
				{ message_type: "2", direction: "in" },
			],
		});
		expect(result.details.validation?.trace.every(step => step.valid)).toBe(true);
		expect(result.details.validation?.valid).toBe(false);
		expect(result.details.validation?.sessions[0]!.valid).toBe(false);
	});

	it("honors cancellation and rejects conflicting action inputs", async () => {
		const tool = new ProtocolSequenceTool(session());
		const controller = new AbortController();
		controller.abort();
		await expect(
			tool.execute("test", { action: "reassemble", framing, chunks: [{ data_hex: "" }] }, controller.signal),
		).rejects.toThrow();
		await expect(
			run({ action: "reassemble", framing, chunks: [{ data_hex: "" }], chunks_path: "chunks.json" }),
		).rejects.toThrow("not both");
		await expect(
			run({ action: "validate", framing, chunks: [{ data_hex: "" }], messages: [{ reset: true }], model }),
		).rejects.toThrow("not both");
	});
});

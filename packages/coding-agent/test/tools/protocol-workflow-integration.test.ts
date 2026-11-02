import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { removeWithRetries } from "@reverse/utils";
import { Settings } from "../../src/config/settings";
import { EvidenceStore } from "../../src/evidence/store";
import { evaluateEvidenceSupport } from "../../src/evidence/validity";
import { resolveCapa, resolveKaitaiToolchainReadiness } from "../../src/extensibility/protocol-toolchain";
import { ReverseWorkflowStore } from "../../src/reverse-workflow";
import { advanceWorkflow } from "../../src/reverse-workflow/progression";
import { hashBuffer } from "../../src/reverse-workspace";
import {
	AppExperimentTool,
	CapabilityInspectTool,
	FormatInspectTool,
	ReverseWorkflowTool,
	ReverseWorkspaceTool,
	type ToolSession,
} from "../../src/tools";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

async function withNoAmbientHttpProxy<T>(fn: () => Promise<T>): Promise<T> {
	const proxyKeys = [
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"ALL_PROXY",
		"http_proxy",
		"https_proxy",
		"all_proxy",
		"NO_PROXY",
		"no_proxy",
	];
	const saved = new Map<string, string | undefined>();
	for (const k of proxyKeys) {
		saved.set(k, process.env[k]);
		delete process.env[k];
	}
	process.env.NO_PROXY = "127.0.0.1,localhost";
	process.env.no_proxy = "127.0.0.1,localhost";
	try {
		return await fn();
	} finally {
		for (const [k, v] of saved.entries()) {
			if (v === undefined) delete process.env[k];
			else process.env[k] = v;
		}
	}
}

function assertRealProtocolEnginesOrActionableBlocker(): void {
	const kaitai = resolveKaitaiToolchainReadiness();
	if (!kaitai.ready) {
		throw new Error(
			`Protocol integration test requires real kaitai-struct-compiler + Python kaitaistruct runtime: ${kaitai.incompatibilityReason ?? kaitai.compiler.error ?? kaitai.runtime.error ?? "not ready"}. Install via: ${kaitai.setupCommands.join(" && ")}`,
		);
	}
	const capa = resolveCapa();
	if (!capa.available || !capa.path) {
		throw new Error(
			`Protocol integration test requires real capa CLI executable: ${capa.error ?? "capa not found"}. Install via: pip install flare-capa`,
		);
	}
}

function buildRvp1Frame(options: {
	version: number;
	opcode: number;
	seqNum: number;
	payload: Buffer;
	checksum: number;
}): Buffer {
	const header = Buffer.alloc(11);
	header.write("RVP1", 0, "ascii");
	header.writeUInt8(options.version & 0xff, 4);
	header.writeUInt16BE(options.opcode & 0xffff, 5);
	header.writeUInt16LE(options.seqNum & 0xffff, 7);
	header.writeUInt16BE(options.payload.byteLength & 0xffff, 9);
	const trailer = Buffer.alloc(2);
	trailer.writeUInt16BE(options.checksum & 0xffff, 0);
	return Buffer.concat([header, options.payload, trailer]);
}

const RVP1_FRAME_KSY = [
	"meta:",
	"  id: rvp1_frame",
	"  endian: be",
	"seq:",
	"  - id: magic",
	"    contents: [0x52, 0x56, 0x50, 0x31]",
	"  - id: version",
	"    type: u1",
	"  - id: opcode",
	"    type: u2",
	"  - id: seq_num",
	"    type: u2le",
	"  - id: payload_len",
	"    type: u2",
	"  - id: payload",
	"    size: payload_len",
	"  - id: checksum",
	"    type: u2",
	"",
].join("\n");

/**
 * Generates a valid synthetic x86_64 ELF executable (8192 bytes) with:
 * - function at VA 0x401000 (file offset 0x1000)
 * - protocol marker string "RVP1_FRAME_PARSER_V2" at file offset 0x1040 (decimal 4160, VA 0x401040)
 */
function buildSyntheticProtocolClientElf64(): Buffer {
	const buf = Buffer.alloc(8192, 0);

	// ELF64 header (64 bytes at 0x0)
	buf.writeUInt8(0x7f, 0);
	buf.write("ELF", 1, "ascii");
	buf.writeUInt8(2, 4); // EI_CLASS = ELFCLASS64
	buf.writeUInt8(1, 5); // EI_DATA = ELFDATA2LSB
	buf.writeUInt8(1, 6); // EI_VERSION = EV_CURRENT
	buf.writeUInt16LE(2, 16); // e_type = ET_EXEC
	buf.writeUInt16LE(62, 18); // e_machine = EM_X86_64
	buf.writeUInt32LE(1, 20); // e_version = 1
	buf.writeBigUInt64LE(0x401000n, 24); // e_entry = 0x401000
	buf.writeBigUInt64LE(64n, 32); // e_phoff = 64
	buf.writeBigUInt64LE(0x1800n, 40); // e_shoff = 0x1800
	buf.writeUInt32LE(0, 48); // e_flags
	buf.writeUInt16LE(64, 52); // e_ehsize = 64
	buf.writeUInt16LE(56, 54); // e_phentsize = 56
	buf.writeUInt16LE(1, 56); // e_phnum = 1
	buf.writeUInt16LE(64, 58); // e_shentsize = 64
	buf.writeUInt16LE(4, 60); // e_shnum = 4
	buf.writeUInt16LE(3, 62); // e_shstrndx = 3

	// Program Header 0 at offset 64: PT_LOAD mapping 0x0..0x2000 at VA 0x400000 (PF_R | PF_X)
	const phOff = 64;
	buf.writeUInt32LE(1, phOff + 0); // p_type = PT_LOAD
	buf.writeUInt32LE(5, phOff + 4); // p_flags = PF_R | PF_X
	buf.writeBigUInt64LE(0n, phOff + 8); // p_offset
	buf.writeBigUInt64LE(0x400000n, phOff + 16); // p_vaddr
	buf.writeBigUInt64LE(0x400000n, phOff + 24); // p_paddr
	buf.writeBigUInt64LE(0x2000n, phOff + 32); // p_filesz
	buf.writeBigUInt64LE(0x2000n, phOff + 40); // p_memsz
	buf.writeBigUInt64LE(0x1000n, phOff + 48); // p_align

	// Function at file offset 0x1000 (VA 0x401000)
	const codeBytes = Buffer.from([
		0x55, // push rbp
		0x48,
		0x89,
		0xe5, // mov rbp, rsp
		0xb8,
		0x31,
		0x50,
		0x56,
		0x52, // mov eax, 0x52565031 ("RVP1")
		0x35,
		0xde,
		0xc0,
		0x37,
		0x13, // xor eax, 0x1337c0de
		0x5d, // pop rbp
		0xc3, // ret
	]);
	codeBytes.copy(buf, 0x1000);

	// Protocol marker string at file offset 0x1040 (decimal 4160, VA 0x401040)
	buf.write("RVP1_FRAME_PARSER_V2\0", 0x1040, "ascii");

	// .shstrtab at offset 0x1700
	const shstrtab = Buffer.from("\0.text\0.rodata\0.shstrtab\0", "ascii");
	shstrtab.copy(buf, 0x1700);

	const writeShdr = (
		index: number,
		shName: number,
		shType: number,
		shFlags: bigint,
		shAddr: bigint,
		shOffset: bigint,
		shSize: bigint,
	) => {
		const base = 0x1800 + index * 64;
		buf.writeUInt32LE(shName, base + 0);
		buf.writeUInt32LE(shType, base + 4);
		buf.writeBigUInt64LE(shFlags, base + 8);
		buf.writeBigUInt64LE(shAddr, base + 16);
		buf.writeBigUInt64LE(shOffset, base + 24);
		buf.writeBigUInt64LE(shSize, base + 32);
		buf.writeUInt32LE(0, base + 40);
		buf.writeUInt32LE(0, base + 44);
		buf.writeBigUInt64LE(16n, base + 48);
		buf.writeBigUInt64LE(0n, base + 56);
	};

	writeShdr(0, 0, 0, 0n, 0n, 0n, 0n);
	writeShdr(1, 1, 1, 6n, 0x401000n, 0x1000n, 0x30n); // .text
	writeShdr(2, 7, 1, 2n, 0x401040n, 0x1040n, 0x40n); // .rodata
	writeShdr(3, 15, 3, 0n, 0n, 0x1700n, BigInt(shstrtab.length)); // .shstrtab

	return buf;
}

const RVP1_CAPA_RULE_YML = [
	"rule:",
	"  meta:",
	"    name: rvp1 protocol frame marker",
	"    namespace: communication/http/protocol",
	"    authors:",
	"      - reverse-integration-test",
	"    scopes:",
	"      static: file",
	"      dynamic: file",
	"  features:",
	"    - and:",
	'      - string: "RVP1_FRAME_PARSER_V2"',
	"      - format: elf",
	"",
].join("\n");

describe("protocol-workflow-integration Step 6 (end-to-end HAR import -> replay diff -> Kaitai parse -> capa locate -> record/recall)", () => {
	it("executes a single logical run from begin through HAR binary import, localhost replay diff, Kaitai compile/parse, capa ELF location, evidence gate enforcement, record, and new-session recall", async () => {
		assertRealProtocolEnginesOrActionableBlocker();

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "proto-wf-integration-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		const evStore = new EvidenceStore({ repositoryRoot: tempDir });
		const session1 = createTestSession(tempDir);

		const reqFrame = buildRvp1Frame({
			version: 1,
			opcode: 0x0101,
			seqNum: 7,
			payload: Buffer.from([0xca, 0xfe, 0xba, 0xbe]),
			checksum: 0x1111,
		});
		const recordedRespFrame = buildRvp1Frame({
			version: 1,
			opcode: 0x0201,
			seqNum: 7,
			payload: Buffer.from("ACK_07", "ascii"),
			checksum: 0x1337,
		});
		const liveBaselineRespFrame = buildRvp1Frame({
			version: 1,
			opcode: 0x0201,
			seqNum: 8,
			payload: Buffer.from("LIVE08", "ascii"),
			checksum: 0x1337,
		});
		const unauthRespFrame = buildRvp1Frame({
			version: 1,
			opcode: 0x02ff,
			seqNum: 0,
			payload: Buffer.from("DENY", "ascii"),
			checksum: 0xffff,
		});

		const receivedRequests: Array<{
			method: string;
			pathname: string;
			auth: string | null;
			seedSeq: string | null;
			body: Buffer;
		}> = [];

		const server = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			async fetch(req) {
				const url = new URL(req.url);
				const body = Buffer.from(await req.arrayBuffer());
				const auth = req.headers.get("authorization");
				const seedSeq = req.headers.get("x-seed-seq");
				receivedRequests.push({
					method: req.method,
					pathname: url.pathname,
					auth,
					seedSeq,
					body,
				});

				if (auth !== "Bearer proto_live_token_99") {
					return new Response(new Uint8Array(unauthRespFrame), {
						status: 401,
						headers: {
							"Content-Type": "application/octet-stream",
							"X-Frame-Mode": "binary-v1",
						},
					});
				}

				const outFrame = seedSeq === "7" ? recordedRespFrame : liveBaselineRespFrame;
				return new Response(new Uint8Array(outFrame), {
					status: 200,
					headers: {
						"Content-Type": "application/octet-stream",
						"X-Frame-Mode": "binary-v1",
					},
				});
			},
		});

		const serverOrigin = `http://127.0.0.1:${server.port}`;
		process.env.TEST_PROTO_WORKFLOW_AUTH = "Bearer proto_live_token_99";

		try {
			await withNoAmbientHttpProxy(async () => {
				const samplesDir = path.join(tempDir, "samples");
				const capturesDir = path.join(tempDir, "captures");
				const schemasDir = path.join(tempDir, "schemas");
				const rulesDir = path.join(tempDir, "rules");
				await fs.mkdir(samplesDir, { recursive: true });
				await fs.mkdir(capturesDir, { recursive: true });
				await fs.mkdir(schemasDir, { recursive: true });
				await fs.mkdir(rulesDir, { recursive: true });

				// 1. Write synthetic ELF target, local HAR capture (complete + truncated entry), KSY schema, and capa rule
				const elfBuffer = buildSyntheticProtocolClientElf64();
				const targetElfRel = "samples/protocol_client.elf";
				const targetElfAbs = path.join(tempDir, targetElfRel);
				await fs.writeFile(targetElfAbs, elfBuffer);
				const targetSha256 = hashBuffer(elfBuffer).sha256;

				const harRel = "captures/protocol_exchange.har";
				const harAbs = path.join(tempDir, harRel);
				const truncatedRespSlice = recordedRespFrame.subarray(0, 8);
				const harDoc = {
					log: {
						version: "1.2",
						creator: { name: "reverse-protocol-integration-test", version: "1.0" },
						entries: [
							{
								_id: "har_rvp1_complete",
								startedDateTime: "2026-10-30T12:00:00.000Z",
								time: 5,
								request: {
									method: "POST",
									url: `${serverOrigin}/v1/frame`,
									httpVersion: "HTTP/1.1",
									headers: [
										{ name: "Host", value: `127.0.0.1:${server.port}` },
										{ name: "Content-Type", value: "application/octet-stream" },
										{ name: "X-Client-Marker", value: "RVP1_FRAME_PARSER_V2" },
										{ name: "Authorization", value: "Bearer captured_har_token_old" },
									],
									queryString: [],
									cookies: [],
									headersSize: -1,
									bodySize: reqFrame.byteLength,
									postData: {
										mimeType: "application/octet-stream",
										encoding: "base64",
										_rawBytes: true,
										text: reqFrame.toString("base64"),
									},
								},
								response: {
									status: 200,
									statusText: "OK",
									httpVersion: "HTTP/1.1",
									headers: [
										{ name: "Content-Type", value: "application/octet-stream" },
										{ name: "X-Frame-Mode", value: "binary-v1" },
										{ name: "Content-Length", value: String(recordedRespFrame.byteLength) },
									],
									cookies: [],
									content: {
										size: recordedRespFrame.byteLength,
										mimeType: "application/octet-stream",
										encoding: "base64",
										_rawBytes: true,
										text: recordedRespFrame.toString("base64"),
									},
									redirectURL: "",
									headersSize: -1,
									bodySize: recordedRespFrame.byteLength,
								},
								cache: {},
								timings: { send: 1, wait: 3, receive: 1 },
							},
							{
								_id: "har_rvp1_truncated",
								startedDateTime: "2026-10-30T12:00:01.000Z",
								time: 4,
								request: {
									method: "POST",
									url: `${serverOrigin}/v1/frame`,
									httpVersion: "HTTP/1.1",
									headers: [
										{ name: "Host", value: `127.0.0.1:${server.port}` },
										{ name: "Content-Type", value: "application/octet-stream" },
										{ name: "Authorization", value: "Bearer captured_har_token_old" },
									],
									queryString: [],
									cookies: [],
									headersSize: -1,
									bodySize: reqFrame.byteLength,
									postData: {
										mimeType: "application/octet-stream",
										encoding: "base64",
										_rawBytes: true,
										text: reqFrame.toString("base64"),
									},
								},
								response: {
									status: 200,
									statusText: "OK",
									httpVersion: "HTTP/1.1",
									headers: [
										{ name: "Content-Type", value: "application/octet-stream" },
										{ name: "X-Frame-Mode", value: "binary-v1" },
										{ name: "Content-Length", value: String(recordedRespFrame.byteLength) },
									],
									cookies: [],
									content: {
										size: recordedRespFrame.byteLength,
										mimeType: "application/octet-stream",
										encoding: "base64",
										_rawBytes: true,
										text: truncatedRespSlice.toString("base64"),
									},
									redirectURL: "",
									headersSize: -1,
									bodySize: recordedRespFrame.byteLength,
								},
								cache: {},
								timings: { send: 1, wait: 2, receive: 1 },
							},
						],
					},
				};
				const harRawBuf = Buffer.from(JSON.stringify(harDoc, null, 2), "utf8");
				await fs.writeFile(harAbs, harRawBuf);
				const harSha256 = hashBuffer(harRawBuf).sha256;

				const ksyRel = "schemas/rvp1_frame.ksy";
				const ksyAbs = path.join(tempDir, ksyRel);
				const ksyBuf = Buffer.from(RVP1_FRAME_KSY, "utf8");
				await fs.writeFile(ksyAbs, ksyBuf);
				const ksySha256 = hashBuffer(ksyBuf).sha256;

				const ruleRel = "rules/protocol_frame_rule.yml";
				const ruleAbs = path.join(tempDir, ruleRel);
				const ruleBuf = Buffer.from(RVP1_CAPA_RULE_YML, "utf8");
				await fs.writeFile(ruleAbs, ruleBuf);
				const ruleSha256 = hashBuffer(ruleBuf).sha256;

				// 2. Create workflow targeting the native ELF sample and begin a single logical analysis run
				const wfTool1 = new ReverseWorkflowTool(session1);
				const wsTool1 = new ReverseWorkspaceTool(session1);
				const appTool1 = new AppExperimentTool(session1);
				const fmtTool1 = new FormatInspectTool(session1);
				const capTool1 = new CapabilityInspectTool(session1);

				const wfRes = await wfTool1.execute("wf-create", {
					action: "create",
					target: targetElfAbs,
					format: "ELF",
					goal: "Verify RVP1 binary protocol exchange, Kaitai frame format, and native client capability marker",
				});
				const workflow = wfRes.details.workflow!;
				expect(workflow.target_sha256).toBe(targetSha256);
				const workflowId = workflow.id;
				const stepId = workflow.steps[0]!.id;

				const beginRes = await wsTool1.execute("ws-begin", {
					action: "begin",
					workflow_id: workflowId,
					step_id: stepId,
					purpose:
						"Import HAR binary frame, replay against localhost, parse with Kaitai, and locate marker via capa",
					command: "app_experiment + format_inspect + capability_inspect",
					inputs: [targetElfRel, harRel, ksyRel, ruleRel],
				});
				expect(beginRes.details.action).toBe("begin");
				const runId = beginRes.details.run_id!;
				const runPaths = beginRes.details.paths!;
				expect(beginRes.details.run?.status).toBe("running");

				const declaredInputMap = new Map(beginRes.details.run!.inputs.map(i => [i.path, i.sha256]));
				expect(declaredInputMap.get(targetElfRel)).toBe(targetSha256);
				expect(declaredInputMap.get(harRel)).toBe(harSha256);
				expect(declaredInputMap.get(ksyRel)).toBe(ksySha256);
				expect(declaredInputMap.get(ruleRel)).toBe(ruleSha256);

				// 3. Step A: Import complete binary HTTP exchange (entry_index: 0) from local HAR
				const importRes = await appTool1.execute("net-import-complete", {
					action: "network_import",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					capture_path: harRel,
					capture_format: "har",
					entry_index: 0,
				});
				expect(importRes.details.status).toBe("ok");
				expect(importRes.details.replayCase?.replay_ready).toBe(true);
				expect(importRes.details.replayCase?.request.body.completeness).toBe("complete");
				expect(importRes.details.replayCase?.request.body.representation).toBe("captured_raw_bytes");
				expect(importRes.details.replayCase?.request.body.sha256).toBe(hashBuffer(reqFrame).sha256);
				expect(importRes.details.replayCase?.recorded_response.body.completeness).toBe("complete");
				expect(importRes.details.replayCase?.recorded_response.body.representation).toBe("captured_raw_bytes");
				expect(importRes.details.replayCase?.recorded_response.body.sha256).toBe(
					hashBuffer(recordedRespFrame).sha256,
				);

				const importedCaseRel = importRes.details.caseRelativePath!;
				const importedReqBodyRel = importRes.details.requestBodyRelativePath!;
				const importedRespBodyRel = importRes.details.responseBodyRelativePath!;
				expect(importedCaseRel.startsWith(runPaths.relative.dumps_dir)).toBe(true);
				expect(importedReqBodyRel.startsWith(runPaths.relative.dumps_dir)).toBe(true);
				expect(importedRespBodyRel.startsWith(runPaths.relative.dumps_dir)).toBe(true);

				// 4. Step B: Replay imported case against localhost server and verify response diffs
				const replayRes = await appTool1.execute("net-replay-complete", {
					action: "network_replay",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					case_file: importedCaseRel,
					allowed_origins: [serverOrigin],
					header_env_map: { Authorization: "TEST_PROTO_WORKFLOW_AUTH" },
					compare_headers: ["Content-Type", "X-Frame-Mode"],
					variant_requests: [
						{
							id: "echo_recorded_seq",
							name: "Request echoing recorded sequence 7",
							headers: { "X-Seed-Seq": "7" },
							auth_header_env: "TEST_PROTO_WORKFLOW_AUTH",
						},
						{
							id: "unauth_probe",
							name: "Unauthenticated binary probe",
						},
					],
				});
				expect(replayRes.details.status).toBe("ok");
				expect(receivedRequests.length).toBe(3);
				expect(Buffer.compare(receivedRequests[0]!.body, reqFrame)).toBe(0);

				// Baseline vs recorded: status 200 matches, selected headers match, binary body differs (seq 7 vs seq 8)
				const baseVsRec = replayRes.details.baselineVsRecorded!;
				expect(baseVsRec.available).toBe(true);
				expect(baseVsRec.status_equal).toBe(true);
				expect(baseVsRec.selected_headers_equal).toBe(true);
				expect(baseVsRec.raw_equal).toBe(false);
				expect(baseVsRec.normalized_equal).toBe("not_applicable");
				expect(baseVsRec.length_delta).toBe(0);

				const baselineBodyRel = replayRes.details.baselineResult!.relativeArtifactPath!;
				expect(baselineBodyRel.startsWith(runPaths.relative.dumps_dir)).toBe(true);
				expect(replayRes.details.baselineResult?.bodySha256).toBe(hashBuffer(liveBaselineRespFrame).sha256);

				// Variant 0 (echo_recorded_seq): differs from baseline (seq 8) and matches recorded response (seq 7)
				const varEcho = replayRes.details.variantResults![0]!;
				expect(varEcho.id).toBe("echo_recorded_seq");
				expect(varEcho.status).toBe(200);
				expect(varEcho.diffAgainstBaseline.raw_equal).toBe(false);
				expect(varEcho.diffAgainstRecorded?.raw_equal).toBe(true);

				// Variant 1 (unauth_probe): HTTP 401 binary error response
				const varUnauth = replayRes.details.variantResults![1]!;
				expect(varUnauth.id).toBe("unauth_probe");
				expect(varUnauth.status).toBe(401);
				expect(varUnauth.diffAgainstBaseline.statusMatch).toBe(false);
				expect(varUnauth.diffAgainstBaseline.statusDelta).toBe("200 -> 401");
				expect(varUnauth.diffAgainstBaseline.lengthDelta).toBe(
					unauthRespFrame.byteLength - liveBaselineRespFrame.byteLength,
				);

				// 5. Step C: Compile KSY schema and parse both extracted recorded and live response bodies
				const compileRes = await fmtTool1.execute("fmt-compile", {
					action: "compile",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					schema_path: ksyRel,
				});
				expect(compileRes.details.status).toBe("ok");
				expect(compileRes.details.manifest?.compiler.read_pos_enabled).toBe(true);
				const manifestRel = compileRes.details.manifestRelativePath!;

				const parseRecordedRes = await fmtTool1.execute("fmt-parse-recorded", {
					action: "parse",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					manifest_path: manifestRel,
					sample_path: importedRespBodyRel,
				});
				expect(parseRecordedRes.details.status).toBe("ok");
				expect(parseRecordedRes.details.parseResult?.ok).toBe(true);
				expect(parseRecordedRes.details.parseResult?.sample_size).toBe(19);
				expect(parseRecordedRes.details.parseResult?.consumed_bytes).toBe(19);
				expect(parseRecordedRes.details.parseResult?.trailing_bytes).toBe(0);

				const recFields = new Map(parseRecordedRes.details.parseResult!.fields.map(f => [f.path, f]));
				expect(recFields.get("magic")).toMatchObject({
					type: "bytes",
					value: "52565031",
					start: 0,
					end: 4,
					file_start: 0,
					file_end: 4,
				});
				expect(recFields.get("version")).toMatchObject({ type: "int", value: 1, start: 4, end: 5 });
				expect(recFields.get("opcode")).toMatchObject({ type: "int", value: 0x0201, start: 5, end: 7 });
				expect(recFields.get("seq_num")).toMatchObject({ type: "int", value: 7, start: 7, end: 9 });
				expect(recFields.get("payload_len")).toMatchObject({ type: "int", value: 6, start: 9, end: 11 });
				expect(recFields.get("payload")).toMatchObject({
					type: "bytes",
					value: Buffer.from("ACK_07", "ascii").toString("hex"),
					start: 11,
					end: 17,
				});
				expect(recFields.get("checksum")).toMatchObject({ type: "int", value: 0x1337, start: 17, end: 19 });

				const parseLiveRes = await fmtTool1.execute("fmt-parse-live", {
					action: "parse",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					manifest_path: manifestRel,
					sample_path: baselineBodyRel,
				});
				expect(parseLiveRes.details.status).toBe("ok");
				const liveFields = new Map(parseLiveRes.details.parseResult!.fields.map(f => [f.path, f]));
				expect(liveFields.get("seq_num")).toMatchObject({ type: "int", value: 8, start: 7, end: 9 });
				expect(liveFields.get("payload")).toMatchObject({
					type: "bytes",
					value: Buffer.from("LIVE08", "ascii").toString("hex"),
					start: 11,
					end: 17,
				});
				expect(liveFields.get("checksum")).toMatchObject({ type: "int", value: 0x1337, start: 17, end: 19 });

				// 6. Step D: Verify failure/unknown semantics on truncated captured response (entry_index: 1)
				const importTruncRes = await appTool1.execute("net-import-truncated", {
					action: "network_import",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					capture_path: harRel,
					capture_format: "har",
					entry_index: 1,
				});
				expect(importTruncRes.details.status).toBe("ok");
				expect(importTruncRes.details.replayCase?.recorded_response.body.completeness).toBe("truncated");
				expect(importTruncRes.details.replayCase?.recorded_response.body.size_bytes).toBe(8);
				expect(importTruncRes.details.replayCase?.recorded_response.body.declared_size_bytes).toBe(19);

				const replayTruncRes = await appTool1.execute("net-replay-truncated", {
					action: "network_replay",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					case_file: importTruncRes.details.caseRelativePath!,
					allowed_origins: [serverOrigin],
					header_env_map: { Authorization: "TEST_PROTO_WORKFLOW_AUTH" },
				});
				expect(replayTruncRes.details.status).toBe("ok");
				expect(replayTruncRes.details.baselineVsRecorded?.raw_equal).toBe("unknown");
				expect(replayTruncRes.details.baselineVsRecorded?.normalized_equal).toBe("unknown");
				expect(replayTruncRes.details.baselineVsRecorded?.comparison_reason).toContain(
					"incomplete_body (left=truncated, right=complete)",
				);

				const parseTruncRes = await fmtTool1.execute("fmt-parse-truncated", {
					action: "parse",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					manifest_path: manifestRel,
					sample_path: importTruncRes.details.responseBodyRelativePath!,
				});
				expect(parseTruncRes.details.status).toBe("error");
				expect(parseTruncRes.details.parseResult?.ok).toBe(false);
				expect(parseTruncRes.details.parseResult?.error_offset).toBe(8);
				expect(parseTruncRes.details.parseResult?.error_stream_pos).toBe(8);
				expect(parseTruncRes.details.parseResult?.error_field_path).toBe("seq_num");
				const partialFields = new Map(parseTruncRes.details.parseResult!.fields.map(f => [f.path, f]));
				expect(partialFields.get("magic")?.value).toBe("52565031");
				expect(partialFields.get("opcode")?.value).toBe(0x0201);
				expect(partialFields.has("seq_num")).toBe(false);

				// 7. Step E: Locate protocol marker in synthetic native ELF with project-local capa rule
				const capaRes = await capTool1.execute("cap-detect-elf", {
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: targetElfRel,
					rules_path: ruleRel,
					os: "linux",
				});
				expect(capaRes.details.status, capaRes.details.error).toBe("ok");
				expect(capaRes.details.exitCode).toBe(0);
				expect(capaRes.details.assuranceLevel).toBe("static_candidate");
				expect(capaRes.details.report?.sample.sha256).toBe(targetSha256);
				expect(capaRes.details.report?.rules_provenance).toMatchObject({
					source: "external_manifest",
					rules_kind: "single_file",
					rules_path: ruleRel,
					rule_count: 1,
					independent_content_hash_available: true,
					verified_unchanged_after_execution: true,
					bound_in_begin_inputs: true,
				});
				expect(capaRes.details.report?.matched_rule_count).toBe(1);

				const matchedRule = capaRes.details.report!.rules[0]!;
				expect(matchedRule.rule_name).toBe("rvp1 protocol frame marker");
				expect(matchedRule.namespace).toBe("communication/http/protocol");
				expect(matchedRule.primary_scope).toBe("file");
				expect(matchedRule.matches[0]?.address).toMatchObject({
					kind: "no_address",
					has_address: false,
					value: null,
					display: "no address",
				});
				expect(matchedRule.matches[0]?.tree).toMatchObject({
					node_kind: "statement",
					type: "and",
					success: true,
				});
				const markerLeaf = matchedRule.matches[0]!.leaf_features.find(lf => lf.type === "string");
				expect(markerLeaf).toBeDefined();
				expect(markerLeaf!.value).toBe("RVP1_FRAME_PARSER_V2");
				expect(markerLeaf!.locations[0]).toMatchObject({
					kind: "file_offset",
					decimal: "4160",
					hex: "0x1040",
					display: "file:0x1040",
				});

				// 8. Step F: Verify candidate assurance from all tools does not upgrade evidence or dynamic workflow gates
				const importCands = importRes.details.evidenceCandidates ?? [];
				const replayCands = replayRes.details.evidenceCandidates ?? [];
				const parseCands = parseLiveRes.details.evidenceCandidates ?? [];
				const capaCands = capaRes.details.evidenceCandidates ?? [];
				expect(importCands.length).toBeGreaterThan(0);
				expect(replayCands.length).toBeGreaterThan(0);
				expect(parseCands.length).toBeGreaterThan(0);
				expect(capaCands.length).toBeGreaterThan(0);

				for (const c of [...importCands, ...replayCands]) {
					expect(c.assurance).toBe("static_candidate");
				}
				for (const c of parseCands) {
					expect(c.assurance_level).toBe("static_candidate");
				}
				for (const c of capaCands) {
					expect(c.assurance_level).toBe("static_candidate");
					expect(c.can_satisfy_dynamic_call_gate).toBe(false);
				}

				const persistedFactIds: string[] = [];
				for (const c of [importCands[0]!, replayCands[0]!]) {
					const f = await evStore.addFact({
						kind: "fact",
						target: targetElfRel,
						subject: "rvp1_protocol_frame",
						sourceTool: c.sourceTool,
						locator: c.locator,
						content: c.content,
						context: {
							subject: "rvp1_protocol_frame",
							assurance: c.assurance,
							executionBinding: { artifactSha256: targetSha256 },
						},
					});
					persistedFactIds.push(f.id);
				}
				const parseFactCand = parseCands.find(c => c.kind === "fact")!;
				const addedParseFact = await evStore.addFact({
					kind: "fact",
					target: targetElfRel,
					subject: "rvp1_protocol_frame",
					sourceTool: "format_inspect",
					locator: `${parseFactCand.artifact_path}@0..19`,
					content: parseFactCand.statement,
					context: {
						subject: "rvp1_protocol_frame",
						assurance: parseFactCand.assurance_level,
						executionBinding: { artifactSha256: targetSha256 },
					},
				});
				persistedFactIds.push(addedParseFact.id);

				const capaFactCand = capaCands.find(c => c.kind === "fact")!;
				const capaHypCand = capaCands.find(c => c.kind === "hypothesis")!;
				const addedCapaFact = await evStore.addFact({
					kind: "fact",
					target: targetElfRel,
					subject: "rvp1_protocol_frame",
					sourceTool: "capability_inspect",
					locator: capaFactCand.leaf_locations[0]?.display ?? capaFactCand.artifact_path,
					content: capaFactCand.statement,
					context: {
						subject: "rvp1_protocol_frame",
						assurance: capaFactCand.assurance_level,
						executionBinding: { artifactSha256: targetSha256 },
					},
				});
				persistedFactIds.push(addedCapaFact.id);

				const addedHyp = await evStore.addHypothesis({
					kind: "hypothesis",
					title: "Client parses and exchanges RVP1 binary protocol frames",
					target: targetElfRel,
					subject: "rvp1_protocol_frame",
					claim: capaHypCand.claim ?? capaHypCand.statement,
					verificationPlan: capaHypCand.verification_plan ?? "Hook frame parser at runtime",
					facts: persistedFactIds,
					executionBinding: { artifactSha256: targetSha256 },
				});

				const dynSupportEval = await evaluateEvidenceSupport(await evStore.getAllRecords(), persistedFactIds, {
					requiredKinds: ["fact"],
					requiredSubject: "rvp1_protocol_frame",
					requiredTargetSha256: targetSha256,
					minAssurance: "dynamic_call_observation",
				});
				expect(dynSupportEval.valid).toBe(false);
				expect(dynSupportEval.highestAssurance).toBe("static_candidate");
				expect(dynSupportEval.reason).toMatch(/assurance|dynamic_call_observation/i);

				await expect(
					evStore.verifyHypothesis({
						hypothesisId: addedHyp.id,
						method: "HAR replay + Kaitai parse + capa detect",
						command: "app_experiment + format_inspect + capability_inspect",
						result: "Matched frame fields and file offset 0x1040",
						conclusion: "Attempt to escalate static candidates to dynamic call observation",
						status: "verified",
						assurance: "dynamic_call_observation",
					}),
				).rejects.toThrow(/assurance|dynamic_call_observation|insufficient/i);

				const staticConclusion = await evStore.verifyHypothesis({
					hypothesisId: addedHyp.id,
					method: "HAR replay + Kaitai parse + capa detect",
					command: "app_experiment + format_inspect + capability_inspect",
					result: "Matched frame fields and file offset 0x1040",
					conclusion: "Confirmed static candidate structure and marker location",
					status: "verified",
					assurance: "static_candidate",
				});
				expect(staticConclusion.context?.assurance).toBe("static_candidate");

				const dynGateWf = await wfStore.create({
					id: "wf_proto_dyn_gate_check",
					target: targetElfAbs,
					format: "ELF",
					goal: "Dynamic runtime verification gate check",
					steps: [
						{
							id: "step_frida_hook",
							title: "Frida runtime frame hook",
							tool: "frida",
							gate: "G2",
							params_summary: { action: "spawn" },
							status: "pending",
							attempts: 0,
							max_attempts: 3,
							created_at: new Date().toISOString(),
							updated_at: new Date().toISOString(),
						},
					],
				});
				const gateProgression = await advanceWorkflow(
					dynGateWf,
					{
						step_id: "step_frida_hook",
						status: "completed",
						evidence_ids: [...persistedFactIds, staticConclusion.id],
					},
					{ repositoryRoot: tempDir, evidenceStore: evStore },
				);
				expect(gateProgression.advanced).toBe(false);
				expect(gateProgression.status).toBe("held_pending_decision");
				expect(dynGateWf.steps[0]!.status).toBe("pending");

				// 9. Step G: Record all run scripts/outputs/evidence and verify recall from a fresh session instance
				const runScriptPaths = compileRes.details.manifest!.generated_sources.map(g => g.path);
				const allRunOutputs = Array.from(
					new Set([
						...(importRes.details.relativeOutputPaths ?? []),
						...(replayRes.details.relativeOutputPaths ?? []),
						...(compileRes.details.relativeOutputPaths ?? []),
						...(parseRecordedRes.details.relativeOutputPaths ?? []),
						...(parseLiveRes.details.relativeOutputPaths ?? []),
						...(importTruncRes.details.relativeOutputPaths ?? []),
						...(replayTruncRes.details.relativeOutputPaths ?? []),
						...(parseTruncRes.details.relativeOutputPaths ?? []),
						...(capaRes.details.relativeOutputPaths ?? []),
					]),
				);

				const recordRes = await wsTool1.execute("ws-record", {
					action: "record",
					workflow_id: workflowId,
					run_id: runId,
					exit_code: 0,
					summary:
						"Completed RVP1 HAR import, localhost binary replay diff, Kaitai frame parsing, and capa ELF marker detection",
					script_paths: runScriptPaths,
					output_paths: allRunOutputs,
					evidence_ids: [...persistedFactIds, addedHyp.id, staticConclusion.id],
				});
				expect(recordRes.details.action).toBe("record");
				const recordedRun = recordRes.details.run!;
				expect(recordedRun.status).toBe("succeeded");
				expect(recordedRun.exit_code).toBe(0);
				expect(recordedRun.inputs.length).toBe(4);
				expect(recordedRun.scripts.length).toBe(runScriptPaths.length);
				expect(recordedRun.outputs.length).toBe(allRunOutputs.length);

				for (const ref of [...recordedRun.inputs, ...recordedRun.scripts, ...recordedRun.outputs]) {
					expect(ref.sha256).toMatch(/^[0-9a-f]{64}$/);
					expect(ref.size_bytes).toBeGreaterThan(0);
				}

				const updatedWf = await wfStore.get(workflowId);
				const updatedStepRefs = new Set(updatedWf?.steps[0]?.artifact_refs ?? []);
				expect(updatedStepRefs.has(runPaths.relative.run_json)).toBe(true);
				for (const s of recordedRun.scripts) {
					expect(updatedStepRefs.has(s.path)).toBe(true);
				}
				for (const o of recordedRun.outputs) {
					expect(updatedStepRefs.has(o.path)).toBe(true);
				}

				// Instantiate a new session and new ReverseWorkspaceTool to verify cross-session recall
				const session2 = createTestSession(tempDir);
				const wsTool2 = new ReverseWorkspaceTool(session2);
				const recallRes = await wsTool2.execute("ws-recall-session2", {
					action: "recall",
					workflow_id: workflowId,
					target_hash: targetSha256,
					query: "Kaitai",
				});
				expect(recallRes.details.action).toBe("recall");
				expect(recallRes.details.recalled_runs?.length).toBe(1);

				const recalled = recallRes.details.recalled_runs![0]!;
				expect(recalled.reuse_status).toBe("available");
				expect(recalled.run.id).toBe(runId);
				expect(recalled.run.target_sha256).toBe(targetSha256);
				expect(recalled.run.inputs).toEqual(recordedRun.inputs);
				expect(recalled.run.scripts).toEqual(recordedRun.scripts);
				expect(recalled.run.outputs).toEqual(recordedRun.outputs);
				expect(recalled.reusable_script_paths).toEqual(runScriptPaths.map(rel => path.join(tempDir, rel)));
			});
		} finally {
			delete process.env.TEST_PROTO_WORKFLOW_AUTH;
			server.stop(true);
			await removeWithRetries(evStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	}, 90_000);
});

import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { removeWithRetries } from "@reverse/utils";
import { Settings } from "../../src/config/settings";
import { EvidenceStore } from "../../src/evidence/store";
import { ReverseWorkflowStore } from "../../src/reverse-workflow";
import { hashBuffer } from "../../src/reverse-workspace";
import { ReverseWorkflowTool, ReverseWorkspaceTool, type ToolSession } from "../../src/tools";
import { CapabilityInspectTool, capabilityInspectSchema } from "../../src/tools/capability-inspect";

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
						planFilePath: "local://capability-inspect-plan.md",
					}),
				}
			: {}),
	};
}

/**
 * 构造最小合法的 64 位 Linux ELF（ET_EXEC，EM_X86_64，EI_OSABI=ELFOSABI_LINUX）：
 * - 基址：0x400000，代码段文件偏移：0x1000，函数入口 VA：0x401000 (4198400)
 * - 指令序列：
 *   0x401000: 55                   push rbp
 *   0x401001: 48 89 e5             mov rbp, rsp
 *   0x401004: b8 78 56 34 12       mov eax, 0x12345678
 *   0x401009: 35 ef be ad de       xor eax, 0xdeadbeef
 *   0x40100e: 5d                   pop rbp
 *   0x40100f: c3                   ret
 * - 文件偏移 0x1040 (4160)：ASCII 字符串 "synth-capability-marker\0"
 */
function buildSyntheticLinuxElf64(): Buffer {
	const ehdrSize = 64;
	const phdrSize = 56;
	const codeOffset = 0x1000;
	const vaddrBase = 0x400000n;
	const entryVaddr = vaddrBase + BigInt(codeOffset);

	const code = Buffer.from([
		0x55, // push rbp
		0x48,
		0x89,
		0xe5, // mov rbp, rsp
		0xb8,
		0x78,
		0x56,
		0x34,
		0x12, // mov eax, 0x12345678
		0x35,
		0xef,
		0xbe,
		0xad,
		0xde, // xor eax, 0xdeadbeef
		0x5d, // pop rbp
		0xc3, // ret
	]);
	const paddedCode = Buffer.alloc(0x40, 0x90);
	code.copy(paddedCode, 0);
	const rodata = Buffer.from("synth-capability-marker\0", "ascii");
	const payload = Buffer.concat([paddedCode, rodata]);
	const fileSize = codeOffset + payload.byteLength;

	const buf = Buffer.alloc(fileSize, 0);
	// e_ident: \x7fELF, ELFCLASS64(2), ELFDATA2LSB(1), EV_CURRENT(1), ELFOSABI_LINUX(3)
	Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 3]).copy(buf, 0);
	buf.writeUInt16LE(2, 16); // e_type = ET_EXEC
	buf.writeUInt16LE(62, 18); // e_machine = EM_X86_64
	buf.writeUInt32LE(1, 20); // e_version = EV_CURRENT
	buf.writeBigUInt64LE(entryVaddr, 24); // e_entry
	buf.writeBigUInt64LE(BigInt(ehdrSize), 32); // e_phoff
	buf.writeBigUInt64LE(0n, 40); // e_shoff
	buf.writeUInt32LE(0, 48); // e_flags
	buf.writeUInt16LE(ehdrSize, 52); // e_ehsize
	buf.writeUInt16LE(phdrSize, 54); // e_phentsize
	buf.writeUInt16LE(1, 56); // e_phnum
	buf.writeUInt16LE(64, 58); // e_shentsize
	buf.writeUInt16LE(0, 60); // e_shnum
	buf.writeUInt16LE(0, 62); // e_shstrndx

	// Program Header (PT_LOAD) at offset 64
	const pOff = ehdrSize;
	buf.writeUInt32LE(1, pOff); // p_type = PT_LOAD
	buf.writeUInt32LE(5, pOff + 4); // p_flags = PF_R | PF_X
	buf.writeBigUInt64LE(0n, pOff + 8); // p_offset
	buf.writeBigUInt64LE(vaddrBase, pOff + 16); // p_vaddr
	buf.writeBigUInt64LE(vaddrBase, pOff + 24); // p_paddr
	buf.writeBigUInt64LE(BigInt(fileSize), pOff + 32); // p_filesz
	buf.writeBigUInt64LE(BigInt(fileSize), pOff + 40); // p_memsz
	buf.writeBigUInt64LE(0x1000n, pOff + 48); // p_align

	payload.copy(buf, codeOffset);
	return buf;
}

/**
 * 构造最小合法的 32 位 Windows PE（IMAGE_FILE_MACHINE_I386）：
 * - ImageBase：0x400000，.text RVA：0x1000，PointerToRawData：0x200，函数入口 VA：0x401000 (4198400)
 * - 指令序列：
 *   0x401000: 55                   push ebp
 *   0x401001: 89 e5                mov ebp, esp
 *   0x401003: b8 78 56 34 12       mov eax, 0x12345678
 *   0x401008: 35 ef be ad de       xor eax, 0xdeadbeef
 *   0x40100d: 5d                   pop ebp
 *   0x40100e: c3                   ret
 * - 文件偏移 0x240 (576)：ASCII 字符串 "synth-capability-marker\0"
 */
function buildSyntheticWindowsPe32(): Buffer {
	const buf = Buffer.alloc(0x400, 0);
	buf.write("MZ", 0, "ascii");
	buf.writeUInt32LE(0x80, 0x3c); // e_lfanew = 0x80

	const peOff = 0x80;
	buf.write("PE\0\0", peOff, "ascii");
	// COFF File Header
	buf.writeUInt16LE(0x014c, peOff + 4); // Machine = IMAGE_FILE_MACHINE_I386
	buf.writeUInt16LE(1, peOff + 6); // NumberOfSections = 1
	buf.writeUInt32LE(0, peOff + 8); // TimeDateStamp
	buf.writeUInt32LE(0, peOff + 12); // PointerToSymbolTable
	buf.writeUInt32LE(0, peOff + 16); // NumberOfSymbols
	buf.writeUInt16LE(0x00e0, peOff + 20); // SizeOfOptionalHeader
	buf.writeUInt16LE(0x0102, peOff + 22); // Characteristics (EXECUTABLE_IMAGE | 32BIT_MACHINE)

	const optOff = peOff + 24;
	buf.writeUInt16LE(0x010b, optOff); // Magic = PE32
	buf.writeUInt8(14, optOff + 2); // MajorLinkerVersion
	buf.writeUInt8(0, optOff + 3); // MinorLinkerVersion
	buf.writeUInt32LE(0x200, optOff + 4); // SizeOfCode
	buf.writeUInt32LE(0, optOff + 8); // SizeOfInitializedData
	buf.writeUInt32LE(0, optOff + 12); // SizeOfUninitializedData
	buf.writeUInt32LE(0x1000, optOff + 16); // AddressOfEntryPoint
	buf.writeUInt32LE(0x1000, optOff + 20); // BaseOfCode
	buf.writeUInt32LE(0x1000, optOff + 24); // BaseOfData
	buf.writeUInt32LE(0x00400000, optOff + 28); // ImageBase
	buf.writeUInt32LE(0x1000, optOff + 32); // SectionAlignment
	buf.writeUInt32LE(0x0200, optOff + 36); // FileAlignment
	buf.writeUInt16LE(6, optOff + 40); // MajorOperatingSystemVersion
	buf.writeUInt16LE(0, optOff + 42); // MinorOperatingSystemVersion
	buf.writeUInt16LE(0, optOff + 44); // MajorImageVersion
	buf.writeUInt16LE(0, optOff + 46); // MinorImageVersion
	buf.writeUInt16LE(6, optOff + 48); // MajorSubsystemVersion
	buf.writeUInt16LE(0, optOff + 50); // MinorSubsystemVersion
	buf.writeUInt32LE(0, optOff + 52); // Win32VersionValue
	buf.writeUInt32LE(0x2000, optOff + 56); // SizeOfImage
	buf.writeUInt32LE(0x0200, optOff + 60); // SizeOfHeaders
	buf.writeUInt32LE(0, optOff + 64); // CheckSum
	buf.writeUInt16LE(3, optOff + 68); // Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI
	buf.writeUInt16LE(0, optOff + 70); // DllCharacteristics
	buf.writeUInt32LE(0x100000, optOff + 72); // SizeOfStackReserve
	buf.writeUInt32LE(0x1000, optOff + 76); // SizeOfStackCommit
	buf.writeUInt32LE(0x100000, optOff + 80); // SizeOfHeapReserve
	buf.writeUInt32LE(0x1000, optOff + 84); // SizeOfHeapCommit
	buf.writeUInt32LE(0, optOff + 88); // LoaderFlags
	buf.writeUInt32LE(16, optOff + 92); // NumberOfRvaAndSizes

	const secOff = optOff + 0xe0;
	buf.write(".text\0\0\0", secOff, "ascii");
	buf.writeUInt32LE(0x200, secOff + 8); // VirtualSize
	buf.writeUInt32LE(0x1000, secOff + 12); // VirtualAddress
	buf.writeUInt32LE(0x200, secOff + 16); // SizeOfRawData
	buf.writeUInt32LE(0x200, secOff + 20); // PointerToRawData
	buf.writeUInt32LE(0x60000020, secOff + 36); // Characteristics = CODE | EXECUTE | READ

	const code = Buffer.from([
		0x55, // push ebp
		0x89,
		0xe5, // mov ebp, esp
		0xb8,
		0x78,
		0x56,
		0x34,
		0x12, // mov eax, 0x12345678
		0x35,
		0xef,
		0xbe,
		0xad,
		0xde, // xor eax, 0xdeadbeef
		0x5d, // pop ebp
		0xc3, // ret
	]);
	const paddedCode = Buffer.alloc(0x40, 0x90);
	code.copy(paddedCode, 0);
	const rodata = Buffer.from("synth-capability-marker\0", "ascii");
	const payload = Buffer.concat([paddedCode, rodata]);
	payload.copy(buf, 0x200);
	return buf;
}

const SYNTH_FUNC_RULE_YML = [
	"rule:",
	"  meta:",
	"    name: synthetic xor marker capability",
	"    namespace: data-manipulation/encryption/xor",
	"    authors:",
	"      - reverse-test",
	"    scopes:",
	"      static: function",
	"      dynamic: unsupported",
	"    description: Detects synthetic function with xor constant and marker",
	"  features:",
	"    - and:",
	"      - mnemonic: xor",
	"      - number: 0xdeadbeef = MAGIC_XOR_KEY",
	"      - or:",
	"        - number: 0x12345678",
	"        - number: 0x87654321",
	"      - optional:",
	"        - mnemonic: sub",
	"      - not:",
	"        - number: 0x99999999",
	"",
].join("\n");

const SYNTH_FILE_RULE_YML = [
	"rule:",
	"  meta:",
	"    name: synthetic file string marker",
	"    namespace: executable/resource",
	"    authors:",
	"      - reverse-test",
	"    scopes:",
	"      static: file",
	"      dynamic: file",
	"  features:",
	"    - and:",
	'      - string: "synth-capability-marker"',
	"      - or:",
	"        - format: elf",
	"        - format: pe",
	"",
].join("\n");

const SYNTH_NOMATCH_RULE_YML = [
	"rule:",
	"  meta:",
	"    name: synthetic non-matching capability",
	"    namespace: anti-analysis/debugger-detection",
	"    authors:",
	"      - reverse-test",
	"    scopes:",
	"      static: function",
	"      dynamic: unsupported",
	"  features:",
	"    - number: 0xfeedface",
	"",
].join("\n");

describe("capability_inspect explainable capa capability identification (Step 5)", () => {
	it("assigns read tier to status, write tier to import, exec tier to detect, enforces backend=capa, and blocks detect/import in Plan mode before process execution or writes", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cap-inspect-planmode-"));
		try {
			const normalTool = new CapabilityInspectTool(createTestSession(tempDir));
			expect(normalTool.approval({ action: "status" })).toBe("read");
			expect(normalTool.approval({ action: "import" })).toBe("write");
			expect(normalTool.approval({ action: "detect" })).toBe("exec");
			expect(normalTool.approval({})).toBe("exec");

			const jsonSchema = capabilityInspectSchema.toJsonSchema() as {
				properties?: Record<string, unknown>;
			};
			expect(jsonSchema.properties).toHaveProperty("action");
			expect(jsonSchema.properties).toHaveProperty("backend");
			expect(jsonSchema.properties).toHaveProperty("rules_path");
			expect(jsonSchema.properties).toHaveProperty("restrict_to_functions");

			await expect(
				normalTool.execute("bad-backend", {
					action: "status",
					backend: "other" as "capa",
				}),
			).rejects.toThrow(/Unsupported capability_inspect backend/i);

			const planTool = new CapabilityInspectTool(createTestSession(tempDir, { planMode: true }), {
				agentDir: tempDir,
				env: {
					PATH: tempDir,
					HOME: tempDir,
					REVERSE_CODING_AGENT_DIR: tempDir,
				},
				which: () => null,
				capaPath: path.join(tempDir, "nonexistent-capa"),
			});
			const statusRes = await planTool.execute("plan-status", { action: "status" });
			expect(statusRes.details.status).toBe("missing_dependency");
			expect(statusRes.details.backend).toBe("capa");

			await expect(
				planTool.execute("plan-detect", {
					action: "detect",
					workflow_id: "wf_1",
					step_id: "step_1",
					run_id: "run_1",
					sample_path: "sample.elf",
				}),
			).rejects.toThrow(/Plan mode is read-only/i);

			await expect(
				planTool.execute("plan-import", {
					action: "import",
					workflow_id: "wf_1",
					step_id: "step_1",
					run_id: "run_1",
					report_path: "report.json",
				}),
			).rejects.toThrow(/Plan mode is read-only/i);
		} finally {
			await removeWithRetries(tempDir);
		}
	}, 30_000);

	it("reports missing_dependency when capa is unavailable for status/detect, while offline import succeeds without requiring the capa executable", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cap-inspect-offline-"));
		const emptyBinDir = path.join(tempDir, "empty_bin");
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		try {
			await fs.mkdir(emptyBinDir, { recursive: true });
			const sampleBytes = buildSyntheticLinuxElf64();
			const sampleHash = hashBuffer(sampleBytes).sha256;
			const samplePath = path.join(tempDir, "sample.elf");
			await fs.writeFile(samplePath, sampleBytes);

			// 构造含 64 位超大整数、全地址类型、嵌套布尔树与 captures 的官方格式 capa JSON 报告
			const rawReportObj = {
				meta: {
					timestamp: "2026-11-02T12:00:00.000000",
					version: "10.0.0",
					argv: ["-j", "sample.elf"],
					sample: {
						md5: "651b4570099f9c02748b4b432d68686b",
						sha1: "39c732443b0c3dd63d245d809f1bc692734c5e72",
						sha256: sampleHash,
						path: "/tmp/sample.elf",
					},
					flavor: "static",
					analysis: {
						format: "elf",
						arch: "amd64",
						os: "linux",
						extractor: "VivisectFeatureExtractor",
						rules: ["/opt/capa/rules"],
						base_address: {
							type: "absolute",
							value: 4194304,
						},
						layout: { functions: [] },
						feature_counts: {
							file: 5,
							functions: [
								{
									address: { type: "absolute", value: 4198400 },
									count: 13,
								},
							],
						},
						library_functions: [],
					},
				},
				rules: {
					"offline rule with 64bit and all address kinds": {
						meta: {
							name: "offline rule with 64bit and all address kinds",
							namespace: "data-manipulation/encryption/xor",
							authors: ["reverse-test"],
							scopes: {
								static: "function",
								dynamic: "call",
							},
							attack: [{ tactic: "Defense Evasion", technique: "Obfuscated Files or Information", id: "T1027" }],
							mbc: [{ objective: "Data", behavior: "Encode Data", method: "XOR", id: "C0026.002" }],
							references: ["https://example.invalid/spec"],
							examples: [],
							description: "Offline fixture testing 64-bit integer precision and address kinds",
							lib: false,
							is_subscope_rule: false,
						},
						source:
							"rule:\n  meta:\n    name: offline rule with 64bit and all address kinds\n  features:\n    - and:\n      - mnemonic: xor\n",
						matches: "PLACEHOLDER_MATCHES",
					},
				},
			};

			// 直接在 JSON 文本中注入 > Number.MAX_SAFE_INTEGER 的精确 64 位整数（18446744073709551613 = 0xfffffffffffffffd），
			// 验证 Python 桥接在进入 TypeScript JSON.parse 之前完成无损转换！
			const rawJsonText = JSON.stringify(rawReportObj, null, 2).replace(
				'"PLACEHOLDER_MATCHES"',
				`[
          [
            { "type": "absolute", "value": 18446744073709551613 },
            {
              "success": true,
              "node": { "type": "statement", "statement": { "type": "and" } },
              "locations": [],
              "captures": {},
              "children": [
                {
                  "success": true,
                  "node": {
                    "type": "feature",
                    "feature": {
                      "type": "number",
                      "number": 18446744073709551615,
                      "description": "UINT64_MAX_CONST"
                    }
                  },
                  "locations": [
                    { "type": "absolute", "value": 18446744073709551613 },
                    { "type": "relative", "value": 4096 },
                    { "type": "file", "value": 4160 },
                    { "type": "dn token", "value": 100663297 },
                    { "type": "dn token offset", "value": [100663297, 18446744073709551613] }
                  ],
                  "captures": {},
                  "children": []
                },
                {
                  "success": true,
                  "node": {
                    "type": "feature",
                    "feature": {
                      "type": "regex",
                      "regex": "^synth-[a-z]+",
                      "match": "synth-capability"
                    }
                  },
                  "locations": [{ "type": "file", "value": 4160 }],
                  "captures": {
                    "synth-capability": [{ "type": "file", "value": 4160 }]
                  },
                  "children": []
                }
              ]
            }
          ]
        ]`,
			);

			const rawReportPath = path.join(tempDir, "offline_capa.json");
			await fs.writeFile(rawReportPath, rawJsonText, "utf8");

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);

			const wfRes = await wfTool.execute("wf-create", {
				action: "create",
				target: samplePath,
				goal: "Test missing capa dependency vs offline import",
			});
			const workflowId = wfRes.details.workflow!.id;
			const stepId = wfRes.details.workflow!.steps[0]!.id;

			const beginRes = await wsTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Verify offline import without capa executable",
				command: "capability_inspect import",
				inputs: ["offline_capa.json"],
			});
			const runId = beginRes.details.run_id!;

			const isolatedTool = new CapabilityInspectTool(session, {
				agentDir: emptyBinDir,
				env: {
					PATH: emptyBinDir,
					HOME: emptyBinDir,
					REVERSE_CODING_AGENT_DIR: emptyBinDir,
				},
				which: () => null,
				capaPath: path.join(emptyBinDir, "nonexistent-capa"),
			});

			const stMiss = await isolatedTool.execute("st-miss", { action: "status" });
			expect(stMiss.details.status).toBe("missing_dependency");
			expect(stMiss.details.ready).toBe(false);
			expect(stMiss.details.missingTools).toContain("capa");
			expect(stMiss.details.setupCommands).toContain("reverse setup reverse capa --execute");

			const detMiss = await isolatedTool.execute("det-miss", {
				action: "detect",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				sample_path: "sample.elf",
			});
			expect(detMiss.details.status).toBe("missing_dependency");
			expect(detMiss.details.missingTools).toContain("capa");

			// 即使 capa 完全不存在，import 依然成功完成 64 位整数无损桥接与证据生成！
			const impRes = await isolatedTool.execute("imp-ok", {
				action: "import",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				sample_path: "sample.elf",
				report_path: "offline_capa.json",
			});
			expect(impRes.details.status).toBe("ok");
			expect(impRes.details.assuranceLevel).toBe("static_candidate");

			const report = impRes.details.report!;
			expect(report.matched_rule_count).toBe(1);
			const rule = report.rules[0]!;
			expect(rule.rule_name).toBe("offline rule with 64bit and all address kinds");
			expect(rule.namespace).toBe("data-manipulation/encryption/xor");
			expect(rule.primary_scope).toBe("function");
			expect(rule.json_pointer).toBe("/rules/offline rule with 64bit and all address kinds");
			expect(rule.source_json_pointer).toBe("/rules/offline rule with 64bit and all address kinds/source");

			const match = rule.matches[0]!;
			// 验证 18446744073709551613 (0xfffffffffffffffd) 未被 JS Number 截断为 18446744073709552000
			expect(match.address).toMatchObject({
				kind: "absolute",
				raw_type: "absolute",
				has_address: true,
				decimal: "18446744073709551613",
				hex: "0xfffffffffffffffd",
				value: "0xfffffffffffffffd",
				display: "va:0xfffffffffffffffd",
			});

			const numNode = match.tree.children[0]!;
			expect(numNode.node_kind).toBe("feature");
			expect(numNode.feature).toMatchObject({
				type: "number",
				decimal: "18446744073709551615",
				hex: "0xffffffffffffffff",
				value: "0xffffffffffffffff",
				description: "UINT64_MAX_CONST",
			});
			expect(numNode.locations.map(l => l.kind)).toEqual([
				"absolute",
				"relative",
				"file_offset",
				"dotnet_token",
				"dotnet_token_offset",
			]);
			expect(numNode.locations[1]).toMatchObject({
				kind: "relative",
				decimal: "4096",
				hex: "0x1000",
				display: "rva:0x1000",
			});
			expect(numNode.locations[2]).toMatchObject({
				kind: "file_offset",
				decimal: "4160",
				hex: "0x1040",
				display: "file:0x1040",
			});
			expect(numNode.locations[3]).toMatchObject({
				kind: "dotnet_token",
				decimal: "100663297",
				hex: "0x6000001",
				display: "token:0x6000001",
				token: { decimal: "100663297", hex: "0x6000001" },
			});
			expect(numNode.locations[4]).toMatchObject({
				kind: "dotnet_token_offset",
				decimal: "100663297+18446744073709551613",
				hex: "0x6000001+0xfffffffffffffffd",
				display: "token:0x6000001+0xfffffffffffffffd",
				token: {
					decimal: "100663297",
					hex: "0x6000001",
					offset_decimal: "18446744073709551613",
					offset_hex: "0xfffffffffffffffd",
				},
			});

			const regexNode = match.tree.children[1]!;
			expect(regexNode.captures["synth-capability"]?.[0]).toMatchObject({
				kind: "file_offset",
				decimal: "4160",
				hex: "0x1040",
			});
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	}, 30_000);

	it("executes real capa on synthetic Linux ELF64 and Windows PE32 fixtures with deterministic rules, preserving full match trees, file-scope no-address, rules provenance, filters, embedded provenance, and record/recall", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cap-inspect-real-e2e-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		try {
			const samplesDir = path.join(tempDir, "samples");
			const rulesDir = path.join(tempDir, "rules");
			await fs.mkdir(samplesDir, { recursive: true });
			await fs.mkdir(rulesDir, { recursive: true });

			const elfPath = path.join(samplesDir, "synth_target.elf");
			const pePath = path.join(samplesDir, "synth_target.exe");
			await fs.writeFile(elfPath, buildSyntheticLinuxElf64());
			await fs.writeFile(pePath, buildSyntheticWindowsPe32());

			const funcRulePath = path.join(rulesDir, "func_rule.yml");
			const fileRulePath = path.join(rulesDir, "file_rule.yml");
			const noMatchRulePath = path.join(rulesDir, "nomatch_rule.yml");
			await fs.writeFile(funcRulePath, SYNTH_FUNC_RULE_YML, "utf8");
			await fs.writeFile(fileRulePath, SYNTH_FILE_RULE_YML, "utf8");
			await fs.writeFile(noMatchRulePath, SYNTH_NOMATCH_RULE_YML, "utf8");

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const capTool = new CapabilityInspectTool(session);

			const stRes = await capTool.execute("st-real", { action: "status" });
			if (!stRes.details.ready || !stRes.details.capa?.version) {
				throw new Error(
					`Actionable real-engine blocker: capa toolchain is not ready (${stRes.details.error ?? "missing capa"}). Run: reverse setup reverse capa --execute`,
				);
			}
			const realCapaVersion = stRes.details.capa.version;
			expect(stRes.details.status).toBe("ok");
			expect(stRes.details.ready).toBe(true);
			const wfRes = await wfTool.execute("wf-create", {
				action: "create",
				target: elfPath,
				goal: "Verify capa capability detection on synthetic ELF64 and PE32",
			});
			const workflowId = wfRes.details.workflow!.id;
			const stepId = wfRes.details.workflow!.steps[0]!.id;

			const beginRes = await wsTool.execute("ws-begin-1", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Run capa detect on synthetic ELF64 and PE32 with deterministic rules",
				command: "capability_inspect detect",
				inputs: [
					"samples/synth_target.elf",
					"samples/synth_target.exe",
					"rules/func_rule.yml",
					"rules/file_rule.yml",
					"rules/nomatch_rule.yml",
				],
			});
			const runId = beginRes.details.run_id!;

			// 1. 真实 capa 检测合成 Linux ELF64
			const elfDetect = await capTool.execute("det-elf", {
				action: "detect",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				sample_path: "samples/synth_target.elf",
				rules_path: "rules",
			});
			expect(elfDetect.details.error).toBeUndefined();
			expect(elfDetect.details.status).toBe("ok");
			expect(elfDetect.details.exitCode).toBe(0);
			expect(elfDetect.details.assuranceLevel).toBe("static_candidate");

			// 校验所有输出文件权限均为 0600
			if (process.platform !== "win32") {
				for (const outAbs of elfDetect.details.outputPaths ?? []) {
					const st = await fs.stat(outAbs);
					expect(st.mode & 0o777).toBe(0o600);
				}
			}

			const elfReport = elfDetect.details.report!;
			expect(elfReport.analysis.format).toBe("elf");
			expect(elfReport.analysis.arch).toBe("amd64");
			expect(elfReport.analysis.os).toBe("linux");
			expect(elfReport.analysis.extractor).toBe("VivisectFeatureExtractor");
			expect(elfReport.analysis.base_address).toMatchObject({
				kind: "absolute",
				decimal: "4194304",
				hex: "0x400000",
			});
			expect(elfReport.rules_provenance).toMatchObject({
				source: "external_manifest",
				rules_kind: "directory",
				rules_path: "rules",
				rule_count: 3,
				independent_content_hash_available: true,
				verified_unchanged_after_execution: true,
				bound_in_begin_inputs: true,
			});
			expect(elfReport.matched_rule_count).toBe(2);

			const elfByName = new Map(elfReport.rules.map(r => [r.rule_name, r]));
			const elfFuncRule = elfByName.get("synthetic xor marker capability")!;
			expect(elfFuncRule).toBeDefined();
			expect(elfFuncRule.namespace).toBe("data-manipulation/encryption/xor");
			expect(elfFuncRule.primary_scope).toBe("function");
			expect(elfFuncRule.matches[0]?.address).toMatchObject({
				kind: "absolute",
				decimal: "4198400",
				hex: "0x401000",
				display: "va:0x401000",
			});

			// 验证完整布尔匹配树（and -> mnemonic, number, optional, not, or）与叶特征地址
			const rootTree = elfFuncRule.matches[0]!.tree;
			expect(rootTree.node_kind).toBe("statement");
			expect(rootTree.type).toBe("and");
			expect(rootTree.success).toBe(true);
			const childTypes = rootTree.children.map(c => `${c.node_kind}:${c.type}:${c.success}`);
			expect(childTypes).toContain("feature:mnemonic:true");
			expect(childTypes).toContain("feature:number:true");
			expect(childTypes).toContain("statement:optional:true");
			expect(childTypes).toContain("statement:not:true");
			expect(childTypes).toContain("statement:or:true");

			const xorLeaf = elfFuncRule.matches[0]!.leaf_features.find(
				lf => lf.type === "number" && lf.hex === "0xdeadbeef",
			);
			expect(xorLeaf).toBeDefined();
			expect(xorLeaf?.description).toBe("MAGIC_XOR_KEY");
			expect(xorLeaf?.locations[0]).toMatchObject({
				kind: "absolute",
				decimal: "4198409",
				hex: "0x401009",
			});

			// 验证 file-scope 规则显式为 no_address，且叶特征保留文件偏移 0x1040 (4160)
			const elfFileRule = elfByName.get("synthetic file string marker")!;
			expect(elfFileRule).toBeDefined();
			expect(elfFileRule.primary_scope).toBe("file");
			expect(elfFileRule.matches[0]?.address).toMatchObject({
				kind: "no_address",
				raw_type: "no address",
				has_address: false,
				value: null,
				decimal: null,
				hex: null,
				display: "no address",
			});
			const strLeaf = elfFileRule.matches[0]!.leaf_features.find(lf => lf.type === "string");
			expect(strLeaf?.value).toBe("synth-capability-marker");
			expect(strLeaf?.locations[0]).toMatchObject({
				kind: "file_offset",
				decimal: "4160",
				hex: "0x1040",
				display: "file:0x1040",
			});

			// 验证 FACT 与 HYPOTHESIS 证据候选分离，且均处于 static_candidate，给出互补 FindCrypt 的观察地址行动建议
			const candidates = elfDetect.details.evidenceCandidates!;
			const factCands = candidates.filter(c => c.kind === "fact");
			const hypCands = candidates.filter(c => c.kind === "hypothesis");
			expect(factCands.length).toBe(2);
			expect(hypCands.length).toBe(2);
			for (const cand of candidates) {
				expect(cand.assurance_level).toBe("static_candidate");
				expect(cand.can_satisfy_dynamic_call_gate).toBe(false);
				expect(cand.artifact_sha256).toBe(elfDetect.details.reportSha256!);
				expect(cand.raw_report_sha256).toBe(elfDetect.details.rawReportSha256!);
			}
			const xorNextActions = elfDetect.details.nextActions!.filter(
				a => a.rule_name === "synthetic xor marker capability",
			);
			expect(xorNextActions.some(a => a.action_kind === "decompile" && a.complements_findcrypt)).toBe(true);
			expect(xorNextActions.some(a => a.action_kind === "debug_or_hook" && a.complements_findcrypt)).toBe(true);
			expect(xorNextActions.every(a => a.observed_locations.some(loc => loc.hex === "0x401000"))).toBe(true);

			// 2. 真实 capa 检测合成 Windows PE32 + 命名空间筛选 + --restrict-to-functions
			const peDetect = await capTool.execute("det-pe", {
				action: "detect",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				sample_path: "samples/synth_target.exe",
				rules_path: "rules",
				namespace: "data-manipulation/encryption/xor",
				restrict_to_functions: ["0x401000"],
			});
			expect(peDetect.details.status).toBe("ok");
			const peReport = peDetect.details.report!;
			expect(peReport.analysis.format).toBe("pe");
			expect(peReport.analysis.arch).toBe("i386");
			expect(peReport.analysis.os).toBe("windows");
			expect(peReport.matched_rule_count).toBe(1);
			expect(peReport.rules[0]?.rule_name).toBe("synthetic xor marker capability");
			expect(peReport.rules[0]?.matches[0]?.address.hex).toBe("0x401000");
			expect(
				peReport.rules[0]?.matches[0]?.leaf_features.find(lf => lf.type === "number" && lf.hex === "0xdeadbeef")
					?.locations[0]?.hex,
			).toBe("0x401008");
			expect(peReport.limitations.some(l => l.includes("--restrict-to-functions"))).toBe(true);

			// 3. 单规则文件无匹配（0 matches）正常返回 ok 且保留 1 条 0-match FACT
			const noMatchDetect = await capTool.execute("det-nomatch", {
				action: "detect",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				sample_path: "samples/synth_target.exe",
				rules_path: "rules/nomatch_rule.yml",
			});
			expect(noMatchDetect.details.status).toBe("ok");
			expect(noMatchDetect.details.report?.matched_rule_count).toBe(0);
			expect(noMatchDetect.details.rulesProvenance?.rules_kind).toBe("single_file");
			expect(noMatchDetect.details.evidenceCandidates).toHaveLength(1);
			expect(noMatchDetect.details.evidenceCandidates?.[0]?.kind).toBe("fact");

			// 4. 内嵌规则模式（use_embedded_rules: true）：记录引擎二进制 SHA-256 + 版本，明确独立规则哈希不可用
			const embeddedDetect = await capTool.execute("det-embedded", {
				action: "detect",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				sample_path: "samples/synth_target.exe",
				use_embedded_rules: true,
				tag: "create TCP socket",
			});
			expect(embeddedDetect.details.error).toBeUndefined();
			expect(embeddedDetect.details.status).toBe("ok");
			expect(embeddedDetect.details.rulesProvenance).toMatchObject({
				source: "embedded",
				rules_kind: "embedded_in_engine",
				rules_path: null,
				manifest_sha256: null,
				independent_content_hash_available: false,
				engine_version: realCapaVersion,
				verified_unchanged_after_execution: true,
			});
			expect(embeddedDetect.details.rulesProvenance?.engine_binary_sha256).toMatch(/^[0-9a-f]{64}$/);
			expect(
				embeddedDetect.details.limitations?.some(l =>
					l.includes("independent rule directory content SHA-256 is unavailable"),
				),
			).toBe(true);

			// 5. 通过 reverse_workspace record 登记产物并支持新会话 recall
			const recordRes = await wsTool.execute("ws-record", {
				action: "record",
				workflow_id: workflowId,
				run_id: runId,
				exit_code: 0,
				summary: "Completed capa detect on synthetic ELF64 and PE32",
				output_paths: [
					...(elfDetect.details.relativeOutputPaths ?? []),
					...(peDetect.details.relativeOutputPaths ?? []),
				],
			});
			expect(recordRes.details.run?.status).toBe("succeeded");

			const recallRes = await wsTool.execute("ws-recall", {
				action: "recall",
				workflow_id: workflowId,
			});
			expect(recallRes.details.recalled_runs?.[0]?.reuse_status).toBe("available");
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	}, 120_000);

	it("preserves imported dynamic reports (process/thread/call addresses) strictly as historical static_candidate context and prevents dynamic assurance escalation, while rejecting sample hash mismatch, corrupt JSON, and unsupported versions", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cap-inspect-dyn-validation-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		const evStore = new EvidenceStore({ repositoryRoot: tempDir });
		try {
			const sampleBytes = buildSyntheticWindowsPe32();
			const sampleSha256 = hashBuffer(sampleBytes).sha256;
			const samplePath = path.join(tempDir, "sample.exe");
			await fs.writeFile(samplePath, sampleBytes);

			const dynamicReportPath = path.join(tempDir, "dyn_cape_report.json");
			const mismatchReportPath = path.join(tempDir, "mismatch_report.json");
			const corruptReportPath = path.join(tempDir, "corrupt_report.json");
			const unsupportedVerPath = path.join(tempDir, "unsupported_ver.json");
			const badFileMatchAddrPath = path.join(tempDir, "bad_file_addr.json");

			const baseDynReport = {
				meta: {
					timestamp: "2026-11-02T12:00:00.000000",
					version: "10.0.0",
					argv: ["-j", "-f", "cape", "report.json"],
					sample: {
						md5: "277dc0027fba78a527119619a2a6cfe0",
						sha1: "6161f1f07721ffc043b446dc568850b87d8f155f",
						sha256: sampleSha256,
						path: "/tmp/sample.exe",
					},
					flavor: "dynamic",
					analysis: {
						format: "cape",
						arch: "i386",
						os: "windows",
						extractor: "CapeExtractor",
						rules: ["(embedded rules)"],
						base_address: { type: "no address" },
						layout: { processes: [] },
						feature_counts: {
							file: 2,
							processes: [
								{
									address: { type: "process", value: [4242, 1000] },
									count: 15,
								},
							],
						},
						library_functions: [],
					},
				},
				rules: {
					"create process dynamically": {
						meta: {
							name: "create process dynamically",
							namespace: "host-interaction/process/create",
							authors: ["reverse-test"],
							scopes: {
								static: "function",
								dynamic: "call",
							},
							attack: [],
							mbc: [],
							references: [],
							examples: [],
							description: "Historical sandbox call match",
						},
						matches: [
							[
								{ type: "call", value: [4242, 1000, 8888, 99] },
								{
									success: true,
									node: { type: "statement", statement: { type: "subscope", scope: "thread" } },
									locations: [{ type: "thread", value: [4242, 1000, 8888] }],
									captures: {},
									children: [
										{
											success: true,
											node: {
												type: "feature",
												feature: { type: "api", api: "CreateProcessW" },
											},
											locations: [
												{ type: "process", value: [4242, 1000] },
												{ type: "thread", value: [4242, 1000, 8888] },
												{ type: "call", value: [4242, 1000, 8888, 99] },
											],
											captures: {},
											children: [],
										},
									],
								},
							],
						],
					},
				},
			};

			await fs.writeFile(dynamicReportPath, JSON.stringify(baseDynReport, null, 2), "utf8");
			await fs.writeFile(
				mismatchReportPath,
				JSON.stringify({
					...baseDynReport,
					meta: {
						...baseDynReport.meta,
						sample: {
							...baseDynReport.meta.sample,
							sha256: "0".repeat(64),
						},
					},
				}),
				"utf8",
			);
			await fs.writeFile(corruptReportPath, '{"meta": {"version": "10.0.0"}, "rules": ', "utf8");
			await fs.writeFile(
				unsupportedVerPath,
				JSON.stringify({
					...baseDynReport,
					meta: {
						...baseDynReport.meta,
						version: "1.0.0",
					},
				}),
				"utf8",
			);
			await fs.writeFile(
				badFileMatchAddrPath,
				JSON.stringify({
					...baseDynReport,
					meta: { ...baseDynReport.meta, flavor: "static" },
					rules: {
						"invalid file rule with va": {
							meta: {
								name: "invalid file rule with va",
								scopes: { static: "file", dynamic: "file" },
							},
							matches: [
								[
									{ type: "absolute", value: 4198400 },
									{
										success: true,
										node: { type: "feature", feature: { type: "format", format: "pe" } },
										locations: [],
										captures: {},
										children: [],
									},
								],
							],
						},
					},
				}),
				"utf8",
			);

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const capTool = new CapabilityInspectTool(session);

			const wfRes = await wfTool.execute("wf-create", {
				action: "create",
				target: samplePath,
				goal: "Verify dynamic import non-escalation and validation gates",
			});
			const workflowId = wfRes.details.workflow!.id;
			const stepId = wfRes.details.workflow!.steps[0]!.id;

			const beginRes = await wsTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Import dynamic and malformed capa reports",
				command: "capability_inspect import",
				inputs: [
					"dyn_cape_report.json",
					"mismatch_report.json",
					"corrupt_report.json",
					"unsupported_ver.json",
					"bad_file_addr.json",
				],
			});
			const runId = beginRes.details.run_id!;

			const dynImp = await capTool.execute("imp-dyn", {
				action: "import",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				report_path: "dyn_cape_report.json",
			});
			expect(dynImp.details.status).toBe("ok");
			expect(dynImp.details.assuranceLevel).toBe("static_candidate");
			const dynReport = dynImp.details.report!;
			expect(dynReport.analysis_flavor).toBe("dynamic");
			expect(dynReport.historical_dynamic_import).toBe(true);
			expect(dynReport.assurance_level).toBe("static_candidate");

			const dynMatch = dynReport.rules[0]!.matches[0]!;
			expect(dynMatch.address).toMatchObject({
				kind: "call",
				display: "call(pid=4242,ppid=1000,tid=8888,id=99)",
				dynamic: {
					pid: "4242",
					ppid: "1000",
					tid: "8888",
					call_id: "99",
				},
			});
			const apiLocs = dynMatch.leaf_features[0]!.locations;
			expect(apiLocs.map(l => l.kind)).toEqual(["process", "thread", "call"]);

			for (const cand of dynImp.details.evidenceCandidates ?? []) {
				expect(cand.assurance_level).toBe("static_candidate");
				expect(cand.historical_context_only).toBe(true);
				expect(cand.can_satisfy_dynamic_call_gate).toBe(false);
			}

			// 验证将导入的候选写入 EvidenceStore 时仅能作为 static_candidate，绝无法通过 dynamic_call_observation 验证门禁
			const factCand = dynImp.details.evidenceCandidates!.find(c => c.kind === "fact")!;
			const hypCand = dynImp.details.evidenceCandidates!.find(c => c.kind === "hypothesis")!;
			const addedFact = await evStore.addFact({
				kind: "fact",
				title: "Imported capa dynamic rule hit",
				target: "sample.exe",
				subject: "process_creation",
				sourceTool: "capability_inspect",
				locator: `${factCand.artifact_path}#${factCand.json_pointer}`,
				content: factCand.statement,
				executionBinding: { artifactSha256: sampleSha256 },
				context: {
					subject: "process_creation",
					assurance: factCand.assurance_level,
					executionBinding: { artifactSha256: sampleSha256 },
				},
			});
			const addedHyp = await evStore.addHypothesis({
				kind: "hypothesis",
				title: "Program creates child process",
				target: "sample.exe",
				subject: "process_creation",
				claim: hypCand.claim ?? hypCand.statement,
				verificationPlan: hypCand.verification_plan ?? "Verify live",
				facts: [addedFact.id],
				executionBinding: { artifactSha256: sampleSha256 },
			});

			await expect(
				evStore.verifyHypothesis({
					hypothesisId: addedHyp.id,
					status: "verified",
					method: "capability_inspect import",
					command: "capability_inspect import",
					result: "Imported dynamic capa report",
					conclusion: "Attempt to promote imported capa report to dynamic_call_observation",
					context: {
						subject: "process_creation",
						assurance: "dynamic_call_observation",
					},
				}),
			).rejects.toThrow(/assurance|dynamic_call_observation/i);

			// 校验样本 SHA-256 不匹配、损坏 JSON、不支持版本与非法 file-scope 地址均被拒绝且不返回伪成功
			await expect(
				capTool.execute("imp-mismatch", {
					action: "import",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					report_path: "mismatch_report.json",
				}),
			).rejects.toThrow(/Sample SHA-256 mismatch/i);

			await expect(
				capTool.execute("imp-corrupt", {
					action: "import",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					report_path: "corrupt_report.json",
				}),
			).rejects.toThrow(/corrupt_json|Malformed capa JSON/i);

			await expect(
				capTool.execute("imp-unsupported-ver", {
					action: "import",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					report_path: "unsupported_ver.json",
				}),
			).rejects.toThrow(/unsupported_version|Unsupported capa result document version/i);

			await expect(
				capTool.execute("imp-bad-file-addr", {
					action: "import",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					report_path: "bad_file_addr.json",
				}),
			).rejects.toThrow(/File-scope rule[\s\S]*must have 'no address'/i);
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(tempDir);
		}
	}, 30_000);

	it("enforces begin input binding on sample and rule closure, detects post-execution rule drift, enforces sample/output/time bounds, retains 0600 failure diagnostics, rejects symlinks, and honors AbortSignal cancellation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cap-inspect-security-"));
		const outsideDir = await fs.mkdtemp(path.join(os.tmpdir(), "cap-inspect-outside-"));
		const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		try {
			const samplesDir = path.join(tempDir, "samples");
			const rulesDir = path.join(tempDir, "rules");
			await fs.mkdir(samplesDir, { recursive: true });
			await fs.mkdir(rulesDir, { recursive: true });

			const elfPath = path.join(samplesDir, "target.elf");
			const badSamplePath = path.join(samplesDir, "not_an_executable.bin");
			await fs.writeFile(elfPath, buildSyntheticLinuxElf64());
			await fs.writeFile(badSamplePath, Buffer.from("NOT_PE_OR_ELF_DATA_1234567890", "ascii"));

			const boundRulePath = path.join(rulesDir, "bound_rule.yml");
			await fs.writeFile(boundRulePath, SYNTH_FUNC_RULE_YML, "utf8");

			const outsideSecret = path.join(outsideDir, "outside.yml");
			await fs.writeFile(outsideSecret, SYNTH_FILE_RULE_YML, "utf8");

			const session = createTestSession(tempDir);
			const wfTool = new ReverseWorkflowTool(session);
			const wsTool = new ReverseWorkspaceTool(session);
			const capTool = new CapabilityInspectTool(session);

			const wfRes = await wfTool.execute("wf-create", {
				action: "create",
				target: elfPath,
				goal: "Test security, bounds, drift, and cancellation",
			});
			const workflowId = wfRes.details.workflow!.id;
			const stepId = wfRes.details.workflow!.steps[0]!.id;

			// begin 时故意不把 rules/unbound_rule.yml 放进 inputs
			const beginRes = await wsTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: stepId,
				purpose: "Security and bounds checks",
				command: "capability_inspect detect",
				inputs: ["samples/target.elf", "samples/not_an_executable.bin", "rules/bound_rule.yml"],
			});
			const runId = beginRes.details.run_id!;

			// 1. 规则目录中存在未在 begin inputs 声明的新规则文件时，在进程启动前由 loadAnalysisExecution 拒绝
			const unboundRulePath = path.join(rulesDir, "unbound_rule.yml");
			await fs.writeFile(unboundRulePath, SYNTH_FILE_RULE_YML, "utf8");
			await expect(
				capTool.execute("rej-unbound-rule", {
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: "samples/target.elf",
					rules_path: "rules",
				}),
			).rejects.toThrow(/was not declared in 'inputs' at 'begin'/i);
			await fs.unlink(unboundRulePath);

			// 2. 拒绝网络 URL、路径越界、软链样本、软链规则目录及规则目录内部软链
			await expect(
				capTool.execute("rej-url-sample", {
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: "https://example.invalid/sample.elf",
				}),
			).rejects.toThrow(/Network or URI path is prohibited/i);

			await expect(
				capTool.execute("rej-escape-rules", {
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: "samples/target.elf",
					rules_path: outsideDir,
				}),
			).rejects.toThrow(/escapes root directory|Invalid rules_path/i);

			// 拒绝通过 CAPA_RULES_PATH 将任意未绑定的项目外目录伪装成受管规则资产
			const externalEnvTool = new CapabilityInspectTool(session, {
				env: {
					...(process.env as Record<string, string | undefined>),
					CAPA_RULES_PATH: outsideDir,
				},
			});
			await expect(
				externalEnvTool.execute("rej-env-external-rules", {
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: "samples/target.elf",
				}),
			).rejects.toThrow(/Unbound external capa rules path|outside the project directory/i);
			const symlinkSample = path.join(samplesDir, "symlink_target.elf");
			await fs.symlink(elfPath, symlinkSample);
			await expect(
				capTool.execute("rej-symlink-sample", {
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: "samples/symlink_target.elf",
					rules_path: "rules",
				}),
			).rejects.toThrow(/Symlink escape violation/i);
			await fs.unlink(symlinkSample);

			const symlinkRuleInside = path.join(rulesDir, "symlink_rule.yml");
			await fs.symlink(outsideSecret, symlinkRuleInside);
			await expect(
				capTool.execute("rej-symlink-in-rules", {
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: "samples/target.elf",
					rules_path: "rules",
				}),
			).rejects.toThrow(/Symbolic link is not allowed in capa rules directory|Symlink/i);
			await fs.unlink(symlinkRuleInside);

			// 3. 拒绝非法格式与函数地址注入
			await expect(
				capTool.execute("rej-dyn-format", {
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: "samples/target.elf",
					format: "cape" as "auto",
				}),
			).rejects.toThrow(/Unsupported static format/i);

			await expect(
				capTool.execute("rej-bad-func-filter", {
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: "samples/target.elf",
					restrict_to_functions: ["0x401000; rm -rf /"],
				}),
			).rejects.toThrow(/Invalid function address/i);

			// 4. max_sample_bytes 样本大小上限拦截
			await expect(
				capTool.execute("rej-max-sample-bytes", {
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: "samples/target.elf",
					rules_path: "rules",
					max_sample_bytes: 32,
				}),
			).rejects.toThrow(/exceeds max_sample_bytes/i);

			// 5. max_output_bytes 输出大小上限拦截：保留 0600 失败诊断报告且 status="error"
			const overflowRes = await capTool.execute("det-output-overflow", {
				action: "detect",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				sample_path: "samples/target.elf",
				rules_path: "rules",
				max_output_bytes: 512,
			});
			expect(overflowRes.details.status).toBe("error");
			expect(overflowRes.details.failureReport?.output_overflowed).toBe(true);
			expect((await fs.stat(overflowRes.details.reportPath!)).isFile()).toBe(true);

			// 6. 不支持的样本触发 capa 非零退出：保留 0600 失败诊断报告且绝不返回空匹配伪成功
			const badSampleRes = await capTool.execute("det-bad-sample", {
				action: "detect",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				sample_path: "samples/not_an_executable.bin",
				rules_path: "rules",
			});
			expect(badSampleRes.details.status).toBe("error");
			expect(badSampleRes.details.failureReport).toBeDefined();
			expect(badSampleRes.details.report).toBeUndefined();
			if (process.platform !== "win32") {
				const st = await fs.stat(badSampleRes.details.reportPath!);
				expect(st.mode & 0o777).toBe(0o600);
			}

			// 7. 执行后规则完整性复核（post-execution rules drift check）：若执行期间规则文件被篡改则立即报错拒绝
			const driftTool = new CapabilityInspectTool(session, {
				onBeforePostExecutionRulesCheck: async () => {
					await fs.writeFile(boundRulePath, `${SYNTH_FUNC_RULE_YML}# tampered during run\n`, "utf8");
				},
			});
			await expect(
				driftTool.execute("rej-post-exec-drift", {
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: "samples/target.elf",
					rules_path: "rules",
				}),
			).rejects.toThrow(/Capa rules integrity check failed after execution/i);
			await fs.writeFile(boundRulePath, SYNTH_FUNC_RULE_YML, "utf8");

			// 8. AbortSignal 取消（预先取消与运行中取消）
			const preAbort = new AbortController();
			preAbort.abort();
			await expect(
				capTool.execute(
					"cancel-pre",
					{
						action: "detect",
						workflow_id: workflowId,
						step_id: stepId,
						run_id: runId,
						sample_path: "samples/target.elf",
						rules_path: "rules",
					},
					preAbort.signal,
				),
			).rejects.toThrow(/abort|cancel/i);

			const midAbort = new AbortController();
			const pendingDetect = capTool.execute(
				"cancel-mid",
				{
					action: "detect",
					workflow_id: workflowId,
					step_id: stepId,
					run_id: runId,
					sample_path: "samples/target.elf",
					rules_path: "rules",
				},
				midAbort.signal,
			);
			queueMicrotask(() => midAbort.abort());
			await expect(pendingDetect).rejects.toThrow(/abort|cancel/i);
		} finally {
			await removeWithRetries(wfStore.projectDirectory).catch(() => undefined);
			await removeWithRetries(outsideDir);
			await removeWithRetries(tempDir);
		}
	}, 120_000);
});

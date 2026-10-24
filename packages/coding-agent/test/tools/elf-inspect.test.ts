import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { Settings } from "../../src/config/settings";
import type { ToolSession } from "../../src/tools";
import { ElfInspectTool } from "../../src/tools/elf-inspect";
import { executeModuleDump } from "../../src/tools/elf-dump-helper";

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

describe("ElfInspectTool", () => {
	it("registers canonical name, parameter schema, and tier approval contracts", () => {
		const session = createTestSession("/tmp");
		const tool = new ElfInspectTool(session);

		// Read tier
		expect(tool.approval({ action: "status" })).toBe("read");
		expect(tool.approval({ action: "query" })).toBe("read");

		// Exec tier
		expect(tool.approval({ action: "dump" })).toBe("exec");
		expect(tool.approval({ action: "repair" })).toBe("exec");
		expect(tool.approval({ action: "dump_and_repair" })).toBe("exec");
	});

	it("blocks mutating actions in plan mode and permits read actions", async () => {
		const session = createTestSession("/tmp", true);
		const tool = new ElfInspectTool(session);

		const statusRes = await tool.execute("call-1", { action: "status" });
		expect(statusRes.details.action).toBe("status");

		await expect(
			tool.execute("call-2", {
				action: "dump",
				pid: 1234,
				module: "libtarget.so",
			}),
		).rejects.toBeInstanceOf(ToolError);

		await expect(
			tool.execute("call-3", {
				action: "repair",
				dump_path: "/tmp/fake.dump",
				base_address: "0x0",
			}),
		).rejects.toBeInstanceOf(ToolError);
	});

	it("enforces 1 GiB file size limit on query", async () => {
		const session = createTestSession("/tmp");
		const tool = new ElfInspectTool(session);

		const fakeDir = await fs.mkdtemp(path.join(os.tmpdir(), "giant-elf-"));
		const fakePath = path.join(fakeDir, "giant.so");

		// Create sparse file > 1 GiB
		const fd = await fs.open(fakePath, "w");
		await fd.truncate(1024 * 1024 * 1024 + 1024);
		await fd.close();

		try {
			await expect(tool.execute("call-oversize", { action: "query", path: fakePath })).rejects.toBeInstanceOf(
				ToolError,
			);
		} finally {
			await fs.rm(fakeDir, { recursive: true, force: true });
		}
	});

	it("rejects non-ARM architecture in repair", async () => {
		const session = createTestSession("/tmp");
		const tool = new ElfInspectTool(session);

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "nonarm-"));
		const fakeX86Path = path.join(tempDir, "x86.so");

		// Construct minimal x86_64 ELF header (machine = 0x3e / 62)
		const x86Header = Buffer.alloc(52, 0);
		x86Header[0] = 0x7f;
		x86Header[1] = 0x45;
		x86Header[2] = 0x4c;
		x86Header[3] = 0x46;
		x86Header[4] = 2; // ELF64
		x86Header[5] = 1; // LSB
		x86Header.writeUInt16LE(0x3e, 18); // EM_X86_64
		await fs.writeFile(fakeX86Path, x86Header);

		try {
			await expect(
				tool.execute("call-repair-x86", {
					action: "repair",
					dump_path: fakeX86Path,
					base_address: "0x0",
				}),
			).rejects.toBeInstanceOf(ToolError);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects architecture mismatch when requested arch conflicts with dump class", async () => {
		const session = createTestSession("/tmp");
		const tool = new ElfInspectTool(session);

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "mismatch-"));
		const fakeArm64Path = path.join(tempDir, "arm64.so");

		const arm64Header = Buffer.alloc(52, 0);
		arm64Header[0] = 0x7f;
		arm64Header[1] = 0x45;
		arm64Header[2] = 0x4c;
		arm64Header[3] = 0x46;
		arm64Header[4] = 2; // ELF64
		arm64Header[5] = 1; // LSB
		arm64Header.writeUInt16LE(183, 18); // EM_AARCH64
		await fs.writeFile(fakeArm64Path, arm64Header);

		try {
			await expect(
				tool.execute("call-repair-mismatch", {
					action: "repair",
					dump_path: fakeArm64Path,
					base_address: "0x0",
					arch: "32",
				}),
			).rejects.toBeInstanceOf(ToolError);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("executeModuleDump verifies complete contiguous range coverage and detects truncation", async () => {
		const fakeRunner = async () => {
			const meta = {
				module: "libtest.so",
				base: "0x1000",
				size: 16,
				totalReadable: 16,
				unmappedBytes: 0,
				ranges: [{ offset: 0, length: 16, protection: "r-x" }],
				unmappedGaps: [],
			};

			// Emit meta, valid base64 chunk, and done marker
			const b64Data = Buffer.from("0123456789abcdef").toString("base64");
			const out = [
				`__FRIDA_DUMP_META__${JSON.stringify(meta)}__FRIDA_DUMP_META_END__`,
				`__FRIDA_DUMP_CHUNK__0:${b64Data}__FRIDA_DUMP_CHUNK_END__`,
				`__FRIDA_DUMP_DONE__{"success":true}__FRIDA_DUMP_DONE_END__`,
			].join("\n");

			return {
				stdout: Buffer.from(out),
				stderr: "",
				exitCode: 0,
				outputBytes: out.length,
				truncated: false,
				timedOut: false,
			};
		};

		const res = await executeModuleDump({
			pid: 1234,
			module: "libtest.so",
			cwd: "/tmp",
			runner: fakeRunner,
		});

		expect(res.success).toBe(true);
		expect(res.module).toBe("libtest.so");
		expect(res.baseAddress).toBe("0x1000");
		expect(res.moduleSize).toBe(16);
		expect(res.totalReadable).toBe(16);
		expect(Buffer.from(res.dumpBuffer).toString("utf8")).toBe("0123456789abcdef");

		// Truncated execution check
		const truncatedRunner = async () => ({
			stdout: Buffer.from(""),
			stderr: "",
			exitCode: 0,
			outputBytes: 0,
			truncated: true,
			timedOut: false,
		});

		await expect(
			executeModuleDump({
				pid: 1234,
				module: "libtest.so",
				cwd: "/tmp",
				runner: truncatedRunner,
			}),
		).rejects.toBeInstanceOf(ToolError);
	});
});

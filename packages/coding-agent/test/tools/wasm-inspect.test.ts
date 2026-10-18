import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	type ToolSession,
	WasmInspectTool,
	type WasmInspectDetails,
	wabtDependency,
} from "@rva/coding-agent/tools";
import { removeWithRetries } from "@rva/utils";

function u32(value: number): number[] {
	const out: number[] = [];
	let rest = value >>> 0;
	do {
		let byte = rest & 0x7f;
		rest >>>= 7;
		if (rest !== 0) byte |= 0x80;
		out.push(byte);
	} while (rest !== 0);
	return out;
}

function name(value: string): number[] {
	const bytes = [...Buffer.from(value, "utf8")];
	return [...u32(bytes.length), ...bytes];
}

function section(id: number, payload: number[]): number[] {
	return [id, ...u32(payload.length), ...payload];
}

function buildWasm(): Uint8Array {
	const types = [
		0x60,
		...u32(2),
		0x7f,
		0x7f,
		...u32(1),
		0x7f, // (i32, i32) -> (i32)
		0x60,
		...u32(1),
		0x7f,
		...u32(0), // (i32) -> ()
		0x60,
		...u32(0),
		...u32(0), // () -> ()
	];
	const typeSection = section(1, [...u32(3), ...types]);

	const importSection = section(2, [
		...u32(2),
		...name("env"),
		...name("mem"),
		0x02,
		0x01,
		0x01,
		0x02,
		...name("env"),
		...name("log"),
		0x00,
		...u32(1),
	]);

	const functionSection = section(3, [...u32(2), ...u32(0), ...u32(2)]);
	const memorySection = section(5, [0x01, 0x01, 0x01, 0x02]);
	const globalSection = section(6, [0x01, 0x7f, 0x01, 0x41, 0x00, 0x0b]);
	const exportSection = section(7, [
		...u32(3),
		...name("add"),
		0x00,
		...u32(1),
		...name("init"),
		0x00,
		...u32(2),
		...name("memory"),
		0x02,
		...u32(0),
	]);

	const bodyAdd = [0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b];
	const bodyInit = [0x00, 0x0b];
	const codeSection = section(10, [
		...u32(2),
		...u32(bodyAdd.length),
		...bodyAdd,
		...u32(bodyInit.length),
		...bodyInit,
	]);

	const dataBytes = [...Buffer.from("https://api.example.com/v1/login\0hello world\0HELLO", "utf8")];
	const dataSection = section(11, [...u32(1), 0x00, 0x41, 0x08, 0x0b, ...u32(dataBytes.length), ...dataBytes]);

	const moduleNameSubsection = [...name("demo")];
	const functionNamesSubsection = [...u32(2), ...u32(1), ...name("add"), ...u32(2), ...name("init")];
	const nameSection = section(0, [
		...name("name"),
		0x00,
		...u32(moduleNameSubsection.length),
		...moduleNameSubsection,
		0x01,
		...u32(functionNamesSubsection.length),
		...functionNamesSubsection,
	]);

	const producersSection = section(0, [...name("producers"), ...name("processed-by"), ...name("test")]);

	return new Uint8Array([
		0x00,
		0x61,
		0x73,
		0x6d,
		0x01,
		0x00,
		0x00,
		0x00,
		...typeSection,
		...importSection,
		...functionSection,
		...memorySection,
		...globalSection,
		...exportSection,
		...codeSection,
		...dataSection,
		...nameSection,
		...producersSection,
	]);
}

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

async function writeWasmFixture(dir: string): Promise<string> {
	const file = path.join(dir, "fixture.wasm");
	await Bun.write(file, buildWasm());
	return file;
}

async function makeExecutable(dir: string, body: string): Promise<string> {
	const binary = path.join(dir, "wasm2wat");
	await Bun.write(binary, `#!/bin/sh\n${body}\n`);
	await fs.chmod(binary, 0o755);
	return binary;
}

function textOf(result: { content: { type: string; text?: string }[] }): string {
	return result.content.find(entry => entry.type === "text")?.text ?? "";
}

describe("wasm_inspect info", () => {
	it("summarizes sections, imports, exports, names, and data", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-info-"));
		try {
			const file = await writeWasmFixture(tempDir);
			const tools = await createTools(createTestSession(tempDir), ["wasm_inspect"]);
			const tool = tools.find(entry => entry.name === "wasm_inspect")!;
			const result = await tool.execute("wasm-info", { action: "info", path: file });
			const text = textOf(result as never);
			const details = result.details as WasmInspectDetails;

			expect(details.status).toBe("ok");
			expect(details.bytes).toBe(buildWasm().length);
			expect(details.imports?.find(entry => entry.kind === "func")?.module).toBe("env");
			expect(details.imports?.find(entry => entry.kind === "func")?.index).toBe(0);
			expect(details.imports?.find(entry => entry.kind === "func")?.signature).toBe("(i32) -> ()");
			expect(details.exports?.find(entry => entry.name === "add")?.signature).toBe("(i32, i32) -> (i32)");
			expect(details.exports?.find(entry => entry.name === "add")?.functionName).toBe("add");
			expect(details.importedFunctionCount).toBe(1);
			expect(details.definedFunctionCount).toBe(2);
			expect(details.functionCount).toBe(3);
			expect(details.moduleName).toBe("demo");
			expect(details.functionNames).toBe(2);
			expect(details.memories?.[0]).toMatchObject({ min: 1, max: 2, imported: true });
			expect(details.memories?.[1]).toMatchObject({ min: 1, max: 2 });
			expect(details.dataSegments?.[0]).toMatchObject({ index: 0, mode: "active", memory: 0 });
			expect(details.customSections?.map(entry => entry.name)).toContain("name");

			expect(text).toContain("imports (2):");
			expect(text).toContain("env.log → func[0] (i32) -> ()");
			expect(text).toContain('"add" → func[1] (i32, i32) -> (i32) name="add"');
			expect(text).toContain("functions: 1 imported, 2 defined, 3 total");
			expect(text).toContain("memories: 2 (min=1 max=2 imported; min=1 max=2)");
			expect(text).toContain("globals: 1 (1 mutable)");
			expect(text).toContain('function names: 2, module "demo"');
			expect(text).toContain("data[0] active memory=0");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("caps lists and reports truncation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-cap-"));
		try {
			const file = await writeWasmFixture(tempDir);
			const tool = new WasmInspectTool(createTestSession(tempDir));
			const result = await tool.execute("wasm-cap", { action: "info", path: file, limit: 1 });
			const details = result.details as WasmInspectDetails;
			expect(details.truncated).toBe(true);
			expect(details.imports).toHaveLength(1);
			expect(details.exports).toHaveLength(1);
			expect(textOf(result)).toContain("… 2 more");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("wasm_inspect strings and search", () => {
	it("extracts bounded ASCII strings with offsets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-strings-"));
		try {
			const file = await writeWasmFixture(tempDir);
			const tool = new WasmInspectTool(createTestSession(tempDir));
			const result = await tool.execute("wasm-strings", {
				action: "strings",
				path: file,
				min_length: 8,
				limit: 1,
			});
			const details = result.details as WasmInspectDetails;
			expect(details.strings).toHaveLength(1);
			expect(details.strings?.[0]?.source).toBe("data[0]");
			expect(details.strings?.[0]?.text).toBe("https://api.example.com/v1/login");
			expect(details.strings?.[0]?.offset).toBeGreaterThan(0);
			expect(details.totalStrings).toBe(3);
			expect(details.truncated).toBe(true);
			expect(textOf(result)).toContain("1 shown of 3");
			expect(textOf(result)).toContain("use skip to page");

			const all = await tool.execute("wasm-strings-all", {
				action: "strings",
				path: file,
				min_length: 8,
				limit: 10,
			});
			const allDetails = all.details as WasmInspectDetails;
			expect(allDetails.truncated).toBe(false);
			expect(allDetails.strings).toContainEqual(
				expect.objectContaining({ text: "processed-by", source: "custom:producers" }),
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("finds literal matches and respects case sensitivity", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-search-"));
		try {
			const file = await writeWasmFixture(tempDir);
			const tool = new WasmInspectTool(createTestSession(tempDir));
			const exact = await tool.execute("wasm-search-1", {
				action: "search",
				path: file,
				pattern: "hello",
				limit: 10,
			});
			expect((exact.details as WasmInspectDetails).totalMatches).toBe(1);

			const insensitive = await tool.execute("wasm-search-2", {
				action: "search",
				path: file,
				pattern: "hello",
				case_sensitive: false,
				limit: 10,
			});
			const details = insensitive.details as WasmInspectDetails;
			expect(details.totalMatches).toBe(2);
			expect(details.matches?.every(match => match.offset > 0)).toBe(true);
			expect(textOf(insensitive)).toContain("2 matches");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("supports regex and skip/limit paging", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-regex-"));
		try {
			const file = await writeWasmFixture(tempDir);
			const tool = new WasmInspectTool(createTestSession(tempDir));
			const regex = await tool.execute("wasm-regex", {
				action: "search",
				path: file,
				pattern: "https?://[^\\x00\\s]+",
				regex: true,
				limit: 5,
			});
			const regexDetails = regex.details as WasmInspectDetails;
			expect(regexDetails.matches?.[0]?.length).toBe("https://api.example.com/v1/login".length);
			expect(regexDetails.matches?.[0]?.context).toContain("api.example.com");

			const all = await tool.execute("wasm-page-1", {
				action: "search",
				path: file,
				pattern: "e",
				limit: 3,
			});
			const firstPage = all.details as WasmInspectDetails;
			expect(firstPage.matches).toHaveLength(3);
			expect(firstPage.truncated).toBe(true);

			const skipped = await tool.execute("wasm-page-2", {
				action: "search",
				path: file,
				pattern: "e",
				skip: 3,
				limit: 3,
			});
			const secondPage = skipped.details as WasmInspectDetails;
			expect(secondPage.matches?.[0]?.offset).not.toBe(firstPage.matches?.[0]?.offset);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects missing and empty patterns", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-bad-pattern-"));
		try {
			const file = await writeWasmFixture(tempDir);
			const tool = new WasmInspectTool(createTestSession(tempDir));
			await expect(tool.execute("wasm-bad-1", { action: "search", path: file })).rejects.toThrow(
				"pattern is required",
			);
			await expect(tool.execute("wasm-bad-2", { action: "search", path: file, pattern: "  " })).rejects.toThrow(
				"pattern is required",
			);
			await expect(
				tool.execute("wasm-bad-3", { action: "search", path: file, pattern: "(", regex: true }),
			).rejects.toThrow("Invalid regular expression");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("wasm_inspect validation", () => {
	it("rejects missing files and non-WASM bytes", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-invalid-"));
		try {
			const tool = new WasmInspectTool(createTestSession(tempDir));
			await expect(tool.execute("wasm-missing", { action: "info", path: "missing.wasm" })).rejects.toThrow(
				"not found",
			);

			const invalid = path.join(tempDir, "invalid.wasm");
			await Bun.write(invalid, Buffer.from("not wasm"));
			await expect(tool.execute("wasm-invalid", { action: "info", path: invalid })).rejects.toThrow(
				"Not a WebAssembly module",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects truncated headers and section payloads", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-truncated-"));
		try {
			const tool = new WasmInspectTool(createTestSession(tempDir));
			const headerOnly = path.join(tempDir, "header.wasm");
			await Bun.write(headerOnly, new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
			await expect(tool.execute("wasm-header", { action: "info", path: headerOnly })).resolves.toBeDefined();

			const shortHeader = path.join(tempDir, "short.wasm");
			await Bun.write(shortHeader, new Uint8Array([0x00, 0x61]));
			await expect(tool.execute("wasm-short", { action: "info", path: shortHeader })).rejects.toThrow(
				"expected at least 8 header bytes",
			);

			const truncatedSection = path.join(tempDir, "section.wasm");
			await Bun.write(
				truncatedSection,
				new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x01]),
			);
			await expect(tool.execute("wasm-section", { action: "info", path: truncatedSection })).rejects.toThrow(
				"claims 10 bytes",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("wasm_inspect wat", () => {
	it("keeps an install hint when only wat2wasm is present", () => {
		const dependency = wabtDependency(command => (command === "wat2wasm" ? "/opt/wabt/wat2wasm" : null));
		expect(dependency.available).toBe(false);
		expect(dependency.installHint).toContain("wabt");
	});

	it("returns a structured install hint when wabt is absent", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-no-wabt-"));
		try {
			const file = await writeWasmFixture(tempDir);
			const tool = new WasmInspectTool(createTestSession(tempDir), { which: () => null });
			const result = await tool.execute("wasm-wat-missing", { action: "wat", path: file });
			const details = result.details as WasmInspectDetails;
			expect(details.status).toBe("missing_dependency");
			expect(details.dependency?.available).toBe(false);
			expect(details.dependency?.installHint).toContain("wabt");
			expect(textOf(result)).toContain("not available");
			expect(textOf(result)).toContain("info");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("runs wasm2wat and returns WAT", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-wat-"));
		try {
			const file = await writeWasmFixture(tempDir);
			const binary = await makeExecutable(tempDir, `printf '(module\\n  (export "add" (func 0))\\n)\\n'`);
			const tool = new WasmInspectTool(createTestSession(tempDir), { which: () => binary });
			const result = await tool.execute("wasm-wat", { action: "wat", path: file });
			const details = result.details as WasmInspectDetails;
			expect(details.status).toBe("ok");
			expect(details.dependency?.available).toBe(true);
			expect(details.truncated).toBe(false);
			expect(textOf(result)).toContain("(module");
			expect(textOf(result)).toContain('(export "add"');
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("caps WAT output and reports truncation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-wat-cap-"));
		try {
			const file = await writeWasmFixture(tempDir);
			const binary = await makeExecutable(
				tempDir,
				"i=0\nwhile [ $i -lt 200 ]; do printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n'; i=$((i+1)); done",
			);
			const tool = new WasmInspectTool(createTestSession(tempDir), { which: () => binary });
			const result = await tool.execute("wasm-wat-cap", { action: "wat", path: file, max_bytes: 100 });
			const details = result.details as WasmInspectDetails;
			expect(details.status).toBe("ok");
			expect(details.truncated).toBe(true);
			expect(details.outputBytes).toBe(100);
			expect(textOf(result)).toContain("WAT output truncated at 100 bytes");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns a structured error on timeout and nonzero exit", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "wasm-inspect-wat-errors-"));
		try {
			const file = await writeWasmFixture(tempDir);
			const slow = await makeExecutable(tempDir, "sleep 5");
			const slowTool = new WasmInspectTool(createTestSession(tempDir), { which: () => slow });
			const timedOut = await slowTool.execute("wasm-wat-timeout", {
				action: "wat",
				path: file,
				timeout: 0.1,
			});
			const timeoutDetails = timedOut.details as WasmInspectDetails;
			expect(timeoutDetails.status).toBe("error");
			expect(timeoutDetails.error).toContain("timed out");
			expect(textOf(timedOut)).toContain("timed out after 0.1s");

			const failing = await makeExecutable(tempDir, "echo 'bad module' >&2\nexit 2");
			const failingTool = new WasmInspectTool(createTestSession(tempDir), { which: () => failing });
			const failed = await failingTool.execute("wasm-wat-fail", { action: "wat", path: file });
			const failureDetails = failed.details as WasmInspectDetails;
			expect(failureDetails.status).toBe("error");
			expect(failureDetails.error).toContain("exit 2");
			expect(textOf(failed)).toContain("bad module");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

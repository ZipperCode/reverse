import { describe, expect, it } from "bun:test";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	decodeVLQ,
	sanitizeExtractionPath,
	SourcemapInspectTool,
	type SourcemapInspectDetails,
	type ToolSession,
} from "@rva/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@rva/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@rva/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

// Sample SourceMap v3 fixture
// Generated from:
// file: "src/auth/service.ts"
// line 1: const secret = "key123";
// line 2: export function verifyToken(tok: string) { return tok === secret; }
//
// Minified:
// const a="key123";function b(c){return c===a}
//
// Mappings: AAAA,SAASA,GAAI,CAAE,SAASA,GAAW,CAAC,CAAE,MAAO,CAAC,GAAI,CAAC
const SAMPLE_MAP_V3 = {
	version: 3,
	file: "bundle.min.js",
	sourceRoot: "",
	sources: ["src/auth/service.ts", "src/utils/crypto.ts"],
	sourcesContent: [
		'const secret = "key123";\nexport function verifyToken(tok: string) {\n  return tok === secret;\n}\n',
		'export function sha256(data: string) {\n  return "dummy-hash";\n}\n',
	],
	names: ["secret", "verifyToken", "tok", "sha256"],
	// Line 1:
	// AAAA: col 0 -> src 0, line 0, col 0
	// SAASA: col 9 -> src 0, line 0, col 9, name 0 ("secret")
	// GAAI: col 12 -> src 0, line 0, col 16
	mappings: "AAAA,SAASA,GAAI;AAAA",
};

describe("sourcemap_inspect discovery and registration", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes aliases", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("sourcemap_inspect");
		expect(normalizeToolName("sourcemap_inspect")).toBe("sourcemap_inspect");
		expect(normalizeToolName("sourcemap")).toBe("sourcemap_inspect");
		expect(normalizeToolName("sourcemap_recover")).toBe("sourcemap_inspect");
		expect(normalizeToolName("source_map_inspect")).toBe("sourcemap_inspect");
	});

	it("creates tool instance with discoverable loadMode and read approval", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["sourcemap_inspect"]);
			const tool = tools.find(t => t.name === "sourcemap_inspect");
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("sourcemap_inspect");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("sourcemap_inspect VLQ decoding unit tests", () => {
	it("correctly decodes standard base64 VLQ values", () => {
		// 0 -> 'A'
		const [v0, next0] = decodeVLQ("A", 0);
		expect(v0).toBe(0);
		expect(next0).toBe(1);

		// 1 -> 'C'
		const [v1] = decodeVLQ("C", 0);
		expect(v1).toBe(1);

		// -1 -> 'D'
		const [vNeg1] = decodeVLQ("D", 0);
		expect(vNeg1).toBe(-1);

		// 9 -> 'S' (value 18, positive)
		const [v9] = decodeVLQ("S", 0);
		expect(v9).toBe(9);

		// 16 -> 'gB' (0x20 in first byte, 1 in second)
		const [v16, next16] = decodeVLQ("gB", 0);
		expect(v16).toBe(16);
		expect(next16).toBe(2);

		// Multiple sequential VLQs
		const [first, idx1] = decodeVLQ("AAAA", 0);
		expect(first).toBe(0);
		const [second, idx2] = decodeVLQ("AAAA", idx1);
		expect(second).toBe(0);
		const [third, idx3] = decodeVLQ("AAAA", idx2);
		expect(third).toBe(0);
		const [fourth, idx4] = decodeVLQ("AAAA", idx3);
		expect(fourth).toBe(0);
		expect(idx4).toBe(4);
	});
});

describe("sourcemap_inspect action: info", () => {
	it("parses direct .map file and reports sources, names, and mappings stats", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-info-"));
		try {
			const mapPath = path.join(tempDir, "bundle.js.map");
			await fs.writeFile(mapPath, JSON.stringify(SAMPLE_MAP_V3, null, 2), "utf-8");

			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			const result = await tool.execute("call_info_1", {
				action: "info",
				path: "bundle.js.map",
			});

			expect(result.details?.action).toBe("info");
			expect(result.details?.version).toBe(3);
			expect(result.details?.detectedFrom).toBe("direct_map");
			expect(result.details?.sourcesCount).toBe(2);
			expect(result.details?.namesCount).toBe(4);
			expect(result.details?.hasSourcesContent).toBe(true);
			expect(result.details?.sourcesWithContentCount).toBe(2);
			expect(result.details?.sources).toContain("src/auth/service.ts");
			expect(result.details?.names).toContain("verifyToken");

			const outputText = textOf(result);
			expect(outputText).toContain("SourceMap Info: bundle.js.map");
			expect(outputText).toContain("src/auth/service.ts");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("resolves inline base64 sourceMappingURL in a .js file", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-inline-"));
		try {
			const b64Map = Buffer.from(JSON.stringify(SAMPLE_MAP_V3)).toString("base64");
			const jsContent = `const x = 1;\n//# sourceMappingURL=data:application/json;base64,${b64Map}\n`;
			const jsPath = path.join(tempDir, "app.min.js");
			await fs.writeFile(jsPath, jsContent, "utf-8");

			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			const result = await tool.execute("call_info_2", {
				action: "info",
				path: "app.min.js",
			});

			expect(result.details?.action).toBe("info");
			expect(result.details?.detectedFrom).toBe("inline_base64");
			expect(result.details?.sourcesCount).toBe(2);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("resolves relative file sourceMappingURL in a .js file", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-rel-"));
		try {
			const mapPath = path.join(tempDir, "bundle.map");
			await fs.writeFile(mapPath, JSON.stringify(SAMPLE_MAP_V3), "utf-8");

			const jsPath = path.join(tempDir, "bundle.js");
			await fs.writeFile(jsPath, 'var a=1;\n//# sourceMappingURL=bundle.map\n', "utf-8");

			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			const result = await tool.execute("call_info_3", {
				action: "info",
				path: "bundle.js",
			});

			expect(result.details?.action).toBe("info");
			expect(result.details?.detectedFrom).toBe("relative_file");
			expect(result.details?.sourcesCount).toBe(2);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("sourcemap_inspect action: lookup", () => {
	it("maps minified coordinates to original source location and context snippet", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-lookup-"));
		try {
			const mapPath = path.join(tempDir, "bundle.js.map");
			await fs.writeFile(mapPath, JSON.stringify(SAMPLE_MAP_V3), "utf-8");

			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			const result = await tool.execute("call_look_1", {
				action: "lookup",
				path: "bundle.js.map",
				line: 1,
				column: 0,
			});

			expect(result.details?.action).toBe("lookup");
			expect(result.details?.lookup?.generatedLine).toBe(1);
			expect(result.details?.lookup?.generatedColumn).toBe(0);
			expect(result.details?.lookup?.originalSource).toBe("src/auth/service.ts");
			expect(result.details?.lookup?.originalLine).toBe(1);
			expect(result.details?.lookup?.originalColumn).toBe(0);
			expect(result.details?.lookup?.sourceSnippet).toContain("const secret");
			expect(result.details?.lookup?.sourceSnippet).toContain(">");

			const outputText = textOf(result);
			expect(outputText).toContain("SourceMap Lookup: Line 1, Column 0");
			expect(outputText).toContain("src/auth/service.ts");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("resolves symbol name when mapped segment includes nameIndex", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-sym-"));
		try {
			const mapPath = path.join(tempDir, "bundle.js.map");
			await fs.writeFile(mapPath, JSON.stringify(SAMPLE_MAP_V3), "utf-8");

			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			const result = await tool.execute("call_look_2", {
				action: "lookup",
				path: "bundle.js.map",
				line: 1,
				column: 10, // matches segment SAASA (col 9, name 0 = "secret")
			});

			expect(result.details?.lookup?.originalName).toBe("secret");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("throws ToolError when line is out of mapped range", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-oob-"));
		try {
			const mapPath = path.join(tempDir, "bundle.js.map");
			await fs.writeFile(mapPath, JSON.stringify(SAMPLE_MAP_V3), "utf-8");

			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			await expect(
				tool.execute("call_look_oob", {
					action: "lookup",
					path: "bundle.js.map",
					line: 50,
					column: 0,
				}),
			).rejects.toThrow("exceeds total lines mapped");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("sourcemap_inspect action: extract", () => {
	it("extracts embedded original source files inline", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-ext-inline-"));
		try {
			const mapPath = path.join(tempDir, "bundle.js.map");
			await fs.writeFile(mapPath, JSON.stringify(SAMPLE_MAP_V3), "utf-8");

			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			const result = await tool.execute("call_ext_1", {
				action: "extract",
				path: "bundle.js.map",
			});

			expect(result.details?.action).toBe("extract");
			expect(result.details?.extracted?.totalExtracted).toBe(2);
			const files = result.details?.extracted?.files ?? [];
			expect(files.length).toBe(2);
			expect(files[0].source).toBe("src/auth/service.ts");
			expect(files[0].content).toContain("export function verifyToken");
			expect(files[1].source).toBe("src/utils/crypto.ts");
			expect(files[1].content).toContain("export function sha256");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("filters extracted sources by source_path substring", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-ext-filter-"));
		try {
			const mapPath = path.join(tempDir, "bundle.js.map");
			await fs.writeFile(mapPath, JSON.stringify(SAMPLE_MAP_V3), "utf-8");

			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			const result = await tool.execute("call_ext_2", {
				action: "extract",
				path: "bundle.js.map",
				source_path: "crypto",
			});

			expect(result.details?.extracted?.totalExtracted).toBe(1);
			expect(result.details?.extracted?.files[0].source).toBe("src/utils/crypto.ts");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("saves extracted files safely into destination_dir and prevents path traversal", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-ext-dir-"));
		try {
			const mapWithTraversal = {
				...SAMPLE_MAP_V3,
				sources: ["../../evil.ts", "webpack:///./src/clean.ts"],
				sourcesContent: ["const evil = true;", "const clean = true;"],
			};
			const mapPath = path.join(tempDir, "bundle.js.map");
			await fs.writeFile(mapPath, JSON.stringify(mapWithTraversal), "utf-8");

			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			const outDir = path.join(tempDir, "extracted-code");

			const result = await tool.execute("call_ext_3", {
				action: "extract",
				path: "bundle.js.map",
				destination_dir: outDir,
			});

			expect(result.details?.extracted?.totalExtracted).toBe(2);
			const cleanFile = path.join(outDir, "src", "clean.ts");
			const cleanExists = await fs.stat(cleanFile).then(() => true).catch(() => false);
			expect(cleanExists).toBe(true);

			// Path traversal check
			expect(sanitizeExtractionPath("../../evil.ts")).toBe("evil.ts");
			expect(sanitizeExtractionPath("webpack:///./src/foo.ts")).toBe("src/foo.ts");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("sourcemap_inspect error handling & security limits", () => {
	it("rejects remote URL target with informative error", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-err-url-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			await expect(
				tool.execute("call_url_err", {
					action: "info",
					path: "https://example.com/app.js.map",
				}),
			).rejects.toThrow("Remote URL targets are not permitted");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects non-existent file", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-err-404-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			await expect(
				tool.execute("call_404_err", {
					action: "info",
					path: "non-existent-file.map",
				}),
			).rejects.toThrow("Target file not found");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("throws ToolError when extracting from map with no sourcesContent", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sm-err-nocontent-"));
		try {
			const mapNoContent = {
				version: 3,
				file: "min.js",
				sources: ["foo.js"],
				mappings: "AAAA",
			};
			const mapPath = path.join(tempDir, "min.js.map");
			await fs.writeFile(mapPath, JSON.stringify(mapNoContent), "utf-8");

			const session = createTestSession(tempDir);
			const tool = new SourcemapInspectTool(session);
			await expect(
				tool.execute("call_nocontent", {
					action: "extract",
					path: "min.js.map",
				}),
			).rejects.toThrow("does not contain embedded 'sourcesContent'");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

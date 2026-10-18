import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	DroidascTool,
	type DroidascToolDetails,
	type DroidascRunner,
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

async function writeFakeApk(dir: string, name = "test.apk", content = "PK\x03\x04fake-apk-content"): Promise<string> {
	const filePath = path.join(dir, name);
	await fs.writeFile(filePath, content, "utf8");
	return filePath;
}

describe("droidasc registration and canonical naming", () => {
	it("is registered as a builtin tool name", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("droidasc");
	});

	it("normalizes android_analyze alias to droidasc", () => {
		expect(normalizeToolName("android_analyze")).toBe("droidasc");
		expect(normalizeToolName("ANDROID_ANALYZE")).toBe("droidasc");
		expect(normalizeToolName("droidasc")).toBe("droidasc");
	});

	it("instantiates droidasc via createTools", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["droidasc"]);
			const tool = tools.find(t => t.name === "droidasc");
			expect(tool).toBeDefined();
			expect(tool?.label).toBe("DroidASC");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("instantiates droidasc via android_analyze legacy alias", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-alias-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["android_analyze"]);
			const tool = tools.find(t => t.name === "droidasc");
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("droidasc");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("droidasc parameter and target validation", () => {
	it("rejects non-existent target files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-val-missing-"));
		try {
			const tool = new DroidascTool(createTestSession(tempDir));
			await expect(tool.execute("call-1", { op: "manifest", target: "does_not_exist.apk" })).rejects.toThrow(
				"Target file not found",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directories passed as target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-val-dir-"));
		try {
			const subDir = path.join(tempDir, "sub");
			await fs.mkdir(subDir);
			const tool = new DroidascTool(createTestSession(tempDir));
			await expect(tool.execute("call-2", { op: "manifest", target: subDir })).rejects.toThrow("Not a regular file");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects empty target string", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-val-empty-"));
		try {
			const tool = new DroidascTool(createTestSession(tempDir));
			await expect(tool.execute("call-3", { op: "manifest", target: "   " })).rejects.toThrow("target is required");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects raw .dex files with dexdump and jadx suggestion", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-val-dex-"));
		try {
			const dexPath = path.join(tempDir, "classes.dex");
			await fs.writeFile(dexPath, "dex\n035\x00fake-dex", "utf8");
			const tool = new DroidascTool(createTestSession(tempDir));
			await expect(tool.execute("call-dex", { op: "manifest", target: dexPath })).rejects.toThrow(
				"raw DEX file. droidasc requires an .apk package",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects .aab files with bundletool and jadx suggestion", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-val-aab-"));
		try {
			const aabPath = path.join(tempDir, "app.aab");
			await fs.writeFile(aabPath, "fake-aab-content", "utf8");
			const tool = new DroidascTool(createTestSession(tempDir));
			await expect(tool.execute("call-aab", { op: "manifest", target: aabPath })).rejects.toThrow(
				"Android App Bundle (.aab). droidasc requires an .apk package",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects non-.apk files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-val-nonapk-"));
		try {
			const zipPath = path.join(tempDir, "archive.zip");
			await fs.writeFile(zipPath, "fake-zip-content", "utf8");
			const tool = new DroidascTool(createTestSession(tempDir));
			await expect(tool.execute("call-zip", { op: "manifest", target: zipPath })).rejects.toThrow(
				"is not an .apk file",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("enforces query requirement for findrefs string search", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-val-findrefs-str-"));
		try {
			const file = await writeFakeApk(tempDir);
			const tool = new DroidascTool(createTestSession(tempDir));
			await expect(tool.execute("call-4", { op: "findrefs", target: file })).rejects.toThrow(
				"query is required for findrefs",
			);
			await expect(tool.execute("call-4b", { op: "findrefs", kind: "string", target: file })).rejects.toThrow(
				"query is required for findrefs",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("enforces query or class requirement for findrefs type search", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-val-findrefs-type-"));
		try {
			const file = await writeFakeApk(tempDir);
			const tool = new DroidascTool(createTestSession(tempDir));
			await expect(tool.execute("call-type", { op: "findrefs", kind: "type", target: file })).rejects.toThrow(
				"query (or class) is required for findrefs type search",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("enforces class or query requirement for findrefs extends and impl search", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-val-findrefs-ext-"));
		try {
			const file = await writeFakeApk(tempDir);
			const tool = new DroidascTool(createTestSession(tempDir));
			await expect(tool.execute("call-ext", { op: "findrefs", kind: "extends", target: file })).rejects.toThrow(
				"class (or query) is required for findrefs extends search",
			);
			await expect(tool.execute("call-impl", { op: "findrefs", kind: "impl", target: file })).rejects.toThrow(
				"class (or query) is required for findrefs impl search",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("enforces member or class requirement for findrefs method and field search", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-val-findrefs-mf-"));
		try {
			const file = await writeFakeApk(tempDir);
			const tool = new DroidascTool(createTestSession(tempDir));
			await expect(tool.execute("call-meth", { op: "findrefs", kind: "method", target: file })).rejects.toThrow(
				"findrefs method search requires at least a member name",
			);
			await expect(tool.execute("call-fld", { op: "findrefs", kind: "field", target: file })).rejects.toThrow(
				"findrefs field search requires at least a member name",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("enforces class requirement for getclass", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-val-getclass-"));
		try {
			const file = await writeFakeApk(tempDir);
			const tool = new DroidascTool(createTestSession(tempDir));
			await expect(tool.execute("call-5", { op: "getclass", target: file })).rejects.toThrow(
				"class is required for getclass",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("droidasc missing dependency and graceful degradation", () => {
	it("returns structured install hint and fallback notice for manifest operation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-dep-manifest-"));
		try {
			const file = await writeFakeApk(tempDir);
			const tool = new DroidascTool(createTestSession(tempDir), { which: () => null });
			const result = await tool.execute("call-dep-1", { op: "manifest", target: file });
			const details = result.details as DroidascToolDetails;

			expect(details.status).toBe("missing_dependency");
			expect(details.op).toBe("manifest");
			expect(details.dependency?.available).toBe(false);
			expect(details.dependency?.installHint).toContain("droidasc");
			expect(details.fallback?.suggestedFallback).toContain("aapt2 dump badging");
			expect(details.fallback?.activeFallback).toContain("aapt2 dump badging");
			expect(details.fallback?.executed).toBe(false);

			const outputText = textOf(result);
			expect(outputText).toContain("[Notice] Primary tool 'droidasc' not found on PATH");
			expect(outputText).toContain("Install hint:");
			expect(outputText).toContain("Suggested fallback command: aapt2 dump badging");
			expect(outputText).toContain("Fallback command was not executed automatically");
			expect(outputText).toContain("apktool d -s");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns structured fallback notice for findrefs operation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-dep-findrefs-"));
		try {
			const file = await writeFakeApk(tempDir);
			const tool = new DroidascTool(createTestSession(tempDir), { which: () => null });
			const result = await tool.execute("call-dep-2", {
				op: "findrefs",
				target: file,
				query: "secretKey",
			});
			const details = result.details as DroidascToolDetails;

			expect(details.status).toBe("missing_dependency");
			expect(details.op).toBe("findrefs");
			expect(details.fallback?.suggestedFallback).toContain("jadx");
			expect(details.fallback?.executed).toBe(false);
			expect(details.fallback?.alternatives.some(a => a.includes("secretKey"))).toBe(true);

			const outputText = textOf(result);
			expect(outputText).toContain("Suggested fallback command: jadx");
			expect(outputText).toContain("secretKey");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns structured fallback notice for getclass operation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-dep-getclass-"));
		try {
			const file = await writeFakeApk(tempDir);
			const tool = new DroidascTool(createTestSession(tempDir), { which: () => null });
			const result = await tool.execute("call-dep-3", {
				op: "getclass",
				target: file,
				class: "com.example.Auth",
			});
			const details = result.details as DroidascToolDetails;

			expect(details.status).toBe("missing_dependency");
			expect(details.op).toBe("getclass");
			expect(details.fallback?.suggestedFallback).toContain(
				'jadx -d ./artifacts/jadx_out --single-class "com.example.Auth"',
			);
			expect(details.fallback?.executed).toBe(false);

			const outputText = textOf(result);
			expect(outputText).toContain('jadx -d ./artifacts/jadx_out --single-class "com.example.Auth"');
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns structured fallback notice for listclass operation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-dep-listclass-"));
		try {
			const file = await writeFakeApk(tempDir);
			const tool = new DroidascTool(createTestSession(tempDir), { which: () => null });
			const result = await tool.execute("call-dep-4", {
				op: "listclass",
				target: file,
				prefix: "com.example",
			});
			const details = result.details as DroidascToolDetails;

			expect(details.status).toBe("missing_dependency");
			expect(details.op).toBe("listclass");
			expect(details.fallback?.suggestedFallback).toContain("dexdump -f");
			expect(details.fallback?.suggestedFallback).toContain("com.example");
			expect(details.fallback?.executed).toBe(false);

			const outputText = textOf(result);
			expect(outputText).toContain("Suggested fallback command: dexdump -f");
			expect(outputText).toContain("com.example");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("droidasc execution with simulated runner", () => {
	it("executes getmanifest subcommand and returns stdout", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-exec-manifest-"));
		try {
			const file = await writeFakeApk(tempDir);
			let capturedArgs: string[] = [];
			const mockRunner: DroidascRunner = async (_binary, args) => {
				capturedArgs = args;
				return {
					stdout: '<manifest package="com.example.test">\n  <activity name=".MainActivity" />\n</manifest>',
					stderr: "",
					exitCode: 0,
					outputBytes: 74,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			const result = await tool.execute("call-run-1", { op: "manifest", target: file });
			expect(capturedArgs).toEqual(["getmanifest", file]);

			const details = result.details as DroidascToolDetails;
			expect(details.status).toBe("ok");
			expect(details.op).toBe("manifest");
			expect(details.outputBytes).toBe(74);
			expect(details.truncated).toBe(false);

			const outputText = textOf(result);
			expect(outputText).toContain("droidasc manifest:");
			expect(outputText).toContain('<manifest package="com.example.test">');
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("supports getmanifest alias for op", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-exec-getmanifest-"));
		try {
			const file = await writeFakeApk(tempDir);
			let capturedArgs: string[] = [];
			const mockRunner: DroidascRunner = async (_binary, args) => {
				capturedArgs = args;
				return {
					stdout: "<manifest />",
					stderr: "",
					exitCode: 0,
					outputBytes: 12,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			const result = await tool.execute("call-run-alias", { op: "getmanifest", target: file });
			expect(capturedArgs).toEqual(["getmanifest", file]);
			const details = result.details as DroidascToolDetails;
			expect(details.op).toBe("manifest");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes findrefs with default kind: string", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-exec-findrefs-"));
		try {
			const file = await writeFakeApk(tempDir);
			let capturedArgs: string[] = [];
			const mockRunner: DroidascRunner = async (_binary, args) => {
				capturedArgs = args;
				return {
					stdout: 'Lcom/example/AuthManager;->verifyToken(Ljava/lang/String;)Z: string "api/v2/auth"',
					stderr: "",
					exitCode: 0,
					outputBytes: 78,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			const result = await tool.execute("call-run-2", {
				op: "findrefs",
				target: file,
				query: "api/v2/auth",
			});
			expect(capturedArgs).toEqual(["findrefs", file, "string", "api/v2/auth"]);

			const details = result.details as DroidascToolDetails;
			expect(details.status).toBe("ok");
			expect(details.kind).toBe("string");
			expect(textOf(result)).toContain("verifyToken");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes findrefs with explicit kind: string and pattern alias", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-exec-findrefs-pat-"));
		try {
			const file = await writeFakeApk(tempDir);
			let capturedArgs: string[] = [];
			const mockRunner: DroidascRunner = async (_binary, args) => {
				capturedArgs = args;
				return {
					stdout: "found pattern",
					stderr: "",
					exitCode: 0,
					outputBytes: 13,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			const result = await tool.execute("call-pat", {
				op: "findrefs",
				kind: "string",
				target: file,
				pattern: "patternSecret",
			});
			expect(capturedArgs).toEqual(["findrefs", file, "string", "patternSecret"]);
			const details = result.details as DroidascToolDetails;
			expect(details.status).toBe("ok");
			expect(details.kind).toBe("string");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes findrefs with kind: type", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-exec-type-"));
		try {
			const file = await writeFakeApk(tempDir);
			let capturedArgs: string[] = [];
			const mockRunner: DroidascRunner = async (_binary, args) => {
				capturedArgs = args;
				return {
					stdout: "type match",
					stderr: "",
					exitCode: 0,
					outputBytes: 10,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			const result = await tool.execute("call-type-run", {
				op: "findrefs",
				kind: "type",
				target: file,
				query: "com.poc.Main",
			});
			expect(capturedArgs).toEqual(["findrefs", file, "type", "com.poc.Main"]);
			const details = result.details as DroidascToolDetails;
			expect(details.kind).toBe("type");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes findrefs with kind: extends and impl", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-exec-extimpl-"));
		try {
			const file = await writeFakeApk(tempDir);
			let capturedArgs: string[] = [];
			const mockRunner: DroidascRunner = async (_binary, args) => {
				capturedArgs = args;
				return {
					stdout: "extends or impl match",
					stderr: "",
					exitCode: 0,
					outputBytes: 21,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			await tool.execute("call-ext-run", {
				op: "findrefs",
				kind: "extends",
				target: file,
				class: "android.app.Activity",
			});
			expect(capturedArgs).toEqual(["findrefs", file, "extends", "android.app.Activity"]);

			await tool.execute("call-impl-run", {
				op: "findrefs",
				kind: "impl",
				target: file,
				class: "android.os.IInterface",
			});
			expect(capturedArgs).toEqual(["findrefs", file, "impl", "android.os.IInterface"]);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes findrefs with kind: method and class with fuzzy_class / fuzzyClass", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-exec-method-"));
		try {
			const file = await writeFakeApk(tempDir);
			let capturedArgs: string[] = [];
			const mockRunner: DroidascRunner = async (_binary, args) => {
				capturedArgs = args;
				return {
					stdout: "method match",
					stderr: "",
					exitCode: 0,
					outputBytes: 12,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			// method with name, class, and fuzzy_class
			await tool.execute("call-m-1", {
				op: "findrefs",
				kind: "method",
				target: file,
				query: "onCreate",
				class: "com.poc.Main",
				fuzzy_class: true,
			});
			expect(capturedArgs).toEqual([
				"findrefs",
				file,
				"method",
				"onCreate",
				"--class",
				"com.poc.Main",
				"--fuzzy-class",
			]);

			// method with name and class (without fuzzy)
			await tool.execute("call-m-2", {
				op: "findrefs",
				kind: "method",
				target: file,
				query: "onCreate",
				class: "com.poc.Main",
			});
			expect(capturedArgs).toEqual(["findrefs", file, "method", "onCreate", "--class", "com.poc.Main"]);

			// method with fuzzyClass alias and name alias
			await tool.execute("call-m-3", {
				op: "findrefs",
				kind: "method",
				target: file,
				name: "notify",
				className: "MainActivity",
				fuzzyClass: true,
			});
			expect(capturedArgs).toEqual([
				"findrefs",
				file,
				"method",
				"notify",
				"--class",
				"MainActivity",
				"--fuzzy-class",
			]);

			// method with name only
			await tool.execute("call-m-4", {
				op: "findrefs",
				kind: "method",
				target: file,
				query: "onCreate",
			});
			expect(capturedArgs).toEqual(["findrefs", file, "method", "onCreate"]);

			// method with class only
			await tool.execute("call-m-5", {
				op: "findrefs",
				kind: "method",
				target: file,
				class: "com.poc.Main",
			});
			expect(capturedArgs).toEqual(["findrefs", file, "method", "--class", "com.poc.Main"]);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes findrefs with kind: field", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-exec-field-"));
		try {
			const file = await writeFakeApk(tempDir);
			let capturedArgs: string[] = [];
			const mockRunner: DroidascRunner = async (_binary, args) => {
				capturedArgs = args;
				return {
					stdout: "field match",
					stderr: "",
					exitCode: 0,
					outputBytes: 11,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			await tool.execute("call-f-1", {
				op: "findrefs",
				kind: "field",
				target: file,
				query: "apiKey",
			});
			expect(capturedArgs).toEqual(["findrefs", file, "field", "apiKey"]);

			await tool.execute("call-f-2", {
				op: "findrefs",
				kind: "field",
				target: file,
				query: "token",
				class: "com.poc.Main",
			});
			expect(capturedArgs).toEqual(["findrefs", file, "field", "token", "--class", "com.poc.Main"]);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes listclass subcommand without and with prefix", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-exec-listclass-"));
		try {
			const file = await writeFakeApk(tempDir);
			let capturedArgs: string[] = [];
			const mockRunner: DroidascRunner = async (_binary, args) => {
				capturedArgs = args;
				return {
					stdout: "Lcom/poc/Main;\nLcom/poc/Auth;\n",
					stderr: "",
					exitCode: 0,
					outputBytes: 30,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			const result1 = await tool.execute("call-list-1", { op: "listclass", target: file });
			expect(capturedArgs).toEqual(["listclass", file]);
			const details1 = result1.details as DroidascToolDetails;
			expect(details1.status).toBe("ok");
			expect(details1.op).toBe("listclass");
			expect(textOf(result1)).toContain("Lcom/poc/Main;");

			const result2 = await tool.execute("call-list-2", {
				op: "listclass",
				target: file,
				prefix: "com.poc",
			});
			expect(capturedArgs).toEqual(["listclass", file, "--prefix", "com.poc"]);
			const details2 = result2.details as DroidascToolDetails;
			expect(details2.status).toBe("ok");
			expect(details2.op).toBe("listclass");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes getclass with class argument and supports className alias", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-exec-getclass-"));
		try {
			const file = await writeFakeApk(tempDir);
			let capturedArgs: string[] = [];
			const mockRunner: DroidascRunner = async (_binary, args) => {
				capturedArgs = args;
				return {
					stdout:
						"package com.example;\npublic class AuthManager {\n  public boolean verify() { return true; }\n}",
					stderr: "",
					exitCode: 0,
					outputBytes: 85,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			const result = await tool.execute("call-run-3", {
				op: "getclass",
				target: file,
				className: "com/example/AuthManager",
			});
			expect(capturedArgs).toEqual(["getclass", file, "com/example/AuthManager"]);

			const details = result.details as DroidascToolDetails;
			expect(details.status).toBe("ok");
			expect(textOf(result)).toContain("public class AuthManager");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("handles output truncation as success when stdout reaches cap and child is killed (non-zero exitCode)", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-truncation-killed-"));
		try {
			const file = await writeFakeApk(tempDir);
			const mockRunner: DroidascRunner = async () => {
				// When process is killed on overflow, exitCode is non-zero (e.g. 143 / SIGTERM)
				return {
					stdout: "truncated output buffer captured up to max_bytes...",
					stderr: "",
					exitCode: 143,
					outputBytes: 52,
					truncated: true,
					timedOut: false,
					killedOnOverflow: true,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			const result = await tool.execute("call-trunc", { op: "manifest", target: file, max_bytes: 50 });
			const details = result.details as DroidascToolDetails;
			expect(details.status).toBe("ok");
			expect(details.truncated).toBe(true);
			expect(details.outputBytes).toBe(52);
			const text = textOf(result);
			expect(text).toContain("droidasc manifest:");
			expect(text).toContain("(52 bytes, truncated)");
			expect(text).toContain("output truncated at 50 bytes");
			expect(text).not.toContain("droidasc failed");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("handles process timeout cleanly", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-timeout-"));
		try {
			const file = await writeFakeApk(tempDir);
			const mockRunner: DroidascRunner = async () => {
				return {
					stdout: "",
					stderr: "",
					exitCode: 0,
					outputBytes: 0,
					truncated: false,
					timedOut: true,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			const result = await tool.execute("call-timeout", { op: "manifest", target: file, timeout: 5 });
			const details = result.details as DroidascToolDetails;
			expect(details.status).toBe("error");
			expect(details.error).toContain("timed out after 5s");
			expect(textOf(result)).toContain("timed out after 5s");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("handles process failure and non-zero exit code with stderr", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-fail-"));
		try {
			const file = await writeFakeApk(tempDir);
			const mockRunner: DroidascRunner = async () => {
				return {
					stdout: "",
					stderr: "Error: Malformed DEX header",
					exitCode: 1,
					outputBytes: 0,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
				runner: mockRunner,
			});

			const result = await tool.execute("call-fail", { op: "manifest", target: file });
			const details = result.details as DroidascToolDetails;
			expect(details.status).toBe("error");
			expect(details.error).toContain("exit 1");
			expect(details.error).toContain("Malformed DEX header");
			expect(textOf(result)).toContain("droidasc failed (exit 1)");
			expect(textOf(result)).toContain("Malformed DEX header");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("respects AbortSignal before and during execution", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "droidasc-abort-"));
		try {
			const file = await writeFakeApk(tempDir);
			const tool = new DroidascTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/droidasc",
			});

			const controller = new AbortController();
			controller.abort();
			await expect(tool.execute("call-abort", { op: "manifest", target: file }, controller.signal)).rejects.toThrow(
				"Operation aborted",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

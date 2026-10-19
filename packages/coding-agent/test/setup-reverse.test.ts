import { describe, expect, it, vi } from "bun:test";
import { checkReverseTools, detectPackageManagers, handleReverseSetup } from "../src/cli/setup-reverse";
import {
	getReverseTool,
	getReverseTools,
	SKILL_TOOL_CATALOG,
	resolveReverseCapabilities,
} from "../src/extensibility/skill-tool-catalog";
import type { SkillRequirementWhich } from "../src/extensibility/skill-requirements";
import { afterEach, beforeEach } from "bun:test";

let originalRvaLang: string | undefined;
beforeEach(() => {
	originalRvaLang = process.env.REVERSE_LANG;
	process.env.REVERSE_LANG = "en";
});
afterEach(() => {
	if (originalRvaLang !== undefined) process.env.REVERSE_LANG = originalRvaLang;
	else delete process.env.REVERSE_LANG;
});

function mockWhich(lookup: Record<string, string | null>): SkillRequirementWhich {
	return command => lookup[command] ?? null;
}

describe("Reverse toolchain catalog", () => {
	it("contains all required tools for the reverse toolchain", () => {
		const requiredToolIds = [
			"strings",
			"file",
			"jadx",
			"apktool",
			"adb",
			"frida",
			"droidasc",
			"radare2",
			"ida",
			"ast-grep",
			"wabt",
			"upx",
			"aapt2",
			"zipalign",
			"apksigner",
			"dexdump",
			"hermes-dec",
			"hbctool",
			"il2cppdumper",
			"wasm-tools",
			"readelf",
			"mitmproxy",
			"tshark",
			"unidbg",
			"bundletool",
			"dex2jar",
			"baksmali",
			"scrcpy",
			"java",
		];

		for (const id of requiredToolIds) {
			const tool = SKILL_TOOL_CATALOG[id];
			expect(tool).toBeDefined();
			expect(tool?.id).toBe(id);
			expect(tool?.name).toBeDefined();
			expect(tool?.category).toBeDefined();
			expect(tool?.description).toBeDefined();
			expect(tool?.manualUrl).toBeDefined();
		}
	});

	it("differentiates required system tools from optional reverse tools", () => {
		expect(SKILL_TOOL_CATALOG.strings.optional).toBe(false);
		expect(SKILL_TOOL_CATALOG.strings.systemTool).toBe(true);
		expect(SKILL_TOOL_CATALOG.file.optional).toBe(false);
		expect(SKILL_TOOL_CATALOG.file.systemTool).toBe(true);

		expect(SKILL_TOOL_CATALOG.jadx.optional).toBe(true);
		expect(SKILL_TOOL_CATALOG.radare2.optional).toBe(true);
		expect(SKILL_TOOL_CATALOG.frida.optional).toBe(true);
		expect(SKILL_TOOL_CATALOG.upx.optional).toBe(true);
		expect(SKILL_TOOL_CATALOG.apktool.optional).toBe(true);
	});

	it("looks up tools via helper functions case-insensitively", () => {
		expect(getReverseTool("jadx")).toBe(SKILL_TOOL_CATALOG.jadx);
		expect(getReverseTool("JADX")).toBe(SKILL_TOOL_CATALOG.jadx);
		expect(getReverseTool("nonexistent")).toBeUndefined();
		expect(getReverseTools().length).toBeGreaterThanOrEqual(20);
	});

	it("contains unidbg and Android companion tools with proper descriptors", () => {
		const unidbg = SKILL_TOOL_CATALOG.unidbg;
		expect(unidbg).toBeDefined();
		expect(unidbg.category).toBe("android");
		expect(unidbg.optional).toBe(true);
		expect(unidbg.binaries).toContain("unidbg");
		expect(unidbg.secondary).toContain("java");
		expect(unidbg.usage?.canonical).toContain("unidbg");

		const bundletool = SKILL_TOOL_CATALOG.bundletool;
		expect(bundletool).toBeDefined();
		expect(bundletool.category).toBe("android");

		const dex2jar = SKILL_TOOL_CATALOG.dex2jar;
		expect(dex2jar).toBeDefined();
		expect(dex2jar.category).toBe("android");

		const baksmali = SKILL_TOOL_CATALOG.baksmali;
		expect(baksmali).toBeDefined();
		expect(baksmali.category).toBe("android");

		const scrcpy = SKILL_TOOL_CATALOG.scrcpy;
		expect(scrcpy).toBeDefined();
		expect(scrcpy.category).toBe("android");
	});
});

describe("Package manager detection", () => {
	it("detects installed package managers on darwin", () => {
		const which = mockWhich({ brew: "/opt/homebrew/bin/brew", pipx: "/usr/local/bin/pipx" });
		const detected = detectPackageManagers("darwin", which);
		expect(detected).toContain("brew");
		expect(detected).toContain("pipx");
		expect(detected).not.toContain("apt");
	});

	it("detects installed package managers on linux", () => {
		const which = mockWhich({ apt: "/usr/bin/apt", npm: "/usr/bin/npm" });
		const detected = detectPackageManagers("linux", which);
		expect(detected).toContain("apt");
		expect(detected).toContain("npm");
		expect(detected).not.toContain("brew");
	});

	it("detects installed package managers on win32", () => {
		const which = mockWhich({ choco: "C:\\ProgramData\\chocolatey\\bin\\choco.exe" });
		const detected = detectPackageManagers("win32", which);
		expect(detected).toContain("choco");
		expect(detected).not.toContain("brew");
	});
});

describe("checkReverseTools", () => {
	it("correctly marks found tools as installed and resolves missing tool commands", () => {
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
			jadx: "/opt/homebrew/bin/jadx",
			java: "/usr/bin/java",
		});

		const report = checkReverseTools({
			platform: "darwin",
			which,
		});

		expect(report.platform).toBe("darwin");
		expect(report.detectedPackageManagers).toContain("brew");

		const jadx = report.tools.find(t => t.id === "jadx");
		expect(jadx).toBeDefined();
		expect(jadx?.status).toBe("installed");
		expect(jadx?.foundPath).toBe("/opt/homebrew/bin/jadx");

		const apktool = report.tools.find(t => t.id === "apktool");
		expect(apktool).toBeDefined();
		expect(apktool?.status).toBe("missing");
		expect(apktool?.packageManager).toBe("brew");
		expect(apktool?.installCommand).toBe("brew install apktool");
		expect(apktool?.installArgv).toEqual(["brew", "install", "apktool"]);

		// Required tools (strings, file) are present, so ok is true
		expect(report.ok).toBe(true);
		expect(report.missingRequired).toHaveLength(0);
		expect(report.missingOptional).toContain("apktool");
	});

	it("fails report.ok when a required tool is missing", () => {
		const which = mockWhich({
			// strings missing
			file: "/usr/bin/file",
		});

		const report = checkReverseTools({
			platform: "linux",
			which,
		});

		expect(report.ok).toBe(false);
		expect(report.missingRequired).toContain("strings");
	});

	it("handles missing package managers by leaving installCommand null and providing manual instructions", () => {
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			// No brew, apt, or choco
		});

		const report = checkReverseTools({
			platform: "darwin",
			which,
		});

		const radare2 = report.tools.find(t => t.id === "radare2");
		expect(radare2?.status).toBe("missing");
		expect(radare2?.packageManager).toBeNull();
		expect(radare2?.installCommand).toBeNull();
		expect(radare2?.installArgv).toBeNull();
		expect(radare2?.manualUrl).toContain("github.com/radareorg/radare2");
		expect(radare2?.manualInstructions).toBeDefined();
	});

	it("keeps commercial IDA Pro as manual instructions without automated command", () => {
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
		});

		const report = checkReverseTools({
			platform: "darwin",
			which,
		});

		const ida = report.tools.find(t => t.id === "ida");
		expect(ida?.status).toBe("missing");
		expect(ida?.installArgv).toBeNull();
		expect(ida?.manualUrl).toBe("https://hex-rays.com/ida-pro/");
		expect(ida?.manualInstructions).toContain("Commercial software");
	});
});

describe("handleReverseSetup non-interactive modes", () => {
	it("outputs structured JSON report with --json flag", async () => {
		let output = "";
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
		});

		const code = await handleReverseSetup({ json: true }, undefined, {
			platform: "darwin",
			which,
			writeStdout: text => {
				output += text;
			},
		});

		expect(code).toBe(0);
		const parsed = JSON.parse(output);
		expect(parsed.ok).toBe(true);
		expect(parsed.platform).toBe("darwin");
		expect(Array.isArray(parsed.tools)).toBe(true);
		expect(parsed.tools.length).toBeGreaterThanOrEqual(20);
	});

	it("exits 0 on --check when required tools are present", async () => {
		let output = "";
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
		});

		const code = await handleReverseSetup({ check: true }, undefined, {
			platform: "darwin",
			which,
			writeStdout: text => {
				output += text;
			},
		});
		expect(code).toBe(0);
		expect(output).toContain("Reverse engineering toolchain catalog overview");
		expect(output).toContain("[ok] strings");
	});

	it("exits 1 on --check when required tools are missing", async () => {
		let errOutput = "";
		const which = mockWhich({
			// strings and file missing
			brew: "/opt/homebrew/bin/brew",
		});

		const code = await handleReverseSetup({ check: true }, undefined, {
			platform: "darwin",
			which,
			writeStdout: () => {},
			writeStderr: text => {
				errOutput += text;
			},
		});

		expect(code).toBe(1);
		expect(errOutput).toContain("Missing required system tools");
	});

	it("renders Chinese localized text when REVERSE_LANG is zh-CN", async () => {
		process.env.REVERSE_LANG = "zh-CN";
		let output = "";
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
		});

		const code = await handleReverseSetup({ check: true }, undefined, {
			platform: "darwin",
			which,
			writeStdout: text => {
				output += text;
			},
		});

		expect(code).toBe(0);
		expect(output).toContain("逆向工程工具链检测概览：");
		expect(output).toContain("核心系统工具已就绪");
	});

	it("ensures --json and --check are strictly read-only and never trigger execution or prompts", async () => {
		const executorSpy = vi.fn(async () => ({ exitCode: 0, stdout: "", stderr: "" }));
		const confirmSpy = vi.fn(async () => true);
		const promptSpy = vi.fn(async () => "jadx");
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
		});

		// 1. --json mode
		const jsonCode = await handleReverseSetup({ json: true }, "jadx", {
			platform: "darwin",
			which,
			executor: executorSpy,
			confirm: confirmSpy,
			promptLine: promptSpy,
			writeStdout: () => {},
		});
		expect(jsonCode).toBe(0);
		expect(executorSpy).not.toHaveBeenCalled();
		expect(confirmSpy).not.toHaveBeenCalled();
		expect(promptSpy).not.toHaveBeenCalled();

		// 2. --check mode
		const checkCode = await handleReverseSetup({ check: true }, "jadx", {
			platform: "darwin",
			which,
			executor: executorSpy,
			confirm: confirmSpy,
			promptLine: promptSpy,
			writeStdout: () => {},
		});
		expect(checkCode).toBe(0);
		expect(executorSpy).not.toHaveBeenCalled();
		expect(confirmSpy).not.toHaveBeenCalled();
		expect(promptSpy).not.toHaveBeenCalled();

		// 3. --check --json mode
		const checkJsonCode = await handleReverseSetup({ check: true, json: true }, "jadx", {
			platform: "darwin",
			which,
			executor: executorSpy,
			confirm: confirmSpy,
			promptLine: promptSpy,
			writeStdout: () => {},
		});
		expect(checkJsonCode).toBe(0);
		expect(executorSpy).not.toHaveBeenCalled();
		expect(confirmSpy).not.toHaveBeenCalled();
		expect(promptSpy).not.toHaveBeenCalled();
	});
});

describe("handleReverseSetup interactive selection and manual inspection", () => {
	it("defaults to manual inspection mode without execution unless --execute is specified", async () => {
		let output = "";
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
		});

		const executorSpy = vi.fn(async () => ({ exitCode: 0, stdout: "", stderr: "" }));
		const confirmSpy = vi.fn(async () => true);

		const code = await handleReverseSetup({}, "jadx", {
			platform: "darwin",
			which,
			isTTY: true,
			executor: executorSpy,
			confirm: confirmSpy,
			writeStdout: text => {
				output += text;
			},
		});

		expect(code).toBe(0);
		// Verified: Default panel does NOT execute subprocesses or ask to execute!
		expect(executorSpy).not.toHaveBeenCalled();
		expect(confirmSpy).not.toHaveBeenCalled();
		expect(output).toContain("Recommended installation command:");
		expect(output).toContain("brew install jadx");
		expect(output).toContain("Manual setup:");
		expect(output).toContain("https://github.com/skylot/jadx/releases");
		expect(output).toContain("Manual mode");
	});

	it("rejects --execute in non-TTY environments with non-zero exit code", async () => {
		let errOutput = "";
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
		});

		const executorSpy = vi.fn(async () => ({ exitCode: 0, stdout: "", stderr: "" }));

		const code = await handleReverseSetup({ execute: true }, "jadx", {
			platform: "darwin",
			which,
			isTTY: false,
			executor: executorSpy,
			writeStdout: () => {},
			writeStderr: text => {
				errOutput += text;
			},
		});

		expect(code).toBe(1);
		expect(executorSpy).not.toHaveBeenCalled();
		expect(errOutput).toContain("requires an interactive TTY");
	});

	it("executes installation command strictly from catalog after user confirmation when --execute is passed", async () => {
		let output = "";
		const installedBinaries: Record<string, string | null> = {
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
			jadx: null,
			java: "/usr/bin/java",
		};
		const which = mockWhich(installedBinaries);

		const executorSpy = vi.fn(async (_argv: readonly string[]) => {
			// Simulate successful install of jadx
			installedBinaries.jadx = "/opt/homebrew/bin/jadx";
			return { exitCode: 0, stdout: "Installed jadx", stderr: "" };
		});

		const confirmSpy = vi.fn(async () => true);

		const code = await handleReverseSetup({ execute: true }, "jadx", {
			platform: "darwin",
			which,
			isTTY: true,
			executor: executorSpy,
			confirm: confirmSpy,
			writeStdout: text => {
				output += text;
			},
		});

		expect(code).toBe(0);
		expect(confirmSpy).toHaveBeenCalledTimes(1);
		expect(executorSpy).toHaveBeenCalledTimes(1);
		expect(executorSpy).toHaveBeenCalledWith(["brew", "install", "jadx"], expect.any(Object));
		expect(output).toContain("Installation command finished successfully");
		expect(output).toContain("Verified: JADX (Dex to Java decompiler) is now available");
	});

	it("aborts execution when user rejects confirmation in --execute mode", async () => {
		let output = "";
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
		});

		const executorSpy = vi.fn(async () => ({ exitCode: 0, stdout: "", stderr: "" }));
		const confirmSpy = vi.fn(async () => false);

		const code = await handleReverseSetup({ execute: true }, "apktool", {
			platform: "darwin",
			which,
			isTTY: true,
			executor: executorSpy,
			confirm: confirmSpy,
			writeStdout: text => {
				output += text;
			},
		});

		expect(code).toBe(0);
		expect(confirmSpy).toHaveBeenCalledTimes(1);
		expect(executorSpy).not.toHaveBeenCalled();
		expect(output).toContain("Installation cancelled for Apktool");
	});

	it("returns exit code 1 when executor fails in --execute mode", async () => {
		let output = "";
		let errOutput = "";
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
		});

		const executorSpy = vi.fn(async () => ({
			exitCode: 127,
			stdout: "",
			stderr: "brew: command failed: permission denied",
		}));

		const confirmSpy = vi.fn(async () => true);
		const code = await handleReverseSetup({ execute: true }, "apktool", {
			platform: "darwin",
			which,
			isTTY: true,
			confirm: confirmSpy,
			executor: executorSpy,
			writeStdout: text => {
				output += text;
			},
			writeStderr: text => {
				errOutput += text;
			},
		});

		expect(code).toBe(1);
		expect(executorSpy).toHaveBeenCalledTimes(1);
		expect(errOutput).toContain("Installation command failed with exit code 127");
		expect(output).toContain("https://github.com/iBotPeaches/Apktool/releases");
	});

	it("displays manual instructions when attempting to install a tool without compatible package manager", async () => {
		let output = "";
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			// No package manager
		});

		const executorSpy = vi.fn(async () => ({ exitCode: 0, stdout: "", stderr: "" }));

		const code = await handleReverseSetup({}, "radare2", {
			platform: "darwin",
			which,
			executor: executorSpy,
			writeStdout: text => {
				output += text;
			},
		});

		expect(code).toBe(0);
		expect(executorSpy).not.toHaveBeenCalled();
		expect(output).toContain("No compatible package manager");
		expect(output).toContain("https://github.com/radareorg/radare2/releases");
	});

	it("supports multiple tool selection and quits on 'q'", async () => {
		let output = "";
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
		});

		const promptSpy = vi.fn(async () => "q");
		const executorSpy = vi.fn(async () => ({ exitCode: 0, stdout: "", stderr: "" }));

		const code = await handleReverseSetup({}, undefined, {
			platform: "darwin",
			which,
			promptLine: promptSpy,
			executor: executorSpy,
			writeStdout: text => {
				output += text;
			},
		});

		expect(code).toBe(0);
		expect(promptSpy).toHaveBeenCalledTimes(1);
		expect(executorSpy).not.toHaveBeenCalled();
		expect(output).toContain("Setup panel closed");
	});

	it("resolves capabilities correctly with synthetic MCP and CLI statuses", () => {
		// Case 1: Node is installed, but playwright-mcp is unconfigured
		const syntheticUnconfigured = resolveReverseCapabilities({
			platform: "darwin",
			toolStatuses: [
				{ id: "node", status: "installed" },
				{ id: "java", status: "installed" },
				{ id: "curl", status: "installed" },
				{ id: "file", status: "installed" },
			],
			serviceStatuses: [
				{
					id: "playwright-mcp",
					name: "Playwright MCP",
					prerequisitesReady: true,
					ready: true,
					configured: false,
					enabled: null,
					connection: "unknown",
				},
			],
		});

		const browserCap = syntheticUnconfigured.find(c => c.id === "browser_debugger");
		expect(browserCap).toBeDefined();
		// Node alone MUST NOT make browser_debugger ready!
		expect(browserCap?.ready).toBe(false);
		expect(browserCap?.status).toBe("available_with_fallbacks");
		expect(browserCap?.optionalExternalTools[0]?.id).toBe("playwright-mcp");
		expect(browserCap?.optionalExternalTools[0]?.status).toBe("unconfigured");
		expect(browserCap?.optionalExternalTools[0]?.connection).toBe("unknown");

		// Java alone MUST NOT make android_native_emulation ready!
		const androidCap = syntheticUnconfigured.find(c => c.id === "android_native_emulation");
		expect(androidCap).toBeDefined();
		expect(androidCap?.ready).toBe(false);
		expect(androidCap?.status).toBe("available_with_fallbacks");

		// Case 2: playwright-mcp is configured and enabled in mcp.json, but connection is unknown
		const syntheticConfiguredUnknown = resolveReverseCapabilities({
			platform: "darwin",
			toolStatuses: [{ id: "node", status: "installed" }],
			serviceStatuses: [
				{
					id: "playwright-mcp",
					name: "Playwright MCP",
					prerequisitesReady: true,
					ready: true,
					configured: true,
					enabled: true,
					connection: "unknown",
				},
			],
		});

		const browserCapConfigured = syntheticConfiguredUnknown.find(c => c.id === "browser_debugger");
		expect(browserCapConfigured?.ready).toBe(false);
		expect(browserCapConfigured?.status).toBe("available_with_fallbacks");
		expect(browserCapConfigured?.optionalExternalTools[0]?.status).toBe("configured");
		expect(browserCapConfigured?.optionalExternalTools[0]?.connection).toBe("unknown");

		// Case 3: playwright-mcp has verified connection handshake
		const syntheticConnected = resolveReverseCapabilities({
			platform: "darwin",
			toolStatuses: [{ id: "node", status: "installed" }],
			serviceStatuses: [
				{
					id: "playwright-mcp",
					name: "Playwright MCP",
					prerequisitesReady: true,
					ready: true,
					configured: true,
					enabled: true,
					connection: "connected",
				},
			],
		});

		const browserCapConnected = syntheticConnected.find(c => c.id === "browser_debugger");
		expect(browserCapConnected?.ready).toBe(true);
		expect(browserCapConnected?.status).toBe("ready");
		expect(browserCapConnected?.optionalExternalTools[0]?.status).toBe("ready");
		expect(browserCapConnected?.optionalExternalTools[0]?.connection).toBe("connected");
	});
});

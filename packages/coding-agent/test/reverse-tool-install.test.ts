import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
	applyPersistedReverseEnvironment,
	canInstallReverseItem,
	getReverseInstallPlan,
	installReverseItem,
	persistToolEnvironment,
	resolveJavaHomeFromBinary,
} from "../src/extensibility/reverse-tool-install";
import {
	checkReverseTools,
	type ReverseCheckReport,
	type ReverseServiceStatus,
	type ReverseToolStatus,
} from "../src/cli/setup-reverse";

describe("reverse-tool-install shared API", () => {
	let tempDir: string;
	let originalEnv: NodeJS.ProcessEnv;
	let originalBunEnvPath: string | undefined;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "reverse-tool-install-test-"));
		originalEnv = { ...process.env };
		originalBunEnvPath = Bun.env.PATH;
	});

	afterEach(async () => {
		for (const key of Object.keys(process.env)) {
			if (!(key in originalEnv)) {
				delete process.env[key];
			}
		}
		for (const [key, value] of Object.entries(originalEnv)) {
			if (value !== undefined) {
				process.env[key] = value;
			}
		}
		if (originalBunEnvPath !== undefined) Bun.env.PATH = originalBunEnvPath;
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	describe("canInstallReverseItem", () => {
		it("returns true for tools with a catalog installArgv", () => {
			const tool: ReverseToolStatus = {
				kind: "cli",
				id: "jadx",
				name: "JADX",
				category: "decompiler",
				description: "Dex to Java decompiler",
				optional: true,
				systemTool: false,
				status: "missing",
				foundPath: null,
				packageManager: "brew",
				installCommand: "brew install jadx",
				installArgv: ["brew", "install", "jadx"],
				riskNote: null,
				manualUrl: "https://github.com/skylot/jadx",
				manualInstructions: "Install via brew install jadx",
			};
			expect(canInstallReverseItem(tool)).toBe(true);
		});

		it("returns false for manual-only tools with no installArgv (e.g. IDA Pro)", () => {
			const ida: ReverseToolStatus = {
				kind: "cli",
				id: "ida",
				name: "IDA Pro",
				category: "decompiler",
				description: "Interactive Disassembler",
				optional: true,
				systemTool: false,
				status: "missing",
				foundPath: null,
				packageManager: null,
				installCommand: null,
				installArgv: null,
				riskNote: null,
				manualUrl: "https://hex-rays.com/ida-pro/",
				manualInstructions: "Commercial license required.",
			};
			expect(canInstallReverseItem(ida)).toBe(false);
		});

		it("returns true for managed jshookmcp and configurable MCP services", () => {
			const jshook: ReverseServiceStatus = {
				kind: "mcp",
				id: "jshookmcp",
				name: "jshook MCP",
				category: "web",
				description: "JS analysis MCP",
				optional: true,
				license: "AGPL-3.0",
				serverName: "jshook",
				transport: "stdio",
				startCommand: "node dist/index.mjs",
				configPath: ".reverse/mcp.json",
				configPaths: { project: ".reverse/mcp.json", user: "agent/mcp.json" },
				configSnippet: {},
				prerequisites: [],
				missingPrerequisites: [],
				prerequisitesReady: true,
				ready: false,
				configured: false,
				configuredScopes: [],
				enabled: null,
				connection: "unknown",
				status: "missing",
				packageManager: "npm",
				installCommand: "npm install",
				installArgv: ["npm", "install"],
				installer: "jshookmcp",
				installed: false,
				riskNote: "",
				manualUrl: "",
				manualInstructions: "",
				usage: { canonical: "jshook", whenToUse: "js analysis", examples: [] },
			};
			expect(canInstallReverseItem(jshook)).toBe(true);

			const playwright: ReverseServiceStatus = {
				...jshook,
				id: "playwright-mcp",
				installer: undefined,
				installArgv: null,
			};
			expect(canInstallReverseItem(playwright)).toBe(true);
		});
	});

	describe("getReverseInstallPlan", () => {
		it("orders missing secondary dependencies before target tool", () => {
			const jadxStatus: ReverseToolStatus = {
				kind: "cli",
				id: "jadx",
				name: "JADX",
				category: "decompiler",
				description: "Dex to Java decompiler",
				optional: true,
				systemTool: false,
				status: "missing",
				foundPath: null,
				secondaryMissing: ["java"],
				packageManager: "brew",
				installCommand: "brew install jadx",
				installArgv: ["brew", "install", "jadx"],
				riskNote: null,
				manualUrl: "https://github.com/skylot/jadx",
				manualInstructions: "Install via brew install jadx",
			};

			const mockWhich = (cmd: string) => {
				if (cmd === "brew") return "/opt/homebrew/bin/brew";
				return null;
			};

			const plan = getReverseInstallPlan(jadxStatus, {
				which: mockWhich,
				platform: "darwin",
				agentDir: tempDir,
			});

			expect(plan.canInstall).toBe(true);
			expect(plan.steps.length).toBeGreaterThanOrEqual(2);
			expect(plan.steps[0].id).toBe("java");
			expect(plan.steps[0].isDependency).toBe(true);
			expect(plan.steps[plan.steps.length - 1].id).toBe("jadx");
			expect(plan.steps[plan.steps.length - 1].isDependency).toBe(false);
		});

		it("respects snapshot dependency status when provided and falls back to fresh probe when omitted", () => {
			const jadxStatus: ReverseToolStatus = {
				kind: "cli",
				id: "jadx",
				name: "JADX",
				category: "decompiler",
				description: "Dex to Java decompiler",
				optional: true,
				systemTool: false,
				status: "missing",
				foundPath: null,
				secondaryMissing: ["java"],
				packageManager: "brew",
				installCommand: "brew install jadx",
				installArgv: ["brew", "install", "jadx"],
				riskNote: null,
				manualUrl: "https://github.com/skylot/jadx",
				manualInstructions: "Install via brew install jadx",
			};

			const mockWhich = (cmd: string) => {
				if (cmd === "brew") return "/opt/homebrew/bin/brew";
				return null;
			};

			// 1. Live inspection without report: detects Java is missing, orders java before jadx
			const freshPlan = getReverseInstallPlan(jadxStatus, {
				which: mockWhich,
				platform: "darwin",
				agentDir: tempDir,
			});
			expect(freshPlan.canInstall).toBe(true);
			expect(freshPlan.steps.map(s => s.id)).toEqual(["java", "jadx"]);

			// 2. Caller-supplied report snapshot where Java is recorded as installed
			const baseReport = checkReverseTools({ which: mockWhich, platform: "darwin", agentDir: tempDir });
			const snapshotWithJavaInstalled: ReverseCheckReport = {
				...baseReport,
				tools: baseReport.tools.map(t =>
					t.id === "java"
						? { ...t, status: "installed" as const, foundPath: "/opt/homebrew/opt/openjdk/bin/java" }
						: t,
				),
			};

			const snapshotPlan = getReverseInstallPlan(jadxStatus, {
				report: snapshotWithJavaInstalled,
				which: mockWhich,
				platform: "darwin",
				agentDir: tempDir,
			});
			expect(snapshotPlan.canInstall).toBe(true);
			// Prerequisite Java is satisfied according to snapshot, so only jadx is planned
			expect(snapshotPlan.steps.map(s => s.id)).toEqual(["jadx"]);
		});

		it("repairs a present Node runtime with missing npx before configuring MCP", () => {
			const binaries: Record<string, string> = {
				brew: "/opt/homebrew/bin/brew",
				node: "/usr/local/bin/node",
			};
			const which = (command: string) => binaries[command] ?? null;
			const report = checkReverseTools({ which, platform: "darwin", agentDir: tempDir });
			const service = report.services.find(entry => entry.id === "playwright-mcp")!;
			const plan = getReverseInstallPlan(service, { which, platform: "darwin", agentDir: tempDir });
			expect(plan.canInstall).toBe(true);
			expect(plan.steps.map(step => step.id)).toEqual(["node", "playwright-mcp"]);
		});

		it("explains why unsupported tools cannot be installed", () => {
			const idaStatus: ReverseToolStatus = {
				kind: "cli",
				id: "ida",
				name: "IDA Pro",
				category: "decompiler",
				description: "Interactive Disassembler",
				optional: true,
				systemTool: false,
				status: "missing",
				foundPath: null,
				packageManager: null,
				installCommand: null,
				installArgv: null,
				riskNote: null,
				manualUrl: "https://hex-rays.com/ida-pro/",
				manualInstructions: "Commercial license required. Download from Hex-Rays.",
			};

			const plan = getReverseInstallPlan(idaStatus, { agentDir: tempDir });
			expect(plan.canInstall).toBe(false);
			expect(plan.steps).toHaveLength(0);
			expect(plan.reason).toContain("Commercial license required");
		});

		it("plans pip repair when IDA host is present but adapter dependencies are missing", () => {
			const targetPython = "/opt/custom/venv/bin/python";
			const idaRepairStatus: ReverseToolStatus = {
				kind: "cli",
				id: "ida",
				name: "IDA Pro",
				category: "decompiler",
				description: "Interactive Disassembler",
				optional: true,
				systemTool: false,
				status: "missing",
				foundPath: "/opt/ida-pro-9.1",
				secondaryMissing: ["ida-domain"],
				packageManager: "pip",
				installCommand: `${targetPython} -m pip install ida-domain==0.5.1`,
				installArgv: [targetPython, "-m", "pip", "install", "ida-domain==0.5.1"],
				riskNote: "Installs ida-domain into target Python.",
				manualUrl: "https://hex-rays.com/ida-pro/",
				manualInstructions: "Commercial license required.",
			};

			const plan = getReverseInstallPlan(idaRepairStatus, { agentDir: tempDir });
			expect(plan.canInstall).toBe(true);
			expect(plan.steps).toHaveLength(1);
			expect(plan.steps[0].id).toBe("ida");
			expect(plan.steps[0].packageManager).toBe("pip");
			expect(plan.steps[0].argv).toEqual([targetPython, "-m", "pip", "install", "ida-domain==0.5.1"]);
		});
	});

	describe("persistToolEnvironment and applyPersistedReverseEnvironment", () => {
		it("persists JAVA_HOME and extra tool paths into agent .env without mutating shell rc", async () => {
			const fakeJavaHome = path.join(tempDir, "jdk-25");
			const fakeBin = path.join(fakeJavaHome, "bin");
			await fs.promises.mkdir(fakeBin, { recursive: true });

			const initialEnvFile = path.join(tempDir, ".env");
			await fs.promises.writeFile(initialEnvFile, "EXISTING_API_KEY=secret123\nPATH=/custom/existing/path\n");

			await persistToolEnvironment(
				{
					javaHome: fakeJavaHome,
					extraPaths: [fakeBin],
				},
				tempDir,
			);

			const savedContent = await fs.promises.readFile(initialEnvFile, "utf-8");
			expect(savedContent).toContain("EXISTING_API_KEY=secret123");
			expect(savedContent).toContain("PATH=/custom/existing/path");
			expect(savedContent).toContain(`JAVA_HOME="${fakeJavaHome}"`);
			expect(savedContent).toContain(`REVERSE_TOOL_PATHS="${fakeBin}"`);

			expect(process.env.JAVA_HOME).toBe(fakeJavaHome);
			expect(Bun.env.JAVA_HOME).toBe(fakeJavaHome);
			expect(process.env.PATH?.split(path.delimiter)).toContain(fakeBin);
		});

		it("re-applies persisted environment in future sessions via bootstrap", async () => {
			const fakeToolDir = path.join(tempDir, "custom-tools", "bin");
			await fs.promises.mkdir(fakeToolDir, { recursive: true });
			const fakeJavaHome = path.join(tempDir, "custom-jdk");
			await fs.promises.mkdir(fakeJavaHome, { recursive: true });

			const envFile = path.join(tempDir, ".env");
			await fs.promises.writeFile(envFile, `JAVA_HOME="${fakeJavaHome}"\nREVERSE_TOOL_PATHS="${fakeToolDir}"\n`);

			delete process.env.JAVA_HOME;
			delete Bun.env.JAVA_HOME;
			process.env.PATH = "/usr/bin:/bin";

			applyPersistedReverseEnvironment(tempDir);

			expect(Reflect.get(process.env, "JAVA_HOME")).toBe(fakeJavaHome);
			expect(Reflect.get(Bun.env, "JAVA_HOME")).toBe(fakeJavaHome);
			expect(process.env.PATH?.startsWith(fakeToolDir)).toBe(true);
		});
	});

	describe("resolveJavaHomeFromBinary", () => {
		it("resolves Contents/Home on macOS Java bundle structure", async () => {
			const root = path.join(tempDir, "opt", "openjdk@25", "libexec", "openjdk.jdk", "Contents", "Home");
			const bin = path.join(root, "bin");
			await fs.promises.mkdir(bin, { recursive: true });
			const javaFile = path.join(bin, "java");
			await fs.promises.writeFile(javaFile, "#!/bin/sh\nexit 0\n", { mode: 0o755 });

			const symlinkDir = path.join(tempDir, "opt", "openjdk@25", "bin");
			await fs.promises.mkdir(symlinkDir, { recursive: true });
			const symlinkFile = path.join(symlinkDir, "java");
			await fs.promises.symlink(javaFile, symlinkFile);

			const resolved = resolveJavaHomeFromBinary(symlinkFile);
			expect(resolved).toBe(fs.realpathSync(root));
		});

		it("resolves standard Unix layout parent of bin", async () => {
			const root = path.join(tempDir, "usr", "lib", "jvm", "default-jvm");
			const bin = path.join(root, "bin");
			await fs.promises.mkdir(bin, { recursive: true });
			const javaFile = path.join(bin, "java");
			await fs.promises.writeFile(javaFile, "#!/bin/sh\nexit 0\n", { mode: 0o755 });

			const resolved = resolveJavaHomeFromBinary(javaFile);
			expect(resolved).toBe(fs.realpathSync(root));
		});

		it("returns null if path does not point to a java binary with bin/java", async () => {
			const fakeFile = path.join(tempDir, "not-java.txt");
			await fs.promises.writeFile(fakeFile, "hello");
			expect(resolveJavaHomeFromBinary(fakeFile)).toBeNull();
		});
	});

	describe("installReverseItem execution and honest error handling", () => {
		it("fails if executor command exits with non-zero code", async () => {
			const tool: ReverseToolStatus = {
				kind: "cli",
				id: "jadx",
				name: "JADX",
				category: "decompiler",
				description: "Dex to Java decompiler",
				optional: true,
				systemTool: false,
				status: "missing",
				foundPath: null,
				packageManager: "brew",
				installCommand: "brew install jadx",
				installArgv: ["brew", "install", "jadx"],
				riskNote: null,
				manualUrl: "",
				manualInstructions: "",
			};

			const mockExecutor = async () => ({
				exitCode: 1,
				stdout: "",
				stderr: "Error: No formula found for jadx",
			});

			const mockWhich = (cmd: string) => {
				if (cmd === "brew") return "/opt/homebrew/bin/brew";
				if (cmd === "java") return "/opt/homebrew/bin/java";
				return null;
			};

			const result = await installReverseItem(tool, {
				agentDir: tempDir,
				executor: mockExecutor,
				which: mockWhich,
			});

			expect(result.success).toBe(false);
			expect(result.message).toBeDefined();
		});

		it("fails if command exits 0 but executable was not found (no fake success)", async () => {
			const tool: ReverseToolStatus = {
				kind: "cli",
				id: "jadx",
				name: "JADX",
				category: "decompiler",
				description: "Dex to Java decompiler",
				optional: true,
				systemTool: false,
				status: "missing",
				foundPath: null,
				packageManager: "brew",
				installCommand: "brew install jadx",
				installArgv: ["brew", "install", "jadx"],
				riskNote: null,
				manualUrl: "",
				manualInstructions: "",
			};

			const mockExecutor = async () => ({
				exitCode: 0,
				stdout: "Installation complete",
				stderr: "",
			});

			const mockWhich = (cmd: string) => {
				if (cmd === "brew") return "/opt/homebrew/bin/brew";
				if (cmd === "java") return "/opt/homebrew/bin/java";
				return null;
			};

			const result = await installReverseItem(tool, {
				agentDir: tempDir,
				executor: mockExecutor,
				which: mockWhich,
			});

			expect(result.success).toBe(false);
			expect(result.message).toBeDefined();
		});

		it("succeeds when executable is verified and persists environment", async () => {
			const fakeBinDir = path.join(tempDir, "installed-jadx", "bin");
			await fs.promises.mkdir(fakeBinDir, { recursive: true });
			const jadxBinary = path.join(fakeBinDir, "jadx");
			await fs.promises.writeFile(jadxBinary, "#!/bin/sh\necho jadx v1.5.0\n", { mode: 0o755 });

			const tool: ReverseToolStatus = {
				kind: "cli",
				id: "jadx",
				name: "JADX",
				category: "decompiler",
				description: "Dex to Java decompiler",
				optional: true,
				systemTool: false,
				status: "missing",
				foundPath: null,
				packageManager: "brew",
				installCommand: "brew install jadx",
				installArgv: ["brew", "install", "jadx"],
				riskNote: null,
				manualUrl: "",
				manualInstructions: "",
			};

			const mockExecutor = async () => ({
				exitCode: 0,
				stdout: "Success",
				stderr: "",
			});

			const mockWhich = (cmd: string) => {
				if (cmd === "jadx") return jadxBinary;
				if (cmd === "java") return "/usr/bin/java";
				if (cmd === "brew") return "/opt/homebrew/bin/brew";
				return null;
			};
			const result = await installReverseItem(tool, {
				agentDir: tempDir,
				executor: mockExecutor,
				which: mockWhich,
			});

			expect(result.success).toBe(true);

			// Check that environment was persisted
			const envContent = await fs.promises.readFile(path.join(tempDir, ".env"), "utf-8");
			expect(envContent).toContain(fakeBinDir);
			expect(process.env.PATH).toContain(fakeBinDir);
		});
	});

	describe("Non-jshook MCP configuration and connection", () => {
		it("writes MCP config to user mcp.json and hot-connects via mcpManager", async () => {
			const playwrightStatus: ReverseServiceStatus = {
				kind: "mcp",
				id: "playwright-mcp",
				name: "Playwright MCP",
				category: "web",
				description: "Playwright MCP server",
				optional: true,
				license: "Apache-2.0",
				serverName: "playwright",
				transport: "stdio",
				startCommand: "npx -y @playwright/mcp@latest",
				configPath: ".reverse/mcp.json",
				configPaths: { project: ".reverse/mcp.json", user: path.join(tempDir, "mcp.json") },
				configSnippet: {},
				prerequisites: [],
				missingPrerequisites: [],
				prerequisitesReady: true,
				ready: true,
				configured: false,
				configuredScopes: [],
				enabled: null,
				connection: "unknown",
				status: "ready",
				packageManager: "npm",
				installCommand: null,
				installArgv: null,
				riskNote: "",
				manualUrl: "",
				manualInstructions: "",
				usage: { canonical: "playwright", whenToUse: "browser automation", examples: [] },
			};
			let connected = false;
			let refreshedTools = false;

			const mockMcpManager: Pick<
				import("../src/mcp/manager").MCPManager,
				"connectServers" | "getConnectionStatus" | "getTools"
			> = {
				connectServers: async () => {
					connected = true;
					return {
						tools: [],
						errors: new Map(),
						connectedServers: ["playwright"],
						exaApiKeys: [],
					};
				},
				getConnectionStatus: () => "connected",
				getTools: () => [],
			};
			const mockSession = {
				refreshMCPTools: async () => {
					refreshedTools = true;
				},
			};

			const result = await installReverseItem(playwrightStatus, {
				agentDir: tempDir,
				mcpManager: mockMcpManager,
				session: mockSession,
			});

			expect(result.success).toBe(true);
			expect(result.activated).toBe(true);
			expect(connected).toBe(true);
			expect(refreshedTools).toBe(true);

			// Verify mcp.json was written
			const mcpJsonPath = path.join(tempDir, "mcp.json");
			expect(fs.existsSync(mcpJsonPath)).toBe(true);
			const mcpJson = JSON.parse(await fs.promises.readFile(mcpJsonPath, "utf-8"));
			expect(mcpJson.mcpServers?.playwright).toBeDefined();
		});
	});
});

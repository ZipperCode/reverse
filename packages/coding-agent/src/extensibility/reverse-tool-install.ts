// oxlint-disable no-template-curly-in-string
/**
 * Shared Reverse Engineering Toolchain and Helper Service Installer.
 *
 * Provides a unified, safe installation API for CLI and TUI setup surfaces:
 * - Single authoritative graph planner: validates against current platform and available package managers
 * - Validates commands strictly against trusted catalogs (no arbitrary argv execution)
 * - Resolves and installs missing catalog dependencies recursively in topological order
 * - Recursively bootstraps package manager tools (e.g. sdkmanager -> java)
 * - Probes package managers and tools using canonical checkToolRequirements and npm prefixes
 * - Automatically configures and persists narrow tool environment (JAVA_HOME, REVERSE_TOOL_PATHS)
 *   in the agent profile (.env), re-applied at bootstrap without shell rc mutation
 * - Disallows fake success (exit 0 without working binary is treated as failure)
 * - Configures and hot-connects MCP services in live sessions without clobbering user overrides
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { parseEnv } from "node:util";
import {
	$which,
	APP_NAME,
	clearWhichCache,
	getAgentDir,
	getProjectDir,
	isEnoent,
	WhichCachePolicy,
} from "@reverse/utils";
import { refreshShellConfigCache } from "@reverse/utils/procmgr";
import { invalidateShellSnapshotCache } from "../utils/shell-snapshot";
import type { Settings } from "../config/settings";
import {
	SKILL_TOOL_CATALOG,
	type PackageInstallCommand,
	type SkillToolDescriptor,
	type SkillToolPlatform,
} from "./skill-tool-catalog";
import { getMcpService } from "./mcp-service-catalog";
import {
	checkReverseTools,
	executeSafeCatalogCommand,
	isTrustedCatalogArgv,
	readMcpConfigFileSync,
	t,
	type ReverseCheckReport,
	type ReverseServiceStatus,
	type ReverseToolStatus,
} from "../cli/setup-reverse";
import {
	getJshookInstallDir,
	installJshookMcp,
	JSHOOK_PACKAGE_NAME,
	JSHOOK_PACKAGE_VERSION,
	WEBCRACK_PACKAGE_NAME,
	WEBCRACK_PACKAGE_VERSION,
} from "./jshookmcp-install";
import { probeIdaPythonEnvironment } from "../ida/install";
import { clearIdaRuntimeCache } from "../ida/runtime";
import {
	getNativeMcpServer,
	installNativeMcpService,
	isServerConfigIdentical,
	type NativeMcpService,
} from "./native-mcp-install";
import { getPortableToolRecipe, installPortableTool } from "./portable-tool-install";
import { getVmpToolUnsupportedReason, installTritonVenv, type VmpToolId } from "./vmp-toolchain";
import { installLiefVenv } from "./lief-install";
import { buildAndInstallSoFixer, canBuildSoFixer } from "./sofixer-toolchain";
import { buildAndInstallGhidraFindCrypt, canBuildGhidraFindCrypt, resolveGhidraInstallDir } from "./findcrypt-install";
import { installRuntimeTool } from "./runtime-toolchain";
import { installProtectionTool, isProtectionToolId, type ProtectionToolId } from "./protection-toolchain";
import { readMCPConfigFile, setMcpServerEnabled, updateMCPServer } from "../mcp/config-writer";
import type { MCPServerConnection } from "../mcp/types";
import type { MCPManager } from "../mcp/manager";
import type { AgentSession } from "../session/agent-session";
import { checkToolRequirements, type SkillRequirementWhich } from "./skill-requirements";

export interface ReverseInstallOptions {
	cwd?: string;
	agentDir?: string;
	onChunk?: (chunk: string) => void;
	executor?: (
		argv: readonly string[],
		options?: { onChunk?: (chunk: string) => void },
	) => Promise<{ exitCode: number; stdout: string; stderr: string }>;
	which?: SkillRequirementWhich;
	platform?: NodeJS.Platform;
	env?: Record<string, string | undefined>;
	settings?: Settings;
	mcpManager?: Pick<MCPManager, "connectServers" | "getConnectionStatus" | "getTools">;
	session?: Pick<AgentSession, "refreshMCPTools">;
	signal?: AbortSignal;
	plan?: ReverseInstallPlan;
	report?: ReverseCheckReport;
}

export interface ReverseInstallStep {
	id: string;
	name: string;
	kind: "cli" | "mcp";
	packageManager?: string | null;
	command?: string | null;
	argv?: readonly string[] | null;
	riskNote?: string | null;
	isDependency?: boolean;
	secondaryMissing?: string[];
	manualInstructions?: string;
	foundPath?: string | null;
	serverConfigSnapshot?: string;
	installer?:
		| "jshookmcp"
		| "portable"
		| "unidbg"
		| "native-mcp"
		| "triton"
		| "pip"
		| "lief"
		| "sofixer"
		| "ghidra-findcrypt"
		| "runtime-toolchain"
		| "protection-toolchain";
}

export interface ReverseInstallPlan {
	item: ReverseToolStatus | ReverseServiceStatus;
	canInstall: boolean;
	steps: ReverseInstallStep[];
	missingDependencies: string[];
	reason?: string;
}

/** Known bootstrap mappings: package manager -> catalog tool that provides it. */
const MANAGER_BOOTSTRAP_TOOL: Record<string, string> = {
	sdkmanager: "sdkmanager",
	r2pm: "radare2",
};

/**
 * Resolve JAVA_HOME directory from a found java executable binary.
 * Resolves symlinks (e.g. Homebrew openjdk symlinks) and validates Contents/Home or bin/java.
 * Explicitly rejects macOS stub wrapper /usr/bin/java so /usr is never returned.
 */
export function resolveJavaHomeFromBinary(javaBinaryPath: string): string | null {
	try {
		const real = fs.realpathSync(javaBinaryPath);
		if (real === "/usr/bin/java" || real === "/usr") return null;

		// macOS OpenJDK bundle structure (.../libexec/openjdk.jdk/Contents/Home/bin/java)
		const contentsHomeIdx = real.indexOf("/Contents/Home");
		if (contentsHomeIdx !== -1) {
			const javaHome = real.slice(0, contentsHomeIdx + "/Contents/Home".length);
			if (fs.existsSync(path.join(javaHome, "bin", "java"))) {
				return javaHome;
			}
		}
		// Standard Unix/Windows layout (.../bin/java or .../bin/java.exe)
		const binDir = path.dirname(real);
		if (path.basename(binDir).toLowerCase() === "bin") {
			const parent = path.dirname(binDir);
			if (parent === "/usr" || parent === "/usr/local") {
				return null;
			}
			const ext = process.platform === "win32" ? ".exe" : "";
			if (fs.existsSync(path.join(parent, "bin", `java${ext}`))) {
				return parent;
			}
		}
	} catch {}
	return null;
}

function quoteEnvironmentValue(value: string): string {
	if (/[\r\n]/.test(value) || (value.includes("'") && value.includes('"'))) {
		throw new Error("Tool environment paths must fit a single quoted dotenv value.");
	}
	return value.includes('"') ? `'${value}'` : `"${value}"`;
}

/**
 * Persist narrow, trusted reverse toolchain environment into the agent profile (.env).
 * Preserves user's existing PATH and other custom variables. Persists ONLY REVERSE_TOOL_PATHS and JAVA_HOME.
 */
export async function persistToolEnvironment(
	entries: { javaHome?: string; extraPaths?: string[] },
	agentDir?: string,
): Promise<void> {
	const targetAgentDir = agentDir ?? getAgentDir();
	await fs.promises.mkdir(targetAgentDir, { recursive: true, mode: 0o700 });
	const envFile = path.join(targetAgentDir, ".env");

	let currentLines: string[] = [];
	try {
		const content = await fs.promises.readFile(envFile, "utf-8");
		currentLines = content.split(/\r?\n/);
	} catch (error) {
		if (!isEnoent(error)) {
			throw error;
		}
	}
	const existingKeys = new Map<string, number>();
	for (let i = 0; i < currentLines.length; i++) {
		const match = currentLines[i]?.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/);
		if (match) {
			existingKeys.set(match[1], i);
		}
	}

	// 1. Persist JAVA_HOME
	if (entries.javaHome) {
		const line = `JAVA_HOME=${quoteEnvironmentValue(entries.javaHome)}`;
		if (existingKeys.has("JAVA_HOME")) {
			currentLines[existingKeys.get("JAVA_HOME")!] = line;
		} else {
			currentLines.push(line);
		}
		process.env.JAVA_HOME = entries.javaHome;
		Bun.env.JAVA_HOME = entries.javaHome;
	}

	// 2. Persist tool directories into REVERSE_TOOL_PATHS (do NOT overwrite user's PATH line)
	if (entries.extraPaths && entries.extraPaths.length > 0) {
		const validDirs = entries.extraPaths.filter(d => {
			try {
				return path.isAbsolute(d) && fs.existsSync(d) && fs.statSync(d).isDirectory();
			} catch {
				return false;
			}
		});

		if (validDirs.length > 0) {
			let storedPaths: string[] = [];
			const storedLineIdx = existingKeys.get("REVERSE_TOOL_PATHS");
			if (storedLineIdx !== undefined) {
				storedPaths = (parseEnv(currentLines.join("\n")).REVERSE_TOOL_PATHS ?? "")
					.split(path.delimiter)
					.filter(Boolean);
			}

			const merged = [...new Set([...validDirs, ...storedPaths])];
			const storedLine = `REVERSE_TOOL_PATHS=${quoteEnvironmentValue(merged.join(path.delimiter))}`;
			if (storedLineIdx !== undefined) {
				currentLines[storedLineIdx] = storedLine;
			} else {
				currentLines.push(storedLine);
			}

			// Apply to live process PATH (in-memory only)
			const currentProcessPath = process.env.PATH ?? "";
			const pathParts = currentProcessPath.split(path.delimiter).filter(Boolean);
			const newParts = [...merged.filter(d => !pathParts.includes(d)), ...pathParts];
			const updatedPath = newParts.join(path.delimiter);
			process.env.PATH = updatedPath;
			Bun.env.PATH = updatedPath;
		}
	}

	// Atomically write updated .env
	const tmpFile = `${envFile}.${process.pid}.${Date.now()}.tmp`;
	await fs.promises.writeFile(tmpFile, currentLines.filter(l => l !== undefined).join("\n") + "\n", {
		mode: 0o600,
	});
	await fs.promises.rename(tmpFile, envFile);

	refreshShellConfigCache();
	clearWhichCache();
	invalidateShellSnapshotCache();
}

/**
 * Re-apply persisted tool environment from the agent profile (.env).
 * Invoked during process bootstrap and interactive mode startup.
 */
export function applyPersistedReverseEnvironment(agentDir?: string): void {
	const targetAgentDir = agentDir ?? getAgentDir();
	const envFile = path.join(targetAgentDir, ".env");
	if (!fs.existsSync(envFile)) return;

	try {
		const raw = fs.readFileSync(envFile, "utf-8");
		const parsed = parseEnv(raw);

		if (parsed.JAVA_HOME && typeof parsed.JAVA_HOME === "string") {
			const jHome = parsed.JAVA_HOME.trim();
			if (path.isAbsolute(jHome) && fs.existsSync(jHome)) {
				process.env.JAVA_HOME = jHome;
				Bun.env.JAVA_HOME = jHome;
			}
		}

		if (parsed.REVERSE_TOOL_PATHS && typeof parsed.REVERSE_TOOL_PATHS === "string") {
			const extraPaths = parsed.REVERSE_TOOL_PATHS.split(path.delimiter).filter(Boolean);
			const valid = extraPaths.filter(d => {
				try {
					return path.isAbsolute(d) && fs.existsSync(d) && fs.statSync(d).isDirectory();
				} catch {
					return false;
				}
			});
			if (valid.length > 0) {
				const currentParts = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
				const combined = [...new Set([...valid.filter(d => !currentParts.includes(d)), ...currentParts])];
				const newPath = combined.join(path.delimiter);
				process.env.PATH = newPath;
				Bun.env.PATH = newPath;
			}
		}

		refreshShellConfigCache();
		clearWhichCache();
		invalidateShellSnapshotCache();
	} catch {}
}

/**
 * Authoritative single graph planner for installation steps and feasibility.
 * Operates strictly on the requested platform and currently available package managers.
 * Recursively resolves secondary dependencies, prerequisites, and package manager bootstrap tools.
 */
export function getReverseInstallPlan(
	item: ReverseToolStatus | ReverseServiceStatus,
	options: {
		which?: SkillRequirementWhich;
		platform?: NodeJS.Platform;
		env?: Record<string, string | undefined>;
		agentDir?: string;
		cwd?: string;
		report?: ReverseCheckReport;
		settings?: Settings;
	} = {},
): ReverseInstallPlan {
	const reqPlatform = options.platform ?? options.report?.platform ?? process.platform;
	const platform: SkillToolPlatform = reqPlatform === "darwin" || reqPlatform === "win32" ? reqPlatform : "linux";
	const which: SkillRequirementWhich = options.which ?? $which;
	const report =
		options.report ??
		checkReverseTools({
			platform: reqPlatform,
			which,
			env: options.env,
			agentDir: options.agentDir,
			cwd: options.cwd,
			settings: options.settings,
		});

	const statusById: Record<string, ReverseToolStatus | ReverseServiceStatus> = {};
	for (const t of report.tools) statusById[t.id] = t;
	for (const s of report.services) statusById[s.id] = s;

	const availableManagers = new Set(report.detectedPackageManagers);
	const steps: ReverseInstallStep[] = [];
	const missingDependencies: string[] = [];
	const visited = new Set<string>();
	const inProgress = new Set<string>();

	function planTool(id: string): boolean {
		if (visited.has(id)) return true;
		if (inProgress.has(id)) return false; // Cycle guard
		inProgress.add(id);

		const desc = SKILL_TOOL_CATALOG[id];
		if (!desc) {
			inProgress.delete(id);
			return false;
		}

		const currentStatus = (id === item.id ? item : statusById[id]) ?? item;
		if (currentStatus?.status === "installed") {
			inProgress.delete(id);
			visited.add(id);
			return true;
		}

		// 1. Recursively plan secondary dependencies and known prerequisites that are catalog tools
		const prereqIds = [
			...(desc.secondary?.filter(sec => SKILL_TOOL_CATALOG[sec] && sec !== id) ?? []),
			...(desc.usage?.prerequisites?.filter(p => p !== id && SKILL_TOOL_CATALOG[p]) ?? []),
		];

		for (const prereqId of prereqIds) {
			const prereqStatus = statusById[prereqId];
			if (!prereqStatus || prereqStatus.status !== "installed") {
				if (!planTool(prereqId)) {
					missingDependencies.push(prereqId);
					inProgress.delete(id);
					return false;
				}
			}
		}
		// 仅目录内已排入安装计划的依赖可以修复现有程序；npx 等随包提供的伴随程序仍需重装。
		if (
			id !== item.id &&
			currentStatus?.kind === "cli" &&
			currentStatus?.foundPath &&
			(currentStatus.secondaryMissing ?? []).every(dependency => visited.has(dependency))
		) {
			inProgress.delete(id);
			visited.add(id);
			return true;
		}
		if (id === "triton") {
			const isDarwinArm = platform === "darwin" && process.arch === "arm64";
			steps.push({
				id: "triton",
				name: desc.name ?? "Triton Binary Analysis",
				kind: "cli",
				packageManager: isDarwinArm ? "build" : "pip",
				installer: "triton",
				command: isDarwinArm
					? `${APP_NAME} setup reverse triton (managed venv, source build)`
					: `${APP_NAME} setup reverse triton (managed venv)`,
				argv: [APP_NAME, "setup", "reverse", "triton", "--execute"],
				riskNote: t(
					"cli.setup.reverse.triton.risk",
					isDarwinArm
						? "Provisions an isolated virtual environment and compiles triton-library natively from pinned source (commit bc84cf7) using bundled capstone and z3-solver wheels."
						: "Provisions an isolated virtual environment in the agent directory and installs pinned triton-library (Apache-2.0, dynamic binary analysis and symbolic execution).",
				),
				isDependency: id !== item.id,
				manualInstructions: desc.manualInstructions?.[platform],
			});
			inProgress.delete(id);
			visited.add(id);
			return true;
		}
		if (
			id === "ida" &&
			currentStatus?.kind === "cli" &&
			currentStatus.installArgv &&
			currentStatus.packageManager === "pip"
		) {
			steps.push({
				id: "ida",
				name: desc.name ?? "IDA Pro",
				kind: "cli",
				packageManager: "pip",
				installer: "pip",
				command: currentStatus.installCommand ?? currentStatus.installArgv.join(" "),
				argv: currentStatus.installArgv,
				riskNote: currentStatus.riskNote ?? undefined,
				isDependency: id !== item.id,
				secondaryMissing: currentStatus.secondaryMissing ? [...currentStatus.secondaryMissing] : undefined,
				manualInstructions: currentStatus.manualInstructions ?? desc.manualInstructions?.[platform],
				foundPath: currentStatus.foundPath,
			});
			inProgress.delete(id);
			visited.add(id);
			return true;
		}
		if (id === "lief") {
			steps.push({
				id: "lief",
				name: desc.name ?? "LIEF",
				kind: "cli",
				packageManager: "pip",
				installer: "lief",
				command: `${APP_NAME} setup reverse lief (managed venv)`,
				argv: [APP_NAME, "setup", "reverse", "lief", "--execute"],
				riskNote: t(
					"cli.setup.reverse.lief.risk",
					"Provisions an isolated virtual environment in the agent directory and installs pinned lief (1.0.0, Apache-2.0).",
				),
				isDependency: id !== item.id,
				manualInstructions: desc.manualInstructions?.[platform],
			});
			inProgress.delete(id);
			visited.add(id);
			return true;
		}
		if (id === "sofixer") {
			const canBuild = canBuildSoFixer({ which, env: options.env, platform });
			if (!canBuild.supported) {
				reason = `SoFixer requires build tools: ${canBuild.missingPrereqs.join(", ")}. Please install them first.`;
				inProgress.delete(id);
				return false;
			}
			steps.push({
				id: "sofixer",
				name: desc.name ?? "SoFixer",
				kind: "cli",
				packageManager: "build",
				installer: "sofixer",
				command: `${APP_NAME} setup reverse sofixer --execute`,
				argv: [APP_NAME, "setup", "reverse", "sofixer", "--execute"],
				riskNote: t(
					"cli.setup.reverse.sofixer.risk",
					"Builds native 32-bit and 64-bit SoFixer binaries from pinned upstream source (F8LEFT/SoFixer commit 75b8b63, BSD-3-Clause) using CMake and local compiler.",
				),
				isDependency: id !== item.id,
				manualInstructions: desc.manualInstructions?.[platform],
			});
			inProgress.delete(id);
			visited.add(id);
			return true;
		}
		if (id === "ghidra-findcrypt") {
			const ghidraDir = resolveGhidraInstallDir({ env: options.env, which });
			if (!ghidraDir) {
				if (!planTool("ghidra")) {
					reason = "FindCrypt requires Ghidra. Please install Ghidra first ('reverse setup reverse ghidra').";
					inProgress.delete(id);
					return false;
				}
			}
			const canBuild = canBuildGhidraFindCrypt({
				ghidraPath: ghidraDir ?? undefined,
				which,
				env: options.env,
				platform,
			});
			if (!canBuild.supported) {
				reason = `FindCrypt build requires: ${canBuild.missingPrereqs.join(", ")}.`;
				inProgress.delete(id);
				return false;
			}
			steps.push({
				id: "ghidra-findcrypt",
				name: desc.name ?? "Ghidra FindCrypt Analyzer",
				kind: "cli",
				packageManager: "build",
				installer: "ghidra-findcrypt",
				command: `${APP_NAME} setup reverse ghidra-findcrypt --execute`,
				argv: [APP_NAME, "setup", "reverse", "ghidra-findcrypt", "--execute"],
				riskNote: t(
					"cli.setup.reverse.ghidra-findcrypt.risk",
					"Compiles Ghidra FindCrypt extension from upstream source (TorgoTorgo/ghidra-findcrypt commit 5c2fd5b, GPL-3.0) against target Ghidra and installs it into Ghidra Extensions.",
				),
				isDependency: id !== item.id,
				manualInstructions: desc.manualInstructions?.[platform],
			});
			inProgress.delete(id);
			visited.add(id);
			return true;
		}
		if (id === "blutter" || id === "hbctool" || id === "hermes-dec" || id === "il2cppdumper") {
			steps.push({
				id,
				name: desc.name ?? id,
				kind: "cli",
				packageManager: "managed",
				installer: "runtime-toolchain",
				command: `${APP_NAME} setup reverse ${id} --execute`,
				argv: [APP_NAME, "setup", "reverse", id, "--execute"],
				riskNote: t(
					`cli.setup.reverse.${id}.risk`,
					`Provisions managed ${desc.name ?? id} into agent tools directory.`,
				),
				isDependency: id !== item.id,
				manualInstructions: desc.manualInstructions?.[platform],
			});
			inProgress.delete(id);
			visited.add(id);
			return true;
		}
		if (isProtectionToolId(id)) {
			steps.push({
				id,
				name: desc.name ?? id,
				kind: "cli",
				packageManager: "managed",
				installer: "protection-toolchain",
				command: `${APP_NAME} setup reverse ${id} --execute`,
				argv: [APP_NAME, "setup", "reverse", id, "--execute"],
				riskNote: t(
					`cli.setup.reverse.${id}.risk`,
					`Provisions managed ${desc.name ?? id} into agent tools directory.`,
				),
				isDependency: id !== item.id,
				manualInstructions: desc.manualInstructions?.[platform],
			});
			inProgress.delete(id);
			visited.add(id);
			return true;
		}
		// 2. Find a viable recipe strictly on this platform
		const recipes = desc.installCommands?.[platform] ?? [];
		let chosenRecipe: PackageInstallCommand | undefined;

		for (const recipe of recipes) {
			if (!recipe.argv || recipe.argv.length === 0) continue;
			const bootId = MANAGER_BOOTSTRAP_TOOL[recipe.manager];
			if (bootId && bootId !== id && SKILL_TOOL_CATALOG[bootId]) {
				if (!planTool(bootId)) continue;
				chosenRecipe = recipe;
				break;
			}
			if (availableManagers.has(recipe.manager)) {
				chosenRecipe = recipe;
				break;
			}
		}
		if (!chosenRecipe) {
			const portableRecipe = getPortableToolRecipe(id);
			if (portableRecipe && (platform === "win32" || availableManagers.has("portable"))) {
				steps.push({
					id: desc.id,
					name: desc.name ?? desc.id,
					kind: "cli",
					packageManager: "portable",
					installer: "portable",
					command: `reverse setup reverse ${desc.id} (portable upstream download)`,
					argv: ["reverse", "setup", "reverse", desc.id, "--execute"],
					riskNote: `Downloads portable ${portableRecipe.name} v${portableRecipe.version} directly from upstream into agent tools directory.`,
					isDependency: id !== item.id,
					secondaryMissing: desc.secondary ? [...desc.secondary] : undefined,
					manualInstructions: desc.manualInstructions?.[platform],
				});
				inProgress.delete(id);
				visited.add(id);
				return true;
			}
			inProgress.delete(id);
			return false;
		}

		const isPortable = chosenRecipe.manager === "portable";

		steps.push({
			id: desc.id,
			name: desc.name ?? desc.id,
			kind: "cli",
			packageManager: chosenRecipe.manager,
			installer: isPortable ? "portable" : undefined,
			command: chosenRecipe.command,
			argv: chosenRecipe.argv,
			riskNote: chosenRecipe.riskNote,
			isDependency: id !== item.id,
			secondaryMissing: desc.secondary ? [...desc.secondary] : undefined,
			manualInstructions: desc.manualInstructions?.[platform],
		});

		inProgress.delete(id);
		visited.add(id);
		return true;
	}

	let canInstall = false;
	let reason: string | undefined;

	if (item.kind === "cli" && item.id === "unidbg") {
		const desc = SKILL_TOOL_CATALOG.unidbg;
		const steps: ReverseInstallStep[] = [
			{
				id: "unidbg",
				name: desc?.name ?? "Unidbg (ARM32/ARM64 Android Native Library Emulator)",
				kind: "cli",
				packageManager: "build",
				installer: "unidbg",
				command: `${APP_NAME} unidbg build`,
				argv: [APP_NAME, "unidbg", "build"],
				riskNote: "Builds upstream Unidbg using validated JDK 8 and Maven wrapper.",
				isDependency: false,
			},
		];
		return {
			item,
			canInstall: true,
			steps,
			missingDependencies: [],
		};
	}

	if (item.kind === "cli") {
		const desc = SKILL_TOOL_CATALOG[item.id];
		const hasRecipe = Boolean(
			desc?.installCommands?.[platform]?.length ||
			(platform === "win32" && getPortableToolRecipe(item.id)) ||
			item.id === "triton" ||
			item.id === "lief" ||
			item.id === "sofixer" ||
			item.id === "ghidra-findcrypt",
		);
		if (item.status === "installed" && !hasRecipe) {
			return {
				item,
				canInstall: false,
				steps: [],
				missingDependencies: [],
				reason:
					item.manualInstructions ||
					`${item.name} is installed manually and has no automated package manager recipe.`,
			};
		}

		canInstall = planTool(item.id);
		if (!canInstall) {
			const vmpUnsupported =
				item.id === "vmpdump" || item.id === "mergen" || item.id === "novmp" || item.id === "triton"
					? getVmpToolUnsupportedReason(item.id as VmpToolId, platform)
					: null;
			reason =
				vmpUnsupported ||
				item.manualInstructions ||
				`Automated installation is not supported for ${item.name} on ${platform}.`;
		}
	} else if (item.kind === "mcp") {
		const service = getMcpService(item.id);
		if (!service) {
			return {
				item,
				canInstall: false,
				steps: [],
				missingDependencies: [],
				reason: `MCP service "${item.id}" not found in catalog.`,
			};
		}

		// Recursively plan prerequisite tools (e.g. node for jshook/playwright, radare2 for r2mcp)
		let prereqsOk = true;
		for (const reqId of service.requires) {
			const reqStatus = statusById[reqId];
			if (!reqStatus || reqStatus.status !== "installed") {
				if (!planTool(reqId)) {
					missingDependencies.push(reqId);
					prereqsOk = false;
					break;
				}
			}
		}

		if (!prereqsOk) {
			canInstall = false;
			reason = `Required prerequisites cannot be automatically installed on ${platform}: ${missingDependencies.join(", ")}.`;
		} else if (service.installer === "jshookmcp") {
			canInstall = true;
			const installDir = getJshookInstallDir(options.agentDir);
			const installCmd = `npm install --prefix ${installDir} --save-exact --omit=dev --omit=optional --no-audit --no-fund ${JSHOOK_PACKAGE_NAME}@${JSHOOK_PACKAGE_VERSION} ${WEBCRACK_PACKAGE_NAME}@${WEBCRACK_PACKAGE_VERSION}`;
			const installArgv = [
				"npm",
				"install",
				"--prefix",
				installDir,
				"--save-exact",
				"--omit=dev",
				"--omit=optional",
				"--no-audit",
				"--no-fund",
				`${JSHOOK_PACKAGE_NAME}@${JSHOOK_PACKAGE_VERSION}`,
				`${WEBCRACK_PACKAGE_NAME}@${WEBCRACK_PACKAGE_VERSION}`,
			];
			steps.push({
				id: service.id,
				name: service.name,
				kind: "mcp",
				packageManager: "npm",
				command: installCmd,
				argv: installArgv,
				riskNote: `Installs managed ${JSHOOK_PACKAGE_NAME}@${JSHOOK_PACKAGE_VERSION} and ${WEBCRACK_PACKAGE_NAME}@${WEBCRACK_PACKAGE_VERSION} into ${installDir}. ${service.riskNote}`,
				isDependency: false,
				manualInstructions: service.manualInstructions[platform],
			});
		} else if (service.installer === "native-mcp") {
			// Preflight check: 提前校验配置文件中的禁用列表与冲突配置，避免在已被禁用或配置冲突时盲目规划与安装
			const projectConfig = readMcpConfigFileSync(path.join(options.cwd ?? getProjectDir(), ".reverse", "mcp.json"));
			const userConfig = readMcpConfigFileSync(path.join(options.agentDir ?? getAgentDir(), "mcp.json"));

			if (
				userConfig?.disabledServers?.includes(service.serverName) ||
				projectConfig?.disabledServers?.includes(service.serverName)
			) {
				canInstall = false;
				reason = `MCP server "${service.serverName}" is currently disabled in MCP config. Re-enable it before installing.`;
			} else {
				const targetServerConfig = getNativeMcpServer(
					service.id === "x64dbg-mcp" ? "x64dbg" : service.id === "ghidra-mcp" ? "ghidra" : "radare2",
					{ agentDir: options.agentDir },
				);
				const existingServer =
					projectConfig?.mcpServers?.[service.serverName] ?? userConfig?.mcpServers?.[service.serverName];
				if (existingServer && !isServerConfigIdentical(existingServer, targetServerConfig)) {
					canInstall = false;
					reason = `Server "${service.serverName}" already exists in MCP config with a conflicting configuration. Remove or rename it first.`;
				} else {
					canInstall = true;
				}
			}
			if (canInstall) {
				if (service.id === "x64dbg-mcp") {
					const cmdStr = "pip install x64dbg_automate[mcp]==0.9.2";
					steps.push({
						id: service.id,
						name: service.name,
						kind: "mcp",
						packageManager: "pip",
						command: cmdStr,
						argv: ["pip", "install", "x64dbg_automate[mcp]==0.9.2"],
						riskNote: service.riskNote,
						isDependency: false,
						installer: "native-mcp",
						manualInstructions: service.manualInstructions[platform],
					});
				} else if (service.id === "ghidra-mcp") {
					const cmdStr = "pip install ghidra_mcp-2.0.0-py3-none-any.whl[headless]";
					steps.push({
						id: service.id,
						name: service.name,
						kind: "mcp",
						packageManager: "pip",
						command: cmdStr,
						argv: ["pip", "install", "ghidra_mcp[headless]"],
						riskNote: service.riskNote,
						isDependency: false,
						installer: "native-mcp",
						manualInstructions: service.manualInstructions[platform],
					});
				} else if (service.id === "r2mcp") {
					const cmdStr = "r2pm -Uci r2mcp";
					steps.push({
						id: service.id,
						name: service.name,
						kind: "mcp",
						packageManager: "r2pm",
						command: cmdStr,
						argv: ["r2pm", "-Uci", "r2mcp"],
						riskNote: service.riskNote,
						isDependency: false,
						installer: "native-mcp",
						manualInstructions: service.manualInstructions[platform],
					});
				}
			}
		} else if (service.id === "playwright-mcp") {
			canInstall = true;
			steps.push({
				id: service.id,
				name: service.name,
				kind: "mcp",
				packageManager: "npm",
				command: service.startCommand,
				argv: null,
				riskNote: service.riskNote,
				isDependency: false,
				manualInstructions: service.manualInstructions[platform],
			});
		} else {
			const recipes = service.installCommands?.[platform] ?? [];
			let chosenRecipe: PackageInstallCommand | undefined;
			for (const recipe of recipes) {
				if (!recipe.argv || recipe.argv.length === 0) continue;
				if (availableManagers.has(recipe.manager)) {
					chosenRecipe = recipe;
					break;
				}
				const bootId = MANAGER_BOOTSTRAP_TOOL[recipe.manager];
				if (bootId && (statusById[bootId]?.status === "installed" || planTool(bootId))) {
					chosenRecipe = recipe;
					break;
				}
			}

			if (chosenRecipe) {
				canInstall = true;
				steps.push({
					id: service.id,
					name: service.name,
					kind: "mcp",
					packageManager: chosenRecipe.manager,
					command: chosenRecipe.command,
					argv: chosenRecipe.argv,
					riskNote: chosenRecipe.riskNote,
					isDependency: false,
					manualInstructions: service.manualInstructions[platform],
				});
			} else {
				canInstall = false;
				reason =
					service.manualInstructions[platform] ||
					`No automated install recipe available for ${service.name} on ${platform}.`;
			}
		}
	}

	// 确认界面必须展示实际的覆盖配置；执行前再比对，避免审核后切换到另一条启动命令。
	for (const step of steps) {
		if (step.kind !== "mcp" || step.id === "jshookmcp" || step.installer === "native-mcp") continue;
		const service = getMcpService(step.id)!;
		const projectConfig = readMcpConfigFileSync(path.join(options.cwd ?? getProjectDir(), ".reverse", "mcp.json"));
		const userConfig = readMcpConfigFileSync(path.join(options.agentDir ?? getAgentDir(), "mcp.json"));
		const server =
			projectConfig?.mcpServers?.[service.serverName] ??
			userConfig?.mcpServers?.[service.serverName] ??
			service.server;
		step.serverConfigSnapshot = JSON.stringify(server);
		step.command = [step.command, `MCP ${step.serverConfigSnapshot}`].filter(Boolean).join("; ");
	}

	if (!canInstall) {
		steps.length = 0;
	}

	return {
		item,
		canInstall,
		steps,
		missingDependencies: [...new Set(missingDependencies)],
		reason,
	};
}

/** Check if an item can be installed through the authoritative planner. */
export function canInstallReverseItem(
	item: ReverseToolStatus | ReverseServiceStatus,
	options: {
		platform?: NodeJS.Platform;
		which?: SkillRequirementWhich;
		env?: Record<string, string | undefined>;
		agentDir?: string;
		cwd?: string;
		report?: ReverseCheckReport;
	} = {},
): boolean {
	if (item.status === "installed" || item.status === "ready") return true;
	return getReverseInstallPlan(item, options).canInstall;
}

/** Construct a trusted catalog status item for validation against catalog definitions. */
function makeCanonicalCatalogStatus(step: ReverseInstallStep): ReverseToolStatus | ReverseServiceStatus | null {
	if (step.kind === "cli") {
		const desc = SKILL_TOOL_CATALOG[step.id];
		if (!desc) return null;
		return {
			kind: "cli",
			id: desc.id,
			name: desc.name ?? desc.id,
			category: desc.category ?? "general",
			description: desc.description ?? "",
			optional: desc.optional ?? true,
			systemTool: desc.systemTool ?? false,
			status: "missing",
			foundPath: step.foundPath ?? null,
			packageManager: step.packageManager ?? null,
			installCommand: step.command ?? null,
			installArgv: step.argv ?? null,
			riskNote: step.riskNote ?? null,
			manualUrl: desc.manualUrl ?? "",
			manualInstructions: "",
			usage: desc.usage,
		};
	}

	if (step.kind === "mcp") {
		const service = getMcpService(step.id);
		if (!service) return null;
		return {
			kind: "mcp",
			id: service.id,
			name: service.name,
			category: service.category,
			description: service.description,
			optional: true,
			license: service.license,
			serverName: service.serverName,
			transport: service.server.type ?? "stdio",
			startCommand: service.startCommand,
			configPath: service.configPath,
			configPaths: { project: ".reverse/mcp.json", user: ".reverse/agent/mcp.json" },
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
			packageManager: step.packageManager ?? null,
			installCommand: step.command ?? null,
			installArgv: step.argv ?? null,
			installer: service.installer,
			riskNote: step.riskNote ?? "",
			manualUrl: service.manualUrl,
			manualInstructions: "",
			usage: service.usage,
		};
	}

	return null;
}

/** Probe for installed CLI binary using the canonical checkToolRequirements engine. */
function probeCliBinary(
	descriptor: SkillToolDescriptor,
	whichFn: SkillRequirementWhich,
	env: Record<string, string | undefined>,
	platform: SkillToolPlatform,
	options?: { settings?: Settings; cwd?: string },
): string | null {
	const npmPrefix =
		env?.NPM_CONFIG_PREFIX ??
		env?.npm_config_prefix ??
		process.env.NPM_CONFIG_PREFIX ??
		process.env.npm_config_prefix;

	const extraPaths: string[] = [];
	if (npmPrefix) {
		extraPaths.push(process.platform === "win32" ? npmPrefix : path.join(npmPrefix, "bin"));
	}

	const currentPath = env?.PATH ?? process.env.PATH ?? "";
	const combinedPath = [...extraPaths, ...currentPath.split(path.delimiter)].filter(Boolean).join(path.delimiter);

	const probeEnv: Record<string, string | undefined> = {
		...(descriptor.id === "ida" ? {} : process.env),
		...env,
		PATH: combinedPath,
	};

	const statuses = checkToolRequirements([{ id: descriptor.id }], {
		which: whichFn,
		platform,
		env: probeEnv,
		settings: options?.settings,
		cwd: options?.cwd,
	});
	const st = statuses[0];
	if (!st || !st.foundPath || (st.secondaryMissing && st.secondaryMissing.length > 0)) {
		return null;
	}
	return st.foundPath;
}

/**
 * Execute the full installation and configuration workflow for a reverse tool or MCP service.
 */
export async function installReverseItem(
	item: ReverseToolStatus | ReverseServiceStatus,
	options: ReverseInstallOptions = {},
): Promise<{ success: boolean; message?: string; activated?: boolean }> {
	if (item.id === "ida" && !options.env && options.settings) {
		options = { ...options, env: options.settings.getShellConfig().env };
	}
	const reqPlatform = options.platform ?? process.platform;
	const platform: SkillToolPlatform = reqPlatform === "darwin" || reqPlatform === "win32" ? reqPlatform : "linux";
	const which: SkillRequirementWhich = options.which ?? $which;
	const plan = options.plan ?? getReverseInstallPlan(item, options);
	if (options.plan && options.plan.item.id !== item.id) {
		return {
			success: false,
			message: `Plan item "${options.plan.item.id}" does not match target item "${item.id}".`,
		};
	}

	if (!plan.canInstall) {
		return {
			success: false,
			message:
				plan.reason ?? t("cli.setup.reverse.unsupported", `No automated installer available for ${item.name}.`),
		};
	}

	// Preflight validate all steps against trusted catalog before executing anything
	for (const step of plan.steps) {
		const canonical = makeCanonicalCatalogStatus(step);
		if (!canonical) {
			return { success: false, message: `Item "${step.id}" is not in the trusted catalog.` };
		}
		if (step.id === "jshookmcp") {
			const installDir = getJshookInstallDir(options.agentDir);
			const expectedArgv = [
				"npm",
				"install",
				"--prefix",
				installDir,
				"--save-exact",
				"--omit=dev",
				"--omit=optional",
				"--no-audit",
				"--no-fund",
				`${JSHOOK_PACKAGE_NAME}@${JSHOOK_PACKAGE_VERSION}`,
				`${WEBCRACK_PACKAGE_NAME}@${WEBCRACK_PACKAGE_VERSION}`,
			];
			if (
				!step.argv ||
				step.argv.length !== expectedArgv.length ||
				!step.argv.every((v, i) => v === expectedArgv[i])
			) {
				return {
					success: false,
					message: `Untrusted installation command for ${step.name}: argv does not match managed installer definition.`,
				};
			}
		} else if (
			step.installer === "portable" ||
			step.packageManager === "portable" ||
			step.installer === "unidbg" ||
			step.id === "unidbg" ||
			step.installer === "native-mcp" ||
			step.installer === "triton" ||
			step.id === "triton" ||
			step.installer === "lief" ||
			step.id === "lief" ||
			step.installer === "sofixer" ||
			step.id === "sofixer" ||
			step.installer === "ghidra-findcrypt" ||
			step.id === "ghidra-findcrypt" ||
			step.installer === "runtime-toolchain" ||
			step.id === "blutter" ||
			step.id === "hbctool" ||
			step.id === "hermes-dec" ||
			step.id === "il2cppdumper" ||
			step.installer === "protection-toolchain" ||
			isProtectionToolId(step.id)
		) {
			// Trusted internal portable/build/venv installer
		} else if (
			step.argv &&
			step.argv.length > 0 &&
			!isTrustedCatalogArgv(canonical, { settings: options.settings, cwd: options.cwd, env: options.env })
		) {
			return {
				success: false,
				message: `Untrusted installation command for ${step.name}: argv does not match catalog definition.`,
			};
		}
	}

	// Pre-configure environment for any already-present prerequisites (e.g. Node for playwright/jshook, Java for sdkmanager/jadx)
	const prePaths: string[] = [];
	let preJavaHome: string | undefined;

	const checkIds = new Set<string>();
	if (item.kind === "cli") {
		checkIds.add(item.id);
		const desc = SKILL_TOOL_CATALOG[item.id];
		for (const sec of desc?.secondary ?? []) checkIds.add(sec);
	} else if (item.kind === "mcp") {
		const service = getMcpService(item.id);
		for (const req of service?.requires ?? []) checkIds.add(req);
	}
	checkIds.add("java");
	checkIds.add("node");
	for (const step of plan.steps) {
		const managerTool = step.packageManager ? MANAGER_BOOTSTRAP_TOOL[step.packageManager] : undefined;
		if (managerTool) checkIds.add(managerTool);
	}

	for (const id of checkIds) {
		const desc = SKILL_TOOL_CATALOG[id];
		if (desc) {
			const found = probeCliBinary(desc, which, options.env ?? process.env, platform, {
				settings: options.settings,
				cwd: options.cwd,
			});
			if (found && path.isAbsolute(found)) {
				prePaths.push(path.dirname(found));
				if (id === "java" && !preJavaHome) {
					preJavaHome = resolveJavaHomeFromBinary(found) ?? undefined;
				}
			}
		}
	}

	if (prePaths.length > 0 || preJavaHome) {
		await persistToolEnvironment({ javaHome: preJavaHome, extraPaths: prePaths }, options.agentDir);
	}

	// Execute steps in plan order (dependencies first)
	for (const step of plan.steps) {
		const canonical = makeCanonicalCatalogStatus(step);
		if (!canonical) {
			return { success: false, message: `Item "${step.id}" is not in the trusted catalog.` };
		}

		if (step.kind === "cli") {
			const descriptor = SKILL_TOOL_CATALOG[step.id];
			if (!descriptor) {
				return { success: false, message: `Tool "${step.id}" not found in catalog.` };
			}

			if (!step.argv || step.argv.length === 0) {
				return { success: false, message: `No install command defined for ${step.name}.` };
			}
			if (step.installer === "unidbg" || step.id === "unidbg") {
				options.onChunk?.(`[reverse] Building Unidbg from source with verified JDK 8...\n`);
				const { buildUnidbg } = await import("./unidbg-builder");
				const javaHome = options.env?.JAVA_HOME ?? process.env.JAVA_HOME;
				const unidbgDir =
					options.env?.UNIDBG_HOME ??
					options.env?.UNIDBG_ROOT ??
					process.env.UNIDBG_HOME ??
					process.env.UNIDBG_ROOT;
				const mirror =
					options.env?.MAVEN_MIRROR === "default" || options.env?.REVERSE_MAVEN_MIRROR === "default"
						? "default"
						: "aliyun";

				const buildRes = await buildUnidbg({
					unidbgDir,
					javaHome,
					mirror,
					onLog: options.onChunk,
					signal: options.signal,
				});
				if (!buildRes.success) {
					return {
						success: false,
						message: buildRes.error ?? `Unidbg build failed with exit code ${buildRes.exitCode}`,
					};
				}
				await persistToolEnvironment(
					{
						javaHome,
						extraPaths: [buildRes.unidbgDir],
					},
					options.agentDir,
				);
				return {
					success: true,
					message: `Unidbg built successfully in ${buildRes.unidbgDir} (${buildRes.jarPaths.length} JARs compiled).`,
				};
			}

			if (step.installer === "triton" || step.id === "triton") {
				options.onChunk?.(`[reverse] Installing managed Triton symbolic execution environment...\n`);
				const tritonRes = await installTritonVenv({
					agentDir: options.agentDir,
					onChunk: options.onChunk,
					signal: options.signal,
					platform,
					env: options.env,
					which: bin => which(bin, { cache: WhichCachePolicy.Bypass }),
				});
				if (!tritonRes.success || !tritonRes.pythonPath) {
					return {
						success: false,
						message: tritonRes.message ?? "Triton installation failed.",
					};
				}
				const venvBinDir = path.dirname(tritonRes.pythonPath);
				await persistToolEnvironment(
					{
						extraPaths: [venvBinDir],
					},
					options.agentDir,
				);
				return {
					success: true,
					message: tritonRes.message,
				};
			}
			if (step.installer === "lief" || step.id === "lief") {
				options.onChunk?.(`[reverse] Installing managed LIEF environment...\n`);
				const liefRes = await installLiefVenv({
					agentDir: options.agentDir,
					onChunk: options.onChunk,
					signal: options.signal,
					platform,
					env: options.env,
					which: bin => which(bin, { cache: WhichCachePolicy.Bypass }),
				});
				if (!liefRes.success || !liefRes.pythonPath) {
					return {
						success: false,
						message: liefRes.message ?? "LIEF installation failed.",
					};
				}
				const venvBinDir = path.dirname(liefRes.pythonPath);
				await persistToolEnvironment(
					{
						extraPaths: [venvBinDir],
					},
					options.agentDir,
				);
				if (step.isDependency) {
					continue;
				}
				return {
					success: true,
					message: liefRes.message,
				};
			}

			if (step.installer === "sofixer" || step.id === "sofixer") {
				options.onChunk?.(`[reverse] Building SoFixer 32/64 executables from source...\n`);
				const sofixerRes = await buildAndInstallSoFixer({
					agentDir: options.agentDir,
					onLog: options.onChunk,
					signal: options.signal,
					platform,
					env: options.env,
					which: bin => which(bin, { cache: WhichCachePolicy.Bypass }),
				});
				if (!sofixerRes.success) {
					return {
						success: false,
						message: sofixerRes.error ?? "SoFixer build failed.",
					};
				}
				const binDir = path.join(sofixerRes.installDir, "bin");
				await persistToolEnvironment(
					{
						extraPaths: [binDir],
					},
					options.agentDir,
				);
				if (step.isDependency) {
					continue;
				}
				return {
					success: true,
					message: `SoFixer built and installed successfully into ${binDir} (${sofixerRes.binaries.join(", ")}).`,
				};
			}

			if (step.installer === "ghidra-findcrypt" || step.id === "ghidra-findcrypt") {
				options.onChunk?.(`[reverse] Building Ghidra FindCrypt extension matching Ghidra installation...\n`);
				const fcRes = await buildAndInstallGhidraFindCrypt({
					onLog: options.onChunk,
					signal: options.signal,
					platform,
					env: options.env,
					which: bin => which(bin, { cache: WhichCachePolicy.Bypass }),
				});
				if (!fcRes.success) {
					return {
						success: false,
						message: fcRes.error ?? "FindCrypt extension build failed.",
					};
				}
				if (step.isDependency) {
					continue;
				}
				return {
					success: true,
					message: `FindCrypt extension successfully built and installed to ${fcRes.extensionDir}.`,
				};
			}
			if (
				step.installer === "runtime-toolchain" ||
				step.id === "blutter" ||
				step.id === "hbctool" ||
				step.id === "hermes-dec" ||
				step.id === "il2cppdumper"
			) {
				options.onChunk?.(`[reverse] Installing managed runtime tool ${step.name}...\n`);

				const res = await installRuntimeTool(step.id as "blutter" | "hbctool" | "hermes-dec" | "il2cppdumper", {
					agentDir: options.agentDir,
					onLog: options.onChunk,
					signal: options.signal,
					which: bin => which(bin, { cache: WhichCachePolicy.Bypass }),
				});
				if (!res.success) {
					return {
						success: false,
						message: res.error ?? `Installation failed for ${step.name}.`,
					};
				}
				const binDir = path.dirname(res.executablePath);
				if (binDir && fs.existsSync(binDir)) {
					await persistToolEnvironment(
						{
							extraPaths: [binDir],
						},
						options.agentDir,
					);
				}
				if (step.isDependency) {
					continue;
				}
				return {
					success: true,
					message: `Successfully installed ${step.name}.`,
				};
			}
			if (step.installer === "protection-toolchain" || isProtectionToolId(step.id)) {
				options.onChunk?.(`[reverse] Installing managed protection tool ${step.name}...\n`);
				const res = await installProtectionTool(step.id as ProtectionToolId, {
					agentDir: options.agentDir,
					onChunk: options.onChunk,
					onLog: options.onChunk,
					signal: options.signal,
					platform,
					which: bin => which(bin, { cache: WhichCachePolicy.Bypass }),
				});
				if (!res.success) {
					return {
						success: false,
						message: res.error ?? `Installation failed for ${step.name}.`,
					};
				}
				const binDir = path.dirname(res.executablePath);
				const isVenvBin = binDir.includes(".venv");
				if (binDir && fs.existsSync(binDir) && !isVenvBin && path.basename(binDir) === "bin") {
					await persistToolEnvironment(
						{
							extraPaths: [binDir],
						},
						options.agentDir,
					);
				}
				if (step.isDependency) {
					continue;
				}
				return {
					success: true,
					message: res.message ?? `Successfully installed ${step.name}.`,
				};
			}

			if (step.installer === "portable" || step.packageManager === "portable") {
				options.onChunk?.(
					`[reverse] Installing portable ${step.isDependency ? "dependency " : ""}${step.name}...\n`,
				);
				const installRes = await installPortableTool(step.id, {
					agentDir: options.agentDir,
					onChunk: options.onChunk,
					signal: options.signal,
					platform,
				});
				if (!installRes.success) {
					return {
						success: false,
						message: installRes.message ?? `Portable installation failed for ${step.name}.`,
					};
				}
				const extraPaths = Array.from(
					new Set([...(installRes.binDirs ?? []), installRes.installDir, path.join(installRes.installDir, "bin")]),
				).filter(d => fs.existsSync(d));
				await persistToolEnvironment(
					{
						extraPaths,
					},
					options.agentDir,
				);
				const foundPath = probeCliBinary(descriptor, which, options.env ?? process.env, platform, {
					settings: options.settings,
					cwd: options.cwd,
				});
				if (!foundPath) {
					return {
						success: false,
						message: `Portable installation completed, but ${step.name} executable was not found on PATH or catalog search paths.`,
					};
				}
				continue;
			}

			// Validate strictly against catalog definitions before execution
			if (!isTrustedCatalogArgv(canonical, { settings: options.settings, cwd: options.cwd, env: options.env })) {
				return {
					success: false,
					message: `Untrusted installation command for ${step.name}: argv does not match catalog definition.`,
				};
			}
			// Skip re-executing dependency if it was already fulfilled earlier in this batch
			if (step.isDependency) {
				const already = probeCliBinary(descriptor, which, options.env ?? process.env, platform, {
					settings: options.settings,
					cwd: options.cwd,
				});
				if (already) {
					continue;
				}
			}

			options.onChunk?.(
				`[reverse] Installing ${step.isDependency ? "dependency " : ""}${step.name} (${step.command})...\n`,
			);

			let execRes: { exitCode: number; stdout: string; stderr: string };
			if (options.executor) {
				execRes = await options.executor(canonical.installArgv!, { onChunk: options.onChunk });
			} else {
				execRes = await executeSafeCatalogCommand(canonical, {
					allowNonTTY: true,
					isTTY: true,
					timeoutMs: 180_000,
					onChunk: options.onChunk,
					env: options.env,
					settings: options.settings,
					cwd: options.cwd,
				});
			}
			if (execRes.exitCode !== 0) {
				const combinedErr = `${execRes.stderr}\n${execRes.stdout}`;
				if (combinedErr.toLowerCase().includes("license") && combinedErr.toLowerCase().includes("not accepted")) {
					return {
						success: false,
						message: `Android SDK licenses have not been accepted yet. Please run 'sdkmanager --licenses' in your terminal to accept them.`,
					};
				}
				return {
					success: false,
					message:
						execRes.stderr.trim() ||
						execRes.stdout.trim() ||
						`Installation command failed with exit code ${execRes.exitCode}`,
				};
			}

			if (step.id === "ida") {
				clearIdaRuntimeCache();
			}
			const reprobeEnv =
				step.id === "ida" && (step.foundPath ?? (item as ReverseToolStatus).foundPath)
					? { ...(options.env ?? process.env), IDADIR: (step.foundPath ?? (item as ReverseToolStatus).foundPath)! }
					: (options.env ?? process.env);
			// Reprobe binary to ensure real usability (exit 0 alone does not prove success)
			const foundPath = probeCliBinary(descriptor, which, reprobeEnv, platform, {
				settings: options.settings,
				cwd: options.cwd,
			});
			if (!foundPath) {
				const licenseHint =
					step.packageManager === "sdkmanager"
						? " If the installation completed without writing binaries, ensure Android SDK licenses are accepted by running 'sdkmanager --licenses' in your terminal."
						: "";
				return {
					success: false,
					message: `Command completed with exit code 0, but ${step.name} executable was not found on PATH or catalog search paths.${licenseHint}`,
				};
			}

			if (step.id === "ida") {
				const idaDir = step.foundPath ?? (item as ReverseToolStatus).foundPath ?? foundPath;
				const pyProbe = probeIdaPythonEnvironment({
					installDir: idaDir,
					cwd: options.cwd,
					env: reprobeEnv,
					settings: options.settings,
				});
				if (!pyProbe.success) {
					return {
						success: false,
						message: `Installation command completed, but IDA Python adapter is not ready: ${pyProbe.errorReason}`,
					};
				}
			}

			// Persist narrow environment
			const toolDir = path.dirname(foundPath);
			const envPayload: { javaHome?: string; extraPaths: string[] } = {
				extraPaths: [toolDir],
			};

			if (step.id === "java") {
				const javaHome = resolveJavaHomeFromBinary(foundPath);
				if (javaHome) {
					envPayload.javaHome = javaHome;
				}
			}

			await persistToolEnvironment(envPayload, options.agentDir);
		} else if (step.kind === "mcp") {
			if (step.id === "jshookmcp") {
				try {
					const installed = await installJshookMcp({
						cwd: options.cwd ?? getProjectDir(),
						agentDir: options.agentDir,
						scope: "user",
						onChunk: options.onChunk,
						signal: options.signal,
					});

					let activated = false;
					if (options.mcpManager) {
						const loaded = await options.mcpManager.connectServers(
							{ [installed.serverName]: installed.server },
							{
								[installed.serverName]: {
									provider: "reverse",
									providerName: "reverse",
									path: installed.configPath,
									level: "user",
								},
							},
							undefined,
							installed.server.timeout ?? 120_000,
						);
						const connectError = loaded.errors.get(installed.serverName);
						if (connectError || options.mcpManager.getConnectionStatus(installed.serverName) !== "connected") {
							return {
								success: false,
								message: t(
									"cli.setup.reverse.serviceInstallFailed",
									`MCP service ${step.name} installed, but session connection failed: ${connectError ?? "connection incomplete"}`,
									{ name: step.name, error: connectError ?? "connection incomplete" },
								),
							};
						}
						await options.session?.refreshMCPTools(options.mcpManager.getTools());
						activated = true;
					}

					return {
						success: true,
						activated,
						message: t(
							"cli.setup.reverse.serviceInstallSuccess",
							`MCP service ${step.name} installed and configured successfully (config: ${installed.configPath}, tools: ${installed.tools.join(", ")}).`,
							{ name: step.name, path: installed.configPath, tools: installed.tools.join(", ") },
						),
					};
				} catch (err: unknown) {
					const msg = err instanceof Error ? err.message : String(err);
					return {
						success: false,
						message: t(
							"cli.setup.reverse.serviceInstallFailed",
							`MCP service ${step.name} installation failed: ${msg}`,
							{ name: step.name, error: msg },
						),
					};
				}
			} else if (
				step.installer === "native-mcp" ||
				step.id === "x64dbg-mcp" ||
				step.id === "ghidra-mcp" ||
				(step.kind === "mcp" && step.id === "r2mcp")
			) {
				try {
					const nativeService: NativeMcpService =
						step.id === "x64dbg-mcp" ? "x64dbg" : step.id === "ghidra-mcp" ? "ghidra" : "radare2";
					const installed = await installNativeMcpService(nativeService, {
						cwd: options.cwd ?? getProjectDir(),
						agentDir: options.agentDir,
						scope: "user",
						onChunk: options.onChunk,
						signal: options.signal,
					});

					let activated = false;
					if (options.mcpManager) {
						const loaded = await options.mcpManager.connectServers(
							{ [installed.serverName]: installed.server },
							{
								[installed.serverName]: {
									provider: "reverse",
									providerName: "reverse",
									path: installed.configPath,
									level: "user",
								},
							},
							undefined,
							installed.server.timeout ?? 120_000,
						);
						const connectError = loaded.errors.get(installed.serverName);
						if (connectError || options.mcpManager.getConnectionStatus(installed.serverName) !== "connected") {
							return {
								success: false,
								message: t(
									"cli.setup.reverse.serviceInstallFailed",
									`MCP service ${step.name} installed, but session connection failed: ${connectError ?? "connection incomplete"}`,
									{ name: step.name, error: connectError ?? "connection incomplete" },
								),
							};
						}
						await options.session?.refreshMCPTools(options.mcpManager.getTools());
						activated = true;
					}

					return {
						success: true,
						activated,
						message: t(
							"cli.setup.reverse.serviceInstallSuccess",
							`MCP service ${step.name} installed and configured successfully (config: ${installed.configPath}, tools: ${installed.tools.join(", ")}).`,
							{ name: step.name, path: installed.configPath, tools: installed.tools.join(", ") },
						),
					};
				} catch (err: unknown) {
					const msg = err instanceof Error ? err.message : String(err);
					return {
						success: false,
						message: t(
							"cli.setup.reverse.serviceInstallFailed",
							`MCP service ${step.name} installation failed: ${msg}`,
							{ name: step.name, error: msg },
						),
					};
				}
			} else {
				// Non-jshook MCP service (e.g. playwright-mcp, r2mcp)
				const service = getMcpService(step.id);
				if (!service) {
					return { success: false, message: `MCP service "${step.id}" not found in catalog.` };
				}

				if (step.argv && step.argv.length > 0) {
					if (!isTrustedCatalogArgv(canonical)) {
						return {
							success: false,
							message: `Untrusted installation command for ${step.name}: argv does not match catalog definition.`,
						};
					}

					options.onChunk?.(`[reverse] Installing MCP package for ${step.name} (${step.command})...\n`);
					let execRes: { exitCode: number; stdout: string; stderr: string };
					if (options.executor) {
						execRes = await options.executor(canonical.installArgv!, { onChunk: options.onChunk });
					} else {
						execRes = await executeSafeCatalogCommand(canonical, {
							allowNonTTY: true,
							isTTY: true,
							timeoutMs: 180_000,
							onChunk: options.onChunk,
						});
					}
					if (execRes.exitCode !== 0) {
						return {
							success: false,
							message:
								execRes.stderr.trim() ||
								execRes.stdout.trim() ||
								`MCP installation failed with exit code ${execRes.exitCode}`,
						};
					}
				}

				// Read user and project configs to resolve effective configuration
				const userConfigPath = path.join(options.agentDir ?? getAgentDir(), "mcp.json");
				const projectConfigPath = path.join(options.cwd ?? getProjectDir(), ".reverse", "mcp.json");
				const existingUserConfig = await readMCPConfigFile(userConfigPath);
				const existingProjectConfig = await readMCPConfigFile(projectConfigPath);
				const isProjectScope = Boolean(existingProjectConfig.mcpServers?.[service.serverName]);
				const chosenScope: "project" | "user" = isProjectScope ? "project" : "user";
				const chosenConfigPath = isProjectScope ? projectConfigPath : userConfigPath;
				const effectiveServerConfig =
					existingProjectConfig.mcpServers?.[service.serverName] ??
					existingUserConfig.mcpServers?.[service.serverName] ??
					service.server;
				if (step.serverConfigSnapshot !== JSON.stringify(effectiveServerConfig)) {
					return {
						success: false,
						message:
							"MCP configuration changed after review; reopen setup and confirm the updated launch configuration.",
					};
				}
				// Only write default to user config if unconfigured in both scopes
				if (
					!existingProjectConfig.mcpServers?.[service.serverName] &&
					!existingUserConfig.mcpServers?.[service.serverName]
				) {
					await updateMCPServer(userConfigPath, service.serverName, service.server);
				}

				// Enable server using canonical helper (clears stale disabledServers denylist)
				await setMcpServerEnabled({
					userPath: userConfigPath,
					projectPath: projectConfigPath,
					name: service.serverName,
					enabled: true,
				});

				const { expandEnvVarsDeep } = await import("../discovery/helpers");
				const runtimeServerConfig = expandEnvVarsDeep(effectiveServerConfig);

				// Standalone CLI verification: perform live handshake to ensure server is actually runnable
				if (!options.mcpManager && !options.executor) {
					const { connectToServer, disconnectServer, listTools } = await import("../mcp/client");
					let conn: MCPServerConnection | undefined;
					try {
						// 首次通过 npx 下载服务时，与交互会话使用相同的启动等待时间。
						const handshakeConfig = { ...runtimeServerConfig, timeout: runtimeServerConfig.timeout ?? 120_000 };
						conn = await connectToServer(service.serverName, handshakeConfig, { signal: options.signal });
						const tools = await listTools(conn);
						if (!tools) {
							return {
								success: false,
								message: `MCP service ${step.name} connected but failed to list tools.`,
							};
						}
					} catch (err: unknown) {
						const msg = err instanceof Error ? err.message : String(err);
						return {
							success: false,
							message: `MCP service ${step.name} failed verification handshake: ${msg}`,
						};
					} finally {
						if (conn) {
							await disconnectServer(conn).catch(() => {});
						}
					}
				}

				let activated = false;
				if (options.mcpManager) {
					const loaded = await options.mcpManager.connectServers(
						{ [service.serverName]: runtimeServerConfig },
						{
							[service.serverName]: {
								provider: "reverse",
								providerName: "reverse",
								path: chosenConfigPath,
								level: chosenScope,
							},
						},
						undefined,
						runtimeServerConfig.timeout ?? 120_000,
					);
					const connectErr = loaded.errors.get(service.serverName);
					if (connectErr || options.mcpManager.getConnectionStatus(service.serverName) !== "connected") {
						return {
							success: false,
							message: t(
								"cli.setup.reverse.serviceInstallFailed",
								`MCP service ${step.name} configured, but session connection failed: ${connectErr ?? "connection incomplete"}`,
								{ name: step.name, error: connectErr ?? "connection incomplete" },
							),
						};
					}
					await options.session?.refreshMCPTools(options.mcpManager.getTools());
					activated = true;
				}

				return {
					success: true,
					activated,
					message: t(
						"cli.setup.reverse.serviceInstallSuccess",
						`MCP service ${step.name} configured successfully (config: ${chosenConfigPath}).`,
						{ name: step.name, path: chosenConfigPath, tools: service.serverName },
					),
				};
			}
		}
	}

	// Reprobe the final target item to verify usability and persist its environment
	if (item.kind === "cli") {
		const desc = SKILL_TOOL_CATALOG[item.id];
		if (!desc) {
			return { success: false, message: `Tool "${item.id}" not found in catalog.` };
		}
		const finalReprobeEnv =
			item.id === "ida" && item.foundPath
				? { ...(options.env ?? process.env), IDADIR: item.foundPath }
				: (options.env ?? process.env);
		const finalPath = probeCliBinary(desc, which, finalReprobeEnv, platform, {
			settings: options.settings,
			cwd: options.cwd,
		});
		if (!finalPath) {
			return {
				success: false,
				message: `Installation steps finished, but ${item.name} executable was not found on PATH or catalog search paths.`,
			};
		}
		if (item.id === "ida") {
			const pyProbe = probeIdaPythonEnvironment({
				installDir: item.foundPath ?? finalPath,
				cwd: options.cwd,
				env: finalReprobeEnv,
				settings: options.settings,
			});
			if (!pyProbe.success) {
				return {
					success: false,
					message: `Installation steps finished, but IDA Python adapter is not ready: ${pyProbe.errorReason}`,
				};
			}
		}
		const extraPaths = [path.dirname(finalPath)];
		let javaHome: string | undefined;
		if (item.id === "java") {
			javaHome = resolveJavaHomeFromBinary(finalPath) ?? undefined;
		}
		for (const sec of desc.secondary ?? []) {
			const sDesc = SKILL_TOOL_CATALOG[sec];
			if (sDesc) {
				const secPath = probeCliBinary(sDesc, which, options.env ?? process.env, platform, {
					settings: options.settings,
					cwd: options.cwd,
				});
				if (secPath) {
					extraPaths.push(path.dirname(secPath));
					if (sec === "java" && !javaHome) {
						javaHome = resolveJavaHomeFromBinary(secPath) ?? undefined;
					}
				}
			}
		}
		await persistToolEnvironment({ javaHome, extraPaths }, options.agentDir);
	}

	return {
		success: true,
		message: `Successfully installed and configured ${item.name}.`,
	};
}

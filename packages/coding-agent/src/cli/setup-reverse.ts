/**
 * Universal reverse engineering toolchain setup and inspection panel.
 *
 * Provides a trusted, cross-platform CLI and TUI interface for checking and
 * manually installing external reverse tools (JADX, Apktool, ADB, Frida,
 * Radare2, IDA, UPX, etc.).
 *
 * Design principles:
 * - Explicit user trigger: Never run or prompted automatically by skill loading.
 * - Trusted catalog: Commands come strictly from {@link SKILL_TOOL_CATALOG};
 *   no untrusted strings from skills or network are ever executed.
 * - Interactive confirmation: Every single installation command requires explicit
 *   review and manual confirmation [y/N] before execution; no bypass flags allowed.
 * - Authorized setup path: Subprocess execution is only reachable through this
 *   explicit user confirmation boundary; non-interactive modes (--check, --json)
 *   are strictly read-only probes that never execute subprocesses.
 * - Package manager agnostic: Detects brew/apt/choco/winget/pipx/npm/cargo
 *   and falls back to clear manual download instructions when none is available.
 */
import { readFileSync } from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import { $which, APP_NAME, getMCPConfigPath, getProjectDir, WhichCachePolicy, type WhichOptions } from "@reverse/utils";
import chalk from "@reverse/utils/chalk";
import { theme } from "@reverse/tui/theme";
import { getCachedReadOnlySettings, getEffectiveLocale, loadEffectiveSettings } from "../config/persisted-locale";
import { isSettingsInitialized, settings, type Settings } from "../config/settings";
import {
	SKILL_TOOL_CATALOG,
	probeNativeDapAdapters,
	resolveReverseCapabilities,
	type PackageInstallCommand,
	type ReverseCapabilityStatus,
	type SkillToolPlatform,
	type ToolCategory,
	type ToolUsageGuide,
} from "../extensibility/skill-tool-catalog";
import { getMcpServices, mcpServerSnippet, type McpServiceTransport } from "../extensibility/mcp-service-catalog";
import type { MCPConfigFile } from "../mcp/types";
import {
	checkToolRequirements,
	type RequirementStatus,
	type SkillRequirementWhich,
} from "../extensibility/skill-requirements";
import { CLI_TRANSLATIONS_ZH_CN } from "../i18n/zh-CN/cli";
import { getJshookMcpServer, inspectJshookMcp } from "../extensibility/jshookmcp-install";
import { getNativeMcpServer, inspectNativeMcp, type NativeMcpService } from "../extensibility/native-mcp-install";
import { expandTilde } from "../tools/path-utils";
import { cfgDebugEnabled } from "../tools/settings";
export interface ReverseToolStatus {
	kind: "cli";
	id: string;
	name: string;
	category: ToolCategory;
	description: string;
	optional: boolean;
	systemTool: boolean;
	status: "installed" | "missing";
	foundPath: string | null;
	secondaryMissing?: string[];
	packageManager: string | null;
	installCommand: string | null;
	installArgv: readonly string[] | null;
	riskNote: string | null;
	manualUrl: string;
	manualInstructions: string;
	hint?: string;
	usage?: ToolUsageGuide;
}

export interface ReverseServiceConfigPaths {
	/** `mcp.json` used by the running rea install for the current project. */
	project: string;
	/** `mcp.json` used by the running rea install for the user/agent directory. */
	user: string;
}

/**
 * An optional MCP helper service. It is never a PATH binary.
 *
 * Three independent states are reported and must not be conflated:
 * - `prerequisitesReady` / `ready`: the catalogued prerequisite CLI tools exist.
 * - `configured`: an `mcpServers[serverName]` entry exists in a discovered
 *   user or project `mcp.json`.
 * - `enabled`: the configured entry is not disabled; `null` when unconfigured.
 *
 * `connection` is always `"unknown"`: this inspection is read-only and never
 * starts the server or performs an MCP handshake.
 */
export interface ReverseServiceStatus {
	kind: "mcp";
	id: string;
	name: string;
	category: ToolCategory;
	description: string;
	optional: true;
	license: string;
	serverName: string;
	transport: McpServiceTransport;
	startCommand: string;
	configPath: string;
	/** Exact config file candidates resolved from the running installation. */
	configPaths: ReverseServiceConfigPaths;
	configSnippet: Record<string, unknown>;
	prerequisites: RequirementStatus[];
	missingPrerequisites: string[];
	/** Explicit prerequisite-only readiness (the same value as `ready`). */
	prerequisitesReady: boolean;
	/** Backward-compatible alias for `prerequisitesReady`; never means connected. */
	ready: boolean;
	/** Whether an `mcpServers[serverName]` entry was found in either config file. */
	configured: boolean;
	/** Scopes whose mcp.json declares the server. */
	configuredScopes: Array<"user" | "project">;
	/** Effective enabled flag of the configured entry; `null` when unconfigured. */
	enabled: boolean | null;
	/** Connection is never probed by inspection. */
	connection: "unknown";
	status: "ready" | "missing";
	packageManager: string | null;
	installCommand: string | null;
	installArgv: readonly string[] | null;
	installer?: "jshookmcp" | "native-mcp";
	installed?: boolean;
	riskNote: string;
	manualUrl: string;
	manualInstructions: string;
	hint?: string;
	usage: ToolUsageGuide;
}

export interface ReverseCheckReport {
	ok: boolean;
	platform: SkillToolPlatform;
	detectedPackageManagers: string[];
	capabilities: ReverseCapabilityStatus[];
	tools: ReverseToolStatus[];
	/** Optional MCP helper services, kept out of `tools` so they are never reported as PATH binaries. */
	services: ReverseServiceStatus[];
	missingRequired: string[];
	missingOptional: string[];
}

export interface ReverseSetupFlags {
	json?: boolean;
	check?: boolean;
	execute?: boolean;
}

export interface ReverseSetupDeps {
	which?: SkillRequirementWhich;
	platform?: NodeJS.Platform;
	env?: Record<string, string | undefined>;
	/** Project directory used to resolve `.reverse/mcp.json`; defaults to the active project. */
	cwd?: string;
	/** Read-only MCP config probe; defaults to reading the resolved file synchronously. */
	readMcpConfig?: (filePath: string) => MCPConfigFile | null;
	executor?: (
		argv: readonly string[],
		options?: { onChunk?: (chunk: string) => void },
	) => Promise<{ exitCode: number; stdout: string; stderr: string }>;
	promptLine?: (question: string) => Promise<string>;
	confirm?: (question: string) => Promise<boolean>;
	writeStdout?: (chunk: string) => void;
	writeStderr?: (chunk: string) => void;
	isTTY?: boolean;
	/** Agent profile directory; defaults to getAgentDir() for managed tools. */
	agentDir?: string;
	settings?: Settings;
}

/** Read an MCP config file without writing or starting anything. */
export function readMcpConfigFileSync(filePath: string): MCPConfigFile | null {
	try {
		const parsed: unknown = JSON.parse(readFileSync(filePath, "utf8"));
		if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
		return parsed as MCPConfigFile;
	} catch {
		return null;
	}
}

export function t(key: string, fallback: string, vars?: Record<string, string>): string {
	const locale = getEffectiveLocale();
	let text = locale === "zh-CN" ? (CLI_TRANSLATIONS_ZH_CN[key] ?? fallback) : fallback;
	if (vars) {
		for (const [k, v] of Object.entries(vars)) {
			text = text.replaceAll(`{${k}}`, v);
		}
	}
	return text;
}

/** Detect installed package managers on the host system. */
export function detectPackageManagers(
	platform: SkillToolPlatform,
	which: SkillRequirementWhich,
	env: Record<string, string | undefined> = process.env,
): string[] {
	const candidates: Record<SkillToolPlatform, readonly string[]> = {
		darwin: ["brew", "pipx", "pip", "python3", "npm", "cargo", "r2pm", "sdkmanager"],
		linux: [
			"apt",
			"apt-get",
			"pacman",
			"dnf",
			"brew",
			"pipx",
			"pip",
			"python3",
			"npm",
			"cargo",
			"r2pm",
			"sdkmanager",
		],
		win32: ["winget", "choco", "scoop", "pipx", "pip", "py", "npm", "cargo", "r2pm", "sdkmanager", "portable"],
	};
	const options: WhichOptions = { cache: WhichCachePolicy.Bypass, requireAbsolutePaths: true };
	const separator = platform === "win32" ? ";" : path.delimiter;
	const basePath = env.PATH ?? "";
	const androidHome = env.ANDROID_HOME ?? env.ANDROID_SDK_ROOT;
	const androidDirs = androidHome
		? [path.join(androidHome, "cmdline-tools", "latest", "bin"), path.join(androidHome, "cmdline-tools", "bin")]
		: [];
	const extraDirs: string[] =
		platform === "win32"
			? [
					path.win32.normalize(expandTilde("~/AppData/Local/Programs/Python/Python312/Scripts")),
					path.win32.normalize(expandTilde("~/AppData/Roaming/npm")),
					path.win32.normalize(expandTilde("~/AppData/Local/Android/Sdk/cmdline-tools/latest/bin")),
					path.win32.normalize(expandTilde("~/AppData/Local/Android/Sdk/cmdline-tools/bin")),
					...androidDirs,
				]
			: [
					"/opt/homebrew/bin",
					"/usr/local/bin",
					expandTilde("~/.local/bin"),
					"/snap/bin",
					expandTilde("~/Library/Android/sdk/cmdline-tools/latest/bin"),
					expandTilde("~/Library/Android/sdk/cmdline-tools/bin"),
					expandTilde("~/Android/Sdk/cmdline-tools/latest/bin"),
					expandTilde("~/Android/Sdk/cmdline-tools/bin"),
					...androidDirs,
				];
	const searchPath = [basePath, ...extraDirs].filter(Boolean).join(separator);
	if (searchPath) {
		options.PATH = searchPath;
	}
	const found: string[] = [];
	for (const candidate of candidates[platform] ?? []) {
		if (candidate === "portable" || which(candidate, options) !== null) {
			found.push(candidate);
		}
	}
	return found;
}

function isManagerAvailable(manager: string, availableManagers: readonly string[]): boolean {
	if (availableManagers.includes(manager)) return true;
	if (manager === "portable") return true;
	if (manager === "apt" && availableManagers.includes("apt-get")) return true;
	if (manager === "pip" && (availableManagers.includes("python3") || availableManagers.includes("py"))) return true;
	return false;
}

function selectInstallCommand(
	descriptor: { installCommands?: Partial<Record<SkillToolPlatform, readonly PackageInstallCommand[]>> },
	platform: SkillToolPlatform,
	availableManagers: readonly string[],
): PackageInstallCommand | undefined {
	const commands = descriptor.installCommands?.[platform] ?? [];
	for (const cmd of commands) {
		if (isManagerAvailable(cmd.manager, availableManagers)) {
			return cmd;
		}
	}
	return undefined;
}

/**
 * Check all reverse engineering tools in the catalog and resolve their
 * availability and installation paths for the current machine.
 */
export function checkReverseTools(deps: ReverseSetupDeps = {}): ReverseCheckReport {
	const requestedPlatform = deps.platform ?? process.platform;
	const platform: SkillToolPlatform =
		requestedPlatform === "darwin" || requestedPlatform === "win32" ? requestedPlatform : "linux";
	const which: SkillRequirementWhich = deps.which ?? $which;
	const detectedPackageManagers = detectPackageManagers(platform, which, deps.env);
	const descriptors = Object.values(SKILL_TOOL_CATALOG);
	const toolRequirements = descriptors.map(desc => ({ id: desc.id, optional: desc.optional ?? true }));
	const effectiveSettings = deps.settings ?? (isSettingsInitialized() ? settings : getCachedReadOnlySettings());
	const statuses = checkToolRequirements(toolRequirements, {
		platform: requestedPlatform,
		which,
		env: deps.env,
		settings: effectiveSettings,
	});
	const statusById: Record<string, RequirementStatus> = Object.fromEntries(statuses.map(s => [s.id, s]));

	const tools: ReverseToolStatus[] = [];
	const missingRequired: string[] = [];
	const missingOptional: string[] = [];

	for (const desc of descriptors) {
		const reqStatus = statusById[desc.id];
		const foundPath = reqStatus?.foundPath ?? null;
		const secondaryMissing = reqStatus?.secondaryMissing;
		const isInstalled = foundPath !== null && (!secondaryMissing || secondaryMissing.length === 0);

		const isOptional = desc.optional ?? true;
		if (!isInstalled) {
			if (isOptional) missingOptional.push(desc.id);
			else missingRequired.push(desc.id);
		}

		const chosenCmd = isInstalled ? undefined : selectInstallCommand(desc, platform, detectedPackageManagers);
		const manualGuide =
			desc.manualInstructions?.[platform] ??
			(desc.manualUrl ? `See official instructions at ${desc.manualUrl}` : "Manual setup required.");

		tools.push({
			kind: "cli",
			id: desc.id,
			name: desc.name ?? desc.id,
			category: desc.category ?? "general",
			description: desc.description ?? "",
			optional: isOptional,
			systemTool: desc.systemTool ?? false,
			status: isInstalled ? "installed" : "missing",
			foundPath,
			...(secondaryMissing && secondaryMissing.length > 0 && { secondaryMissing }),
			packageManager: chosenCmd?.manager ?? null,
			installCommand: chosenCmd?.command ?? null,
			installArgv: chosenCmd?.argv && chosenCmd.argv.length > 0 ? chosenCmd.argv : null,
			riskNote: chosenCmd?.riskNote ?? null,
			manualUrl: desc.manualUrl ?? "",
			manualInstructions: manualGuide,
			hint: desc.installHints?.[platform]?.join(" or "),
			usage: desc.usage,
		});
	}

	// Service prerequisites are catalogued CLI tools, but keep the fallback for
	// future entries whose ids are not yet in the CLI catalog: an unknown id is
	// probed on PATH and never claims to be an installed service.
	const serviceDescriptors = getMcpServices().filter(desc => !desc.platforms || desc.platforms.includes(platform));
	const uncoveredRequirementIds = [
		...new Set(serviceDescriptors.flatMap(desc => desc.requires).filter(id => !statusById[id])),
	];
	const uncoveredStatuses =
		uncoveredRequirementIds.length > 0
			? checkToolRequirements(
					uncoveredRequirementIds.map(id => ({ id, optional: true })),
					{ platform: requestedPlatform, which, env: deps.env },
				)
			: [];
	for (const status of uncoveredStatuses) statusById[status.id] = status;

	// Resolve the real config candidates from the running installation instead of
	// repeating the catalog's display hint. Reading is probe-only: no file is
	// written and no server is launched.
	const cwd = deps.cwd ?? getProjectDir();
	const userConfigPath = deps.agentDir ? path.join(deps.agentDir, "mcp.json") : getMCPConfigPath("user", cwd);
	const configPaths: ReverseServiceConfigPaths = {
		project: getMCPConfigPath("project", cwd),
		user: userConfigPath,
	};
	const readConfig = deps.readMcpConfig ?? readMcpConfigFileSync;
	const configFiles: Record<"user" | "project", MCPConfigFile | null> = {
		project: readConfig(configPaths.project),
		user: readConfig(configPaths.user),
	};

	const services: ReverseServiceStatus[] = serviceDescriptors.map(desc => {
		const prerequisites = desc.requires
			.map(id => statusById[id])
			.filter((status): status is RequirementStatus => status !== undefined);
		const missingPrerequisites = prerequisites
			.filter(status => status.foundPath === null || (status.secondaryMissing?.length ?? 0) > 0)
			.map(status => status.id);
		const prereqsReady = missingPrerequisites.length === 0;

		let installed: boolean | undefined = undefined;
		if (desc.installer === "jshookmcp") {
			const inspection = inspectJshookMcp({ agentDir: deps.agentDir });
			installed = inspection.installed;
		} else if (desc.installer === "native-mcp") {
			const serviceKey: NativeMcpService =
				desc.id === "x64dbg-mcp" ? "x64dbg" : desc.id === "ghidra-mcp" ? "ghidra" : "radare2";
			const inspection = inspectNativeMcp(serviceKey, { agentDir: deps.agentDir, env: deps.env });
			installed = inspection.installed;
		}

		// Config presence is checked per scope. `enabled` stays null when the
		// service is unconfigured: connection state cannot be observed without
		// starting the server, which inspection never does.
		const configuredScopes: Array<"user" | "project"> = [];
		let enabled: boolean | null = null;
		for (const scope of ["project", "user"] as const) {
			const file = configFiles[scope];
			const entry = file?.mcpServers?.[desc.serverName];
			if (!entry || typeof entry !== "object") continue;
			configuredScopes.push(scope);
			const scopeEnabled =
				!file?.disabledServers?.includes(desc.serverName) &&
				(entry.enabled !== false || (file?.enabledServers?.includes(desc.serverName) ?? false));
			enabled = enabled === null ? scopeEnabled : enabled || scopeEnabled;
		}
		const configured = configuredScopes.length > 0;
		// Readiness for managed services requires prerequisites (e.g. Node), managed package installed,
		// and not explicitly disabled. For other services, readiness remains prerequisite-only.
		const ready =
			desc.installer === "jshookmcp" || desc.id === "x64dbg-mcp" || desc.id === "ghidra-mcp"
				? prereqsReady && installed === true && enabled !== false
				: prereqsReady;

		// Readiness means the prerequisite CLI tools exist, not that the server
		// package is installed. Offer the catalog install command in both states;
		// execution still requires the explicit interactive confirmation below.
		const chosenCmd = selectInstallCommand(desc, platform, detectedPackageManagers);
		const manualGuide = desc.manualInstructions[platform] ?? `See official instructions at ${desc.manualUrl}`;

		return {
			kind: "mcp",
			id: desc.id,
			name: desc.name,
			category: desc.category,
			description:
				desc.installer === "jshookmcp" ? t("cli.setup.reverse.jshookmcp.desc", desc.description) : desc.description,
			optional: true,
			license: desc.license,
			serverName: desc.serverName,
			transport: desc.server.type ?? "stdio",
			startCommand:
				desc.installer === "jshookmcp"
					? `${getJshookMcpServer({ agentDir: deps.agentDir }).command} ${(getJshookMcpServer({ agentDir: deps.agentDir }).args ?? []).join(" ")}`
					: desc.installer === "native-mcp"
						? `${getNativeMcpServer(desc.id === "x64dbg-mcp" ? "x64dbg" : desc.id === "ghidra-mcp" ? "ghidra" : "radare2", { agentDir: deps.agentDir }).command} ${(getNativeMcpServer(desc.id === "x64dbg-mcp" ? "x64dbg" : desc.id === "ghidra-mcp" ? "ghidra" : "radare2", { agentDir: deps.agentDir }).args ?? []).join(" ")}`.trim()
						: desc.startCommand,
			configPath: desc.configPath,
			configPaths,
			configSnippet:
				desc.installer === "jshookmcp"
					? { mcpServers: { [desc.serverName]: getJshookMcpServer({ agentDir: deps.agentDir }) } }
					: desc.id === "x64dbg-mcp" || desc.id === "ghidra-mcp"
						? {
								mcpServers: {
									[desc.serverName]: getNativeMcpServer(desc.id === "x64dbg-mcp" ? "x64dbg" : "ghidra", {
										agentDir: deps.agentDir,
									}),
								},
							}
						: { ...mcpServerSnippet(desc) },
			prerequisites,
			missingPrerequisites,
			prerequisitesReady: prereqsReady,
			ready,
			configured,
			configuredScopes,
			enabled,
			connection: "unknown",
			status: ready ? "ready" : "missing",
			packageManager: chosenCmd?.manager ?? null,
			installCommand: chosenCmd?.command ?? null,
			installArgv: chosenCmd?.argv && chosenCmd.argv.length > 0 ? chosenCmd.argv : null,
			installer: desc.installer,
			installed,
			riskNote:
				desc.installer === "jshookmcp"
					? t("cli.setup.reverse.jshookmcp.risk", desc.riskNote)
					: desc.installer === "native-mcp"
						? t(`cli.setup.reverse.${desc.id}.risk`, desc.riskNote)
						: (chosenCmd?.riskNote ?? desc.riskNote),
			manualUrl: desc.manualUrl,
			manualInstructions: manualGuide,
			hint: desc.installHints?.[platform]?.join(" or "),
			usage: desc.usage,
		};
	});

	const dapAdapters = probeNativeDapAdapters({ cwd: deps.cwd, which });
	const capabilities = resolveReverseCapabilities({
		platform,
		toolStatuses: tools,
		serviceStatuses: services,
		cwd: deps.cwd,
		dapAdapters,
		debugToolEnabled: effectiveSettings ? cfgDebugEnabled.get(effectiveSettings) : true,
	});

	return {
		ok: missingRequired.length === 0,
		platform,
		detectedPackageManagers,
		capabilities,
		tools,
		services,
		missingRequired,
		missingOptional,
	};
}

/** Verify that an item's installArgv strictly originates from the trusted catalog. */
export function isTrustedCatalogArgv(item: ReverseToolStatus | ReverseServiceStatus): boolean {
	if (!item.installArgv || item.installArgv.length === 0) {
		return false;
	}

	if (item.kind === "cli") {
		const desc = SKILL_TOOL_CATALOG[item.id];
		if (!desc || !desc.installCommands) return false;
		if (item.packageManager === "portable") return true;
		for (const cmds of Object.values(desc.installCommands)) {
			if (!cmds) continue;
			for (const cmd of cmds) {
				if (
					cmd.argv &&
					cmd.argv.length === item.installArgv.length &&
					cmd.argv.every((val, idx) => val === item.installArgv![idx])
				) {
					return true;
				}
			}
		}
		return false;
	}

	if (item.kind === "mcp") {
		const services = getMcpServices();
		const service = services.find(s => s.id === item.id);
		if (!service || !service.installCommands) return false;
		for (const cmds of Object.values(service.installCommands)) {
			if (!cmds) continue;
			for (const cmd of cmds) {
				if (
					cmd.argv &&
					cmd.argv.length === item.installArgv.length &&
					cmd.argv.every((val, idx) => val === item.installArgv![idx])
				) {
					return true;
				}
			}
		}
		return false;
	}

	return false;
}

/**
 * Safely execute a catalog installation command for TUI.
 * - Refuses non-TTY execution unless allowNonTTY is explicitly provided.
 * - Subprocess stdin is ignored (never blocks or hijacks TUI keyboard).
 * - Enforces catalog argv validation (rejects untrusted/tampered argv).
 */
export async function executeSafeCatalogCommand(
	item: ReverseToolStatus | ReverseServiceStatus,
	options?: {
		timeoutMs?: number;
		onChunk?: (chunk: string) => void;
		allowNonTTY?: boolean;
		isTTY?: boolean;
		env?: Record<string, string | undefined>;
	},
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
	if (!isTrustedCatalogArgv(item)) {
		return {
			exitCode: 1,
			stdout: "",
			stderr: `Untrusted installation command for ${item.name}: argv does not match catalog definition.`,
		};
	}

	const isTTY = options?.isTTY ?? (options?.allowNonTTY ? true : Boolean(process.stdin.isTTY && process.stdout.isTTY));
	if (!isTTY) {
		return {
			exitCode: 1,
			stdout: "",
			stderr: "TUI installation executor requires an interactive TTY.",
		};
	}

	const argv = item.installArgv!;
	const timeout = options?.timeoutMs ?? 180_000;

	const whichOptions: WhichOptions = { cache: WhichCachePolicy.Bypass, requireAbsolutePaths: true };
	const platform: SkillToolPlatform =
		process.platform === "darwin" || process.platform === "win32" ? process.platform : "linux";
	const separator = platform === "win32" ? ";" : path.delimiter;
	const effectiveEnv = options?.env ?? process.env;
	const basePath = effectiveEnv.PATH ?? "";
	const androidHome = effectiveEnv.ANDROID_HOME ?? effectiveEnv.ANDROID_SDK_ROOT;
	const androidDirs = androidHome
		? [path.join(androidHome, "cmdline-tools", "latest", "bin"), path.join(androidHome, "cmdline-tools", "bin")]
		: [];
	const extraDirs: string[] =
		platform === "win32"
			? [
					path.win32.normalize(expandTilde("~/AppData/Local/Programs/Python/Python312/Scripts")),
					path.win32.normalize(expandTilde("~/AppData/Roaming/npm")),
					path.win32.normalize(expandTilde("~/AppData/Local/Android/Sdk/cmdline-tools/latest/bin")),
					path.win32.normalize(expandTilde("~/AppData/Local/Android/Sdk/cmdline-tools/bin")),
					...androidDirs,
				]
			: [
					"/opt/homebrew/bin",
					"/usr/local/bin",
					expandTilde("~/.local/bin"),
					"/snap/bin",
					expandTilde("~/Library/Android/sdk/cmdline-tools/latest/bin"),
					expandTilde("~/Library/Android/sdk/cmdline-tools/bin"),
					expandTilde("~/Android/Sdk/cmdline-tools/latest/bin"),
					expandTilde("~/Android/Sdk/cmdline-tools/bin"),
					...androidDirs,
				];
	const allDirs = [basePath, ...extraDirs].join(separator).split(separator).filter(Boolean);
	const safePathDirs = allDirs.filter(d => path.isAbsolute(d));
	const safeSearchPath = safePathDirs.join(separator);
	whichOptions.PATH = safeSearchPath;

	const resolvedBinary = path.isAbsolute(argv[0]) ? argv[0] : $which(argv[0], whichOptions);
	if (!resolvedBinary) {
		return {
			exitCode: 1,
			stdout: "",
			stderr: `Cannot safely resolve trusted binary "${argv[0]}" to an absolute path in catalog search paths.`,
		};
	}
	const effectiveArgv = [resolvedBinary, ...argv.slice(1)];
	const spawnEnv = { ...effectiveEnv, PATH: safeSearchPath };

	if (typeof Bun !== "undefined" && typeof Bun.spawn === "function") {
		const proc = Bun.spawn(effectiveArgv as string[], {
			stdin: "ignore",
			stdout: "pipe",
			stderr: "pipe",
			env: spawnEnv,
		});
		let stdout = "";
		let stderr = "";
		const readStream = async (stream: ReadableStream<Uint8Array>, isErr: boolean) => {
			const reader = stream.getReader();
			const decoder = new TextDecoder();
			try {
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					const text = decoder.decode(value, { stream: true });
					if (isErr) stderr += text;
					else stdout += text;
					options?.onChunk?.(text);
				}
			} finally {
				reader.releaseLock();
			}
		};

		let timer: ReturnType<typeof setTimeout> | undefined;
		const timeoutPromise = new Promise<{ timeout: true }>(resolve => {
			timer = setTimeout(() => resolve({ timeout: true }), timeout);
		});

		const runPromise = Promise.all([
			readStream(proc.stdout as ReadableStream<Uint8Array>, false),
			readStream(proc.stderr as ReadableStream<Uint8Array>, true),
		]).then(async () => {
			const exitCode = await proc.exited;
			return { exitCode, stdout, stderr };
		});

		try {
			const res = await Promise.race([runPromise, timeoutPromise]);
			if ("timeout" in res) {
				proc.kill();
				return { exitCode: 124, stdout, stderr: `${stderr}\nExecution timed out after ${timeout}ms.` };
			}
			return res;
		} finally {
			if (timer) clearTimeout(timer);
		}
	}

	const { spawn } = await import("node:child_process");
	const { promise, resolve } = Promise.withResolvers<{ exitCode: number; stdout: string; stderr: string }>();
	let stdout = "";
	let stderr = "";
	let settled = false;

	const child = spawn(effectiveArgv[0], effectiveArgv.slice(1), { stdio: ["ignore", "pipe", "pipe"], env: spawnEnv });
	const timer = setTimeout(() => {
		if (!settled) {
			settled = true;
			child.kill("SIGKILL");
			resolve({ exitCode: 124, stdout, stderr: `${stderr}\nExecution timed out after ${timeout}ms.` });
		}
	}, timeout);

	child.stdout?.on("data", chunk => {
		const text = String(chunk);
		stdout += text;
		options?.onChunk?.(text);
	});
	child.stderr?.on("data", chunk => {
		const text = String(chunk);
		stderr += text;
		options?.onChunk?.(text);
	});
	child.on("close", code => {
		if (!settled) {
			settled = true;
			clearTimeout(timer);
			resolve({ exitCode: code ?? 1, stdout, stderr });
		}
	});
	child.on("error", err => {
		if (!settled) {
			settled = true;
			clearTimeout(timer);
			resolve({ exitCode: 1, stdout, stderr: err.message });
		}
	});

	return promise;
}
function runDefaultPrompt(question: string): Promise<string> {
	const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
	const { promise, resolve } = Promise.withResolvers<string>();
	let settled = false;

	const finish = (val: string) => {
		if (settled) return;
		settled = true;
		process.off("SIGINT", onSigint);
		rl.off("SIGINT", onSigint);
		rl.off("close", onClose);
		rl.close();
		process.stdin.pause();
		resolve(val);
	};

	const onSigint = () => {
		if (settled) return;
		finish("");
		process.exit(130);
	};

	const onClose = () => {
		finish("");
	};

	rl.once("SIGINT", onSigint);
	process.once("SIGINT", onSigint);
	rl.once("close", onClose);

	rl.question(question, answer => {
		finish(answer.trim());
	});

	return promise;
}

async function runDefaultConfirm(question: string): Promise<boolean> {
	const answer = (await runDefaultPrompt(question)).toLowerCase();
	return answer === "y" || answer === "yes";
}

function renderToolTable(report: ReverseCheckReport, write: (text: string) => void): void {
	const colIndex = " #".padEnd(4);
	const colStatus = "Status".padEnd(11);
	const colTool = "Tool".padEnd(16);
	const colCategory = "Category".padEnd(12);
	const colType = "Type".padEnd(10);
	const colDetail = "Details / Install Method";

	write(`\n${chalk.dim("--------------------------------------------------------------------------------")}\n`);
	write(`${chalk.bold(colIndex + colStatus + colTool + colCategory + colType + colDetail)}\n`);
	write(`${chalk.dim("--------------------------------------------------------------------------------")}\n`);

	report.tools.forEach((tool, index) => {
		const idxStr = ` ${index + 1}`.padEnd(4);
		const isOk = tool.status === "installed";
		const statusBadge = isOk
			? chalk.green("[OK]".padEnd(11))
			: tool.optional
				? chalk.yellow("[MISSING]".padEnd(11))
				: chalk.red("[MISSING]".padEnd(11));
		const toolStr = chalk.bold(tool.id.padEnd(16));
		const catStr = chalk.cyan(tool.category.padEnd(12));
		const typeStr = tool.optional ? chalk.dim("optional".padEnd(10)) : chalk.magenta("required".padEnd(10));

		let detailStr = "";
		if (isOk) {
			const secondaryNote =
				tool.secondaryMissing && tool.secondaryMissing.length > 0
					? chalk.yellow(` [Missing prerequisite: ${tool.secondaryMissing.join(", ")}]`)
					: "";
			detailStr = `${chalk.dim(tool.foundPath ?? "found")}${secondaryNote}`;
		} else if (tool.installCommand) {
			detailStr = `${chalk.blue(`[${tool.packageManager}]`)} ${tool.installCommand}`;
		} else {
			detailStr = chalk.gray(`Manual (${tool.manualUrl ? "see download URL" : tool.manualInstructions})`);
		}

		write(`${idxStr}${statusBadge}${toolStr}${catStr}${typeStr}${detailStr}\n`);
	});
	write(`${chalk.dim("--------------------------------------------------------------------------------")}\n\n`);
}

function renderServiceTable(report: ReverseCheckReport, write: (text: string) => void): void {
	if (report.services.length === 0) return;
	write(`\n${chalk.bold("Optional MCP helper services")}\n`);
	write(
		`${chalk.dim("These are MCP servers, not PATH binaries. Prerequisites and mcp.json entries are probed read-only; connection is never verified.")}\n`,
	);
	write(`${chalk.dim("--------------------------------------------------------------------------------")}\n`);
	write(
		`${chalk.bold(" #".padEnd(4) + "Prereqs".padEnd(11) + "Service".padEnd(20) + "Category".padEnd(12) + "Transport".padEnd(11) + "Prerequisites / Config / Setup")}\n`,
	);
	write(`${chalk.dim("--------------------------------------------------------------------------------")}\n`);

	report.services.forEach((service, index) => {
		const idxStr = ` ${index + 1}`.padEnd(4);
		const isConfiguredOnly = service.ready && service.configured;
		const statusBadge = isConfiguredOnly
			? chalk.cyan("[CONFIG]".padEnd(11))
			: service.ready
				? chalk.yellow("[PREREQ]".padEnd(11))
				: chalk.yellow("[MISSING]".padEnd(11));
		const serviceStr = chalk.bold(service.id.padEnd(20));
		const catStr = chalk.cyan(service.category.padEnd(12));
		const transportStr = chalk.dim(service.transport.padEnd(11));
		const configStr = service.configured
			? `configured (${service.configuredScopes.join(", ")})${service.enabled === false ? ", disabled" : ""}`
			: "not configured";
		let detailStr: string;
		if (
			service.ready &&
			((service.installer !== "native-mcp" && service.installer !== "jshookmcp") || service.installed === true)
		) {
			detailStr = `${chalk.dim(`prerequisites ok: ${service.prerequisites.map(p => p.id).join(", ") || "none"}; ${configStr}`)}`;
		} else if (service.installer === "jshookmcp" || service.installer === "native-mcp") {
			const managedStatus = service.installed
				? t("cli.setup.reverse.managedStatusInstalled", "package installed")
				: t("cli.setup.reverse.managedStatusMissing", "package not installed");
			detailStr = `${chalk.blue("[managed]")} ${managedStatus} ${chalk.dim(`(${configStr})`)}`;
		} else if (service.installCommand) {
			detailStr = `${chalk.blue(`[${service.packageManager}]`)} ${service.installCommand} ${chalk.dim(`(${configStr})`)}`;
		} else {
			detailStr = `${chalk.gray(`Manual (${service.manualUrl})`)} ${chalk.dim(`(${configStr})`)}`;
		}
		write(`${idxStr}${statusBadge}${serviceStr}${catStr}${transportStr}${detailStr}\n`);
	});
	write(`${chalk.dim("--------------------------------------------------------------------------------")}\n\n`);
}
function renderCapabilityTable(report: ReverseCheckReport, write: (text: string) => void): void {
	if (!report.capabilities || report.capabilities.length === 0) return;
	write(`\n${chalk.bold("Reverse engineering capability overview")}\n`);
	write(
		`${chalk.dim("High-level reverse capabilities mapped to native tools, external packages, fallbacks, and dispatch.")}\n`,
	);
	write(`${chalk.dim("--------------------------------------------------------------------------------")}\n`);
	const colIndex = " #".padEnd(4);
	const colStatus = "Status".padEnd(14);
	const colCap = "Capability".padEnd(28);
	const colCategory = "Category".padEnd(12);
	const colDetail = "Primary / Native / Fallbacks";

	write(`${chalk.bold(colIndex + colStatus + colCap + colCategory + colDetail)}\n`);
	write(`${chalk.dim("--------------------------------------------------------------------------------")}\n`);

	report.capabilities.forEach((cap, index) => {
		const idxStr = ` ${index + 1}`.padEnd(4);
		const statusBadge =
			cap.status === "ready"
				? chalk.green("[READY]".padEnd(14))
				: cap.status === "available_with_fallbacks"
					? chalk.cyan("[FALLBACKS]".padEnd(14))
					: chalk.yellow("[MISSING]".padEnd(14));
		const capStr = chalk.bold(cap.id.padEnd(28));
		const catStr = chalk.cyan(cap.category.padEnd(12));
		const toolsDesc = cap.optionalExternalTools
			.map(t => (t.status === "installed" || t.status === "ready" ? chalk.green(t.id) : chalk.dim(t.id)))
			.join(", ");
		const nativeDesc = cap.recommendedNativeTool ? ` [native: ${cap.recommendedNativeTool}]` : "";
		const fallbackDesc =
			cap.availableFallbacks.length > 0 ? ` [fallback: ${cap.availableFallbacks.slice(0, 2).join(", ")}]` : "";
		write(`${idxStr}${statusBadge}${capStr}${catStr}${toolsDesc}${nativeDesc}${fallbackDesc}\n`);
	});
	write(`${chalk.dim("--------------------------------------------------------------------------------")}\n\n`);
}

/**
 * Handle reverse tools setup: report `--json` / `--check` or render
 * interactive panel with manual tool selection, pre-install confirmation,
 * safe catalog execution, and status refresh.
 */
export async function handleReverseSetup(
	flags: ReverseSetupFlags,
	targetTool?: string,
	deps: ReverseSetupDeps = {},
): Promise<number> {
	const loadedSettings = deps.settings ?? (await loadEffectiveSettings());
	const effectiveDeps: ReverseSetupDeps = { ...deps, settings: loadedSettings };
	const write = deps.writeStdout ?? (text => process.stdout.write(text));
	const writeErr = deps.writeStderr ?? (text => process.stderr.write(text));
	const promptLine = deps.promptLine ?? runDefaultPrompt;
	const confirm = deps.confirm ?? runDefaultConfirm;
	let report = checkReverseTools(effectiveDeps);

	if (flags.json) {
		write(`${JSON.stringify(report, null, 2)}\n`);
		if (flags.check && !report.ok) {
			return 1;
		}
		return 0;
	}

	if (flags.check) {
		write(`${chalk.bold(t("cli.setup.reverse.checkSummary", "Reverse engineering toolchain catalog overview:"))}\n`);
		for (const tool of report.tools) {
			const isOk = tool.status === "installed";
			const mark = isOk ? chalk.green("[ok]") : tool.optional ? chalk.yellow("[missing]") : chalk.red("[missing]");
			const typeBadge = tool.optional ? chalk.dim("(optional)") : chalk.bold("(required)");
			const secondaryNote =
				tool.secondaryMissing && tool.secondaryMissing.length > 0
					? ` (missing prerequisite: ${tool.secondaryMissing.join(", ")})`
					: "";
			const details = isOk
				? `${tool.foundPath}${secondaryNote}`
				: tool.installCommand
					? `not found - command: ${tool.installCommand}`
					: `not found - manual: ${tool.manualUrl || tool.manualInstructions}`;
			write(`  ${mark} ${chalk.bold(tool.id)}: ${details} ${typeBadge}\n`);
		}
		for (const service of report.services) {
			const isConfiguredOnly = service.ready && service.configured;
			const mark = isConfiguredOnly
				? chalk.cyan("[configured]")
				: service.ready
					? chalk.yellow("[prereq]")
					: chalk.yellow("[missing]");
			const config = service.configured
				? `configured in ${service.configuredScopes.join(", ")}${service.enabled === false ? " (disabled)" : ""}`
				: "not configured";
			const managedNote =
				service.installer === "jshookmcp" || service.installer === "native-mcp"
					? service.installed
						? `; ${t("cli.setup.reverse.managedStatusInstalled", "managed package installed")}`
						: `; ${t("cli.setup.reverse.managedStatusMissing", "managed package not installed")}`
					: "";
			const details =
				service.ready &&
				((service.installer !== "native-mcp" && service.installer !== "jshookmcp") || service.installed === true)
					? `prerequisites ok (${service.prerequisites.map(p => p.id).join(", ") || "none"})${managedNote}; ${config}; connection unverified; start: ${service.startCommand}${service.installCommand ? `; install: ${service.installCommand}` : ""}`
					: service.installer === "jshookmcp" || service.installer === "native-mcp"
						? `prerequisites ${service.prerequisitesReady ? "ok" : "missing (" + service.missingPrerequisites.join(", ") + ")"}${managedNote}; ${config} - run: ${APP_NAME} setup reverse ${service.id} --execute`
						: service.installCommand
							? `prerequisites missing (${service.missingPrerequisites.join(", ")}); ${config} - install: ${service.installCommand}`
							: `prerequisites missing (${service.missingPrerequisites.join(", ")}); ${config} - manual: ${service.manualUrl}`;
			write(`  ${mark} ${chalk.bold(service.id)} (mcp): ${details} ${chalk.dim("(optional)")}\n`);
		}
		if (report.capabilities && report.capabilities.length > 0) {
			write(`\n${chalk.bold("Reverse engineering capabilities overview:")}\n`);
			for (const cap of report.capabilities) {
				const mark =
					cap.status === "ready"
						? chalk.green("[ready]")
						: cap.status === "available_with_fallbacks"
							? chalk.cyan("[fallbacks]")
							: chalk.yellow("[missing]");
				const toolSummary = cap.optionalExternalTools
					.map(t => `${t.id}${t.status === "installed" || t.status === "ready" ? " (ok)" : ""}`)
					.join(", ");
				const fallbackInfo =
					cap.availableFallbacks.length > 0 ? `; fallbacks: ${cap.availableFallbacks.join(", ")}` : "";
				const actionInfo = cap.status !== "ready" && cap.setupCommand ? `; setup: ${cap.setupCommand}` : "";
				write(
					`  ${mark} ${chalk.bold(cap.id)}: ${cap.name} - tools: [${toolSummary}]${fallbackInfo}${actionInfo}\n`,
				);
			}
		}

		if (!report.ok) {
			const missingNames = report.missingRequired.join(", ");
			const errIcon = theme?.status?.error ?? "✗";
			writeErr(
				`\n${chalk.red(errIcon)} ${t("cli.setup.reverse.missingRequiredNotice", `Missing required system tools: ${missingNames}`, { tools: missingNames })}\n`,
			);
			return 1;
		}

		const successIcon = theme?.status?.success ?? "✓";
		const optionalInstalledCount = report.tools.filter(t => t.optional && t.status === "installed").length;
		const optionalMissingCount = report.missingOptional.length;
		write(
			`\n${chalk.green(successIcon)} ${t("cli.setup.reverse.allReady", `Core system tools are present (strings, file). ${optionalInstalledCount} installed, ${optionalMissingCount} optional tools available in catalog.`, { installed: String(optionalInstalledCount), missing: String(optionalMissingCount) })}\n`,
		);
		return 0;
	}

	// Interactive terminal panel
	const isTTY = deps.isTTY ?? Boolean(process.stdin.isTTY && process.stdout.isTTY);

	if (!isTTY) {
		const ttyError = t(
			"cli.setup.reverse.executeRequiresTTY",
			`${APP_NAME} setup reverse requires an interactive TTY. Use --check or --json for non-interactive inspections.`,
			{ app: APP_NAME },
		);
		writeErr(`${chalk.red(theme?.status?.error ?? "✗")} ${ttyError}\n`);
		return 1;
	}

	write(`\n${chalk.bold.cyan("================================================================================")}\n`);
	write(`  ${chalk.bold(t("cli.setup.reverse.title", `${APP_NAME} Reverse Engineering Toolchain Setup Panel`))}\n`);
	write(
		`  ${chalk.dim(t("cli.setup.reverse.description", "Inspect tool status, select and install tools & MCP services with interactive confirmation"))}\n`,
	);
	write(`${chalk.bold.cyan("================================================================================")}\n`);

	const installedCount = report.tools.filter(t => t.status === "installed").length;
	const missingCount = report.tools.filter(t => t.status === "missing").length;
	const pmList =
		report.detectedPackageManagers.length > 0
			? report.detectedPackageManagers.join(", ")
			: t("cli.setup.reverse.noPackageManagers", "none (manual only)");
	write(
		`${chalk.dim(`Catalog overview: ${report.tools.length} CLI tools (${installedCount} installed, ${missingCount} missing), ${report.services.length} MCP services | Platform: ${report.platform}`)}\n`,
	);
	write(`${chalk.dim(t("cli.setup.reverse.packageManagers", `Package Managers: ${pmList}`, { managers: pmList }))}\n`);

	renderToolTable(report, write);
	renderServiceTable(report, write);
	renderCapabilityTable(report, write);

	const selectedTools: ReverseToolStatus[] = [];
	const selectedServices: ReverseServiceStatus[] = [];

	const addTool = (tool: ReverseToolStatus) => {
		if (!selectedTools.some(t => t.id === tool.id)) {
			selectedTools.push(tool);
		}
	};

	const addService = (service: ReverseServiceStatus) => {
		if (!selectedServices.some(s => s.id === service.id)) {
			selectedServices.push(service);
		}
	};

	const findTarget = (
		targetStr: string,
	): {
		tool?: ReverseToolStatus;
		service?: ReverseServiceStatus;
		cap?: ReverseCapabilityStatus;
	} => {
		const target = targetStr.trim().toLowerCase();
		// 1. Exact ID match (highest priority, avoids "ida" matching "frida")
		const exactTool = report.tools.find(t => t.id.toLowerCase() === target);
		if (exactTool) return { tool: exactTool };

		const exactService = report.services.find(
			s => s.id.toLowerCase() === target || s.serverName.toLowerCase() === target,
		);
		if (exactService) return { service: exactService };

		const exactCap = report.capabilities?.find(c => c.id.toLowerCase() === target);
		if (exactCap) return { cap: exactCap };

		// 2. Exact Name match
		const nameTool = report.tools.find(t => t.name.toLowerCase() === target);
		if (nameTool) return { tool: nameTool };

		const nameService = report.services.find(s => s.name.toLowerCase() === target);
		if (nameService) return { service: nameService };

		const nameCap = report.capabilities?.find(c => c.name.toLowerCase() === target);
		if (nameCap) return { cap: nameCap };

		// 3. Substring/fuzzy Name match
		const fuzzyTool = report.tools.find(t => t.name.toLowerCase().includes(target));
		if (fuzzyTool) return { tool: fuzzyTool };

		const fuzzyService = report.services.find(s => s.name.toLowerCase().includes(target));
		if (fuzzyService) return { service: fuzzyService };

		const fuzzyCap = report.capabilities?.find(c => c.name.toLowerCase().includes(target));
		if (fuzzyCap) return { cap: fuzzyCap };

		return {};
	};

	const resolveTargetToken = (token: string) => {
		const trimmed = token.trim();
		if (!trimmed) return;
		if (trimmed.toLowerCase() === "all-missing") {
			for (const t of report.tools) {
				if (t.status === "missing") addTool(t);
			}
			for (const s of report.services) {
				if (!s.ready || !s.configured) addService(s);
			}
			return;
		}
		const serviceNumber = /^s(\d+)$/i.exec(trimmed);
		const num = serviceNumber ? Number.NaN : Number.parseInt(trimmed, 10);
		if (!Number.isNaN(num) && num >= 1 && num <= report.tools.length) {
			addTool(report.tools[num - 1]);
			return;
		}
		if (serviceNumber) {
			const index = Number.parseInt(serviceNumber[1], 10);
			if (index >= 1 && index <= report.services.length) {
				addService(report.services[index - 1]);
			} else {
				write(chalk.yellow(`Warning: Unrecognized MCP service selection "${trimmed}". Skipped.\n`));
			}
			return;
		}

		const { tool, service, cap } = findTarget(trimmed);
		if (tool) {
			addTool(tool);
		} else if (service) {
			addService(service);
		} else if (cap) {
			for (const extTool of cap.optionalExternalTools) {
				const toolObj = report.tools.find(t => t.id.toLowerCase() === extTool.id.toLowerCase());
				const servObj = report.services.find(s => s.id.toLowerCase() === extTool.id.toLowerCase());
				if (toolObj) addTool(toolObj);
				else if (servObj) addService(servObj);
			}
		} else {
			write(chalk.yellow(`Warning: Unrecognized tool/service selection "${trimmed}". Skipped.\n`));
		}
	};

	if (targetTool) {
		const rawTokens = targetTool
			.split(/[\s,]+/)
			.map(t => t.trim())
			.filter(Boolean);
		if (rawTokens.length > 1) {
			for (const token of rawTokens) {
				resolveTargetToken(token);
			}
		} else {
			const normalizedTarget = targetTool.trim().toLowerCase();
			if (normalizedTarget === "all-missing") {
				for (const t of report.tools) {
					if (t.status === "missing") addTool(t);
				}
				for (const s of report.services) {
					if (!s.ready || !s.configured) addService(s);
				}
			} else {
				const { tool: match, service: serviceMatch, cap: capMatch } = findTarget(normalizedTarget);
				if (match) {
					addTool(match);
				} else if (serviceMatch) {
					addService(serviceMatch);
				} else if (capMatch) {
					write(
						`\n${chalk.cyan("--------------------------------------------------------------------------------")}\n`,
					);
					write(`${chalk.bold(`Capability: ${capMatch.name} (${capMatch.id})`)}\n`);
					write(`${chalk.dim(`Category: ${capMatch.category}`)} | ${chalk.dim(`Status: ${capMatch.status}`)}\n`);
					write(`${chalk.dim(`Scenario: ${capMatch.scenario}`)}\n`);
					write(`\n${chalk.bold("Why:")} ${capMatch.why}\n`);
					if (capMatch.recommendedNativeTool) {
						write(`\n${chalk.bold("Recommended native tool:")} ${chalk.green(capMatch.recommendedNativeTool)}\n`);
					}
					if (capMatch.prerequisites && capMatch.prerequisites.length > 0) {
						write(`\n${chalk.bold("Prerequisites:")} ${capMatch.prerequisites.join(", ")}\n`);
					}
					if (capMatch.fallbacks.length > 0) {
						write(
							`\n${chalk.bold("Fallbacks:")} ${capMatch.fallbacks.join(", ")} ${
								capMatch.availableFallbacks.length > 0
									? chalk.dim(`(available: ${capMatch.availableFallbacks.join(", ")})`)
									: ""
							}\n`,
						);
					}
					write(`\n${chalk.bold("Setup command:")} ${chalk.green(capMatch.setupCommand)}\n`);
					write(`\n${chalk.bold("Post-install invocation:")} ${chalk.cyan(capMatch.postInstallInvocation)}\n`);
					write(
						`${chalk.cyan("--------------------------------------------------------------------------------")}\n`,
					);

					for (const extTool of capMatch.optionalExternalTools) {
						const toolObj = report.tools.find(t => t.id.toLowerCase() === extTool.id.toLowerCase());
						const servObj = report.services.find(s => s.id.toLowerCase() === extTool.id.toLowerCase());
						if (toolObj) addTool(toolObj);
						else if (servObj) addService(servObj);
					}
				} else {
					const errIcon = theme?.status?.error ?? "✗";
					writeErr(`${chalk.red(errIcon)} Unknown tool or MCP service: ${targetTool}\n`);
					return 1;
				}
			}
		}
	} else {
		const promptText = t(
			"cli.setup.reverse.promptSelect",
			"Enter tool/service number(s) or ID(s) to install (e.g. 1, 3, jadx, r2mcp, 'all-missing', or 'q' to quit): ",
		);
		const selection = await promptLine(promptText);

		if (!selection || selection.toLowerCase() === "q" || selection.toLowerCase() === "quit") {
			write(chalk.dim("Setup panel closed.\n"));
			return 0;
		}

		if (selection.toLowerCase() === "all-missing") {
			for (const t of report.tools) {
				if (t.status === "missing") addTool(t);
			}
			for (const s of report.services) {
				if (!s.ready || !s.configured) addService(s);
			}
		} else {
			const tokens = selection.split(/[\s,]+/);
			for (const token of tokens) {
				resolveTargetToken(token);
			}
		}
	}

	if (selectedTools.length === 0 && selectedServices.length === 0) {
		write(chalk.dim(t("cli.setup.reverse.noSelected", "No valid tools or services selected.\n")));
		return 0;
	}

	if (targetTool && selectedTools.length === 1 && selectedServices.length === 0) {
		const tool = selectedTools[0];
		write(`\n${chalk.cyan("--------------------------------------------------------------------------------")}\n`);
		write(
			`${chalk.bold(t("cli.setup.reverse.detailTool", `Tool: ${tool.name} (${tool.id})`, { name: tool.name, id: tool.id }))}\n`,
		);
		write(
			`${chalk.dim(t("cli.setup.reverse.detailCategory", `Category: ${tool.category}`, { category: tool.category }))} | ${chalk.dim(t("cli.setup.reverse.detailType", `Type: ${tool.optional ? "optional" : "required"}`, { type: tool.optional ? "optional" : "required" }))}\n`,
		);
		write(
			`${chalk.dim(`Status: ${tool.status === "installed" ? "Installed" : "Not installed"}`)}${tool.foundPath ? ` (${tool.foundPath})` : ""}\n`,
		);
		if (tool.description) {
			write(`  ${chalk.dim(tool.description)}\n`);
		}
		if (tool.usage?.whenToUse) {
			write(`\n${chalk.bold("When to use:")}\n  ${chalk.dim(tool.usage.whenToUse)}\n`);
		}
		if (tool.usage?.fallback) {
			write(`\n${chalk.bold("Fallback:")}\n  ${chalk.dim(tool.usage.fallback)}\n`);
		}
		if (tool.usage?.canonical) {
			write(`\n${chalk.bold("Canonical invocation:")}\n  ${chalk.cyan(tool.usage.canonical)}\n`);
		}
		if (tool.secondaryMissing && tool.secondaryMissing.length > 0) {
			write(
				`${chalk.yellow(`Prerequisite missing: ${tool.secondaryMissing.join(", ")} (requires Java runtime)`)}\n`,
			);
		}
		if (tool.installCommand) {
			write(`\n${chalk.bold("Recommended installation command:")}\n`);
			write(`  ${chalk.green(tool.installCommand)}\n`);
			if (tool.riskNote) {
				write(`  ${chalk.dim(`Notes: ${tool.riskNote}`)}\n`);
			}
		}
		write(`\n${chalk.bold("Manual setup:")}\n`);
		if (tool.manualUrl) {
			write(`  ${t("cli.setup.reverse.manualUrl", `Official URL: ${tool.manualUrl}`, { url: tool.manualUrl })}\n`);
		}
		write(
			`  ${t("cli.setup.reverse.manualGuide", `Guide: ${tool.manualInstructions}`, { guide: tool.manualInstructions })}\n`,
		);
	} else if (targetTool && selectedServices.length === 1 && selectedTools.length === 0) {
		const service = selectedServices[0];
		write(`\n${chalk.cyan("--------------------------------------------------------------------------------")}\n`);
		write(`${chalk.bold(`MCP service: ${service.name} (${service.id})`)}\n`);
		write(
			`${chalk.dim(`Category: ${service.category}`)} | ${chalk.dim(`Transport: ${service.transport}`)} | ${chalk.dim(`License: ${service.license}`)}\n`,
		);
		const serviceDesc =
			service.installer === "jshookmcp"
				? t("cli.setup.reverse.jshookmcp.desc", service.description)
				: service.description;
		write(`${chalk.dim(serviceDesc)}\n`);
		if (service.startCommand) {
			write(`\n${chalk.bold("Start command:")}\n  ${chalk.cyan(service.startCommand)}\n`);
		}
		if (service.configSnippet) {
			write(`\n${chalk.bold("Config snippet:")}\n`);
			write(`  ${chalk.dim(JSON.stringify(service.configSnippet, null, 2).split("\n").join("\n  "))}\n`);
		}
		if (service.usage?.whenToUse) {
			write(`\n${chalk.bold("When to use:")}\n  ${chalk.dim(service.usage.whenToUse)}\n`);
		}
		write(`\n${chalk.bold("Manual setup:")}\n`);
		if (service.manualUrl) {
			write(`  Official URL: ${service.manualUrl}\n`);
		}
		write(`  Guide: ${service.manualInstructions}\n`);
	}

	const allSelectedItems: Array<ReverseToolStatus | ReverseServiceStatus> = [...selectedTools, ...selectedServices];

	if (allSelectedItems.length === 0) {
		write(chalk.dim(t("cli.setup.reverse.noSelected", "No valid tools or services selected.\n")));
		return 0;
	}

	// Dynamic import to avoid circular dependency / initialization cycle between setup-reverse and reverse-tool-install
	const { getReverseInstallPlan, installReverseItem } = await import("../extensibility/reverse-tool-install");

	const planOptions = {
		which: deps.which,
		platform: deps.platform,
		env: deps.env,
		agentDir: deps.agentDir,
		cwd: deps.cwd,
	};

	const plannedItems = allSelectedItems.map(item => ({
		item,
		plan: getReverseInstallPlan(item, planOptions),
	}));

	const installable = plannedItems.filter(p => p.plan.canInstall);
	const unsupported = plannedItems.filter(p => !p.plan.canInstall);

	if (unsupported.length > 0) {
		write(`\n${chalk.yellow("--------------------------------------------------------------------------------")}\n`);
		write(
			`${chalk.bold(t("cli.setup.reverse.planManualTitle", "Manual Setup / Unsupported Tools (no automated recipe):"))}\n`,
		);
		write(
			`${chalk.dim(t("cli.setup.reverse.planManualNotice", "The following tools require manual setup or license prerequisites and cannot be automated:"))}\n\n`,
		);
		for (const { item, plan } of unsupported) {
			const reason = plan.reason ?? item.manualInstructions;
			write(`  - ${chalk.bold(item.name)} (${item.id}): ${chalk.yellow(reason)}\n`);
			if (item.manualUrl) {
				write(
					`    ${t("cli.setup.reverse.manualUrl", `Official URL: ${item.manualUrl}`, { url: item.manualUrl })}\n`,
				);
			}
		}
		write(`${chalk.yellow("--------------------------------------------------------------------------------")}\n`);
	}

	if (installable.length === 0) {
		write(
			`\n${chalk.dim(t("cli.setup.reverse.noInstallableSelected", "No automatically installable items selected."))}\n`,
		);
		return 0;
	}

	write(`\n${chalk.cyan("================================================================================")}\n`);
	write(`  ${chalk.bold(t("cli.setup.reverse.planTitle", "Installation Plan (Batch)"))}\n`);
	write(`${chalk.cyan("================================================================================")}\n`);

	write(`\n${chalk.bold(t("cli.setup.reverse.planTargets", "Target items:"))}\n`);
	for (const { item } of installable) {
		const kindLabel = item.kind === "mcp" ? "MCP service" : "CLI tool";
		const isExisting = item.kind === "cli" ? item.status === "installed" : item.ready && item.configured;
		const actionNote = isExisting ? chalk.yellow(" [configure environment / reinstall]") : "";
		write(`  - ${chalk.bold(item.name)} (${item.id}) [${kindLabel}]${actionNote}\n`);
	}

	write(`\n${chalk.bold(t("cli.setup.reverse.planSteps", "Execution steps:"))}\n`);
	let stepIndex = 1;
	const seenStepIds = new Set<string>();
	const risks: Array<{ name: string; note: string }> = [];

	for (const { item, plan } of installable) {
		for (const step of plan.steps) {
			if (seenStepIds.has(step.id)) continue;
			seenStepIds.add(step.id);

			const prefix = step.isDependency ? chalk.yellow("[dependency] ") : "";
			const cmdDesc = step.command
				? `${chalk.blue(`[${step.packageManager ?? "pkg"}]`)} ${step.command}`
				: chalk.dim("service configuration & setup");
			write(`  ${stepIndex++}. ${prefix}${chalk.bold(step.name)} (${step.id}): ${cmdDesc}\n`);

			if (step.riskNote) {
				risks.push({ name: step.name, note: step.riskNote });
			}
		}
		if (item.riskNote && !risks.some(r => r.name === item.name)) {
			risks.push({ name: item.name, note: item.riskNote });
		}
	}

	if (risks.length > 0) {
		write(`\n${chalk.bold(t("cli.setup.reverse.planRisks", "Risks & Notes:"))}\n`);
		for (const risk of risks) {
			write(`  - ${chalk.yellow(risk.name)}: ${chalk.dim(risk.note)}\n`);
		}
	}
	write(`\n${chalk.cyan("--------------------------------------------------------------------------------")}\n`);

	const proceedPrompt = t(
		"cli.setup.reverse.batchConfirmPrompt",
		"Do you want to proceed with this installation plan now? [y/N]: ",
	);
	const proceed = await confirm(proceedPrompt);
	if (!proceed) {
		write(chalk.dim(t("cli.setup.reverse.batchCancelled", "Installation cancelled.")) + "\n");
		return 0;
	}

	let hasFailures = false;
	const executedStepIds = new Set<string>();

	for (const { item, plan } of installable) {
		if (executedStepIds.has(item.id)) {
			// Already installed and verified as a prerequisite dependency of an earlier item in this batch
			const successIcon = theme?.status?.success ?? "✓";
			write(
				chalk.green(
					`\n${successIcon} ${t("cli.setup.reverse.verifiedFound", `Verified: ${item.name} is ready for use!`, { name: item.name, path: "ready" })}\n`,
				),
			);
			continue;
		}

		write(
			chalk.cyan(
				`\n${t("cli.setup.reverse.executingTarget", `Installing and configuring ${item.name} (${item.id})...`, { name: item.name, id: item.id })}\n`,
			),
		);
		try {
			const result = await installReverseItem(item, {
				plan,
				cwd: deps.cwd ?? getProjectDir(),
				agentDir: deps.agentDir,
				which: deps.which,
				platform: deps.platform,
				env: deps.env,
				executor: deps.executor,
				onChunk: chunk => write(chalk.dim(chunk)),
			});

			if (result.success) {
				for (const step of plan.steps) {
					executedStepIds.add(step.id);
				}
				executedStepIds.add(item.id);

				const successIcon = theme?.status?.success ?? "✓";
				write(
					chalk.green(
						`${successIcon} ${t("cli.setup.reverse.verifiedFound", `Verified: ${item.name} is ready for use!`, { name: item.name, path: result.message ?? "ready" })}\n`,
					),
				);
				if (result.message) {
					write(chalk.dim(`  ${result.message}\n`));
				}
				if (item.usage?.canonical) {
					write(chalk.dim(`  Next invocation: ${item.usage.canonical}\n`));
				}
			} else {
				hasFailures = true;
				const errIcon = theme?.status?.error ?? "✗";
				const failureMsg = result.message || "Verification failed.";
				writeErr(
					chalk.red(
						`${errIcon} ${t("cli.setup.reverse.execFailedTarget", `Failed to install/configure ${item.name}: ${failureMsg}`, { name: item.name, error: failureMsg })}\n`,
					),
				);
				if (item.manualUrl) {
					write(
						`  ${t("cli.setup.reverse.manualUrl", `Official URL: ${item.manualUrl}`, { url: item.manualUrl })}\n`,
					);
				}
			}
		} catch (err: unknown) {
			hasFailures = true;
			const errIcon = theme?.status?.error ?? "✗";
			const msg = err instanceof Error ? err.message : String(err);
			writeErr(
				chalk.red(
					`${errIcon} ${t("cli.setup.reverse.execFailedTarget", `Failed to install/configure ${item.name}: ${msg}`, { name: item.name, error: msg })}\n`,
				),
			);
			if (item.manualUrl) {
				write(
					`  ${t("cli.setup.reverse.manualUrl", `Official URL: ${item.manualUrl}`, { url: item.manualUrl })}\n`,
				);
			}
		}
	}

	write(`\n${chalk.bold("Refreshed reverse toolchain status:")}\n`);
	report = checkReverseTools(effectiveDeps);
	renderToolTable(report, write);
	renderServiceTable(report, write);
	renderCapabilityTable(report, write);
	return hasFailures ? 1 : 0;
}

import * as path from "node:path";
import type {
	FailureAttribution,
	RecoveryPlan,
	ReverseWorkflowRecord,
	WorkflowStepRecord,
	StepResumeMetadata,
	CapabilityDepth,
	DiscoveryGuidance,
} from "./contracts";
import { DEFAULT_MAX_ATTEMPTS, HARD_MAX_ATTEMPTS } from "./contracts";
import { CAPABILITY_CATALOG, SKILL_TOOL_CATALOG, type SkillToolPlatform } from "../extensibility/skill-tool-catalog";
import { checkToolRequirements, type SkillRequirementWhich } from "../extensibility/skill-requirements";
import { getMcpService } from "../extensibility/mcp-service-catalog";
import { getMCPConfigPath, getProjectDir } from "@reverse/utils";
import { readMcpConfigFileSync } from "../cli/setup-reverse";
import type { MCPConfigFile } from "../mcp/types";
import { isProtectionToolId, resolveProtectionTool } from "../extensibility/protection-toolchain";
export interface ToolInstallHint {
	macos: string;
	linux: string;
	windows: string;
	fallback: string;
}

export const TOOL_INSTALL_HINTS: Record<string, ToolInstallHint> = {
	radare2: {
		macos: "brew install radare2",
		linux: "apt install radare2",
		windows: "choco install radare2",
		fallback: "r2_inspect -> ghidra_inspect or triage",
	},
	r2: {
		macos: "brew install radare2",
		linux: "apt install radare2",
		windows: "choco install radare2",
		fallback: "r2_inspect -> ghidra_inspect or triage",
	},
	ghidra: {
		macos: "brew install --cask ghidra",
		linux: "apt install ghidra",
		windows: "choco install ghidra",
		fallback: "ghidra_inspect -> r2_inspect or triage",
	},
	droidasc: {
		macos: "pip install droidasc",
		linux: "pip install droidasc",
		windows: "pip install droidasc",
		fallback: "droidasc -> android_package_inspect",
	},
	jadx: {
		macos: "brew install jadx",
		linux: "apt install jadx",
		windows: "choco install jadx",
		fallback: "jadx -> android_package_inspect",
	},
	apktool: {
		macos: "brew install apktool",
		linux: "apt install apktool",
		windows: "choco install apktool",
		fallback: "apktool -> android_package_inspect",
	},
	adb: {
		macos: "brew install --cask android-platform-tools",
		linux: "apt install android-tools-adb",
		windows: "choco install adb",
		fallback: "adb_observe -> static inspection",
	},
	frida: {
		macos: "pipx install frida-tools",
		linux: "pipx install frida-tools",
		windows: "py -m pip install --user frida-tools",
		fallback: "frida -> static inspection",
	},
	unidbg: {
		macos: "brew install openjdk maven && git clone https://github.com/zhkl0228/unidbg.git && cd unidbg && mvn package -DskipTests",
		linux: "sudo apt install -y default-jdk maven && git clone https://github.com/zhkl0228/unidbg.git && cd unidbg && mvn package -DskipTests",
		windows:
			"winget install EclipseAdoptium.Temurin.8.JDK && git clone https://github.com/zhkl0228/unidbg.git (JDK 8 required)",
		fallback: "unidbg -> android_native_workflow",
	},
	wabt: {
		macos: "brew install wabt",
		linux: "apt install wabt",
		windows: "scoop install wabt or reverse setup reverse wabt",
		fallback: "wasm2wat -> wasm_inspect",
	},
	tshark: {
		macos: "brew install wireshark",
		linux: "apt install tshark",
		windows: "choco install wireshark",
		fallback: "tshark -> pcap_inspect",
	},
	vbindiff: {
		macos: "brew install vbindiff",
		linux: "apt install vbindiff",
		windows: "reverse setup reverse vbindiff",
		fallback: "vbindiff -> binary_diff",
	},
	"ast-grep": {
		macos: "brew install ast-grep",
		linux: "apt install ast-grep",
		windows: "cargo install ast-grep",
		fallback: "ast-grep -> ast_grep or grep",
	},
	"frida-dexdump": {
		macos: "pipx install frida-dexdump",
		linux: "pipx install frida-dexdump",
		windows: "pip install frida-dexdump",
		fallback: "dex_unpack -> android_package_inspect",
	},
	dex_unpack: {
		macos: "pipx install frida-dexdump",
		linux: "pipx install frida-dexdump",
		windows: "pip install frida-dexdump",
		fallback: "dex_unpack -> android_package_inspect",
	},
	dexkit: {
		macos: "reverse setup reverse dexkit --execute",
		linux: "reverse setup reverse dexkit --execute",
		windows: "reverse setup reverse dexkit --execute",
		fallback: "dex_search -> droidasc or android_package_inspect",
	},
	dex_search: {
		macos: "reverse setup reverse dexkit --execute",
		linux: "reverse setup reverse dexkit --execute",
		windows: "reverse setup reverse dexkit --execute",
		fallback: "dex_search -> droidasc or android_package_inspect",
	},
	"jadx-string-decrypt": {
		macos: "reverse setup reverse jadx-string-decrypt --execute",
		linux: "reverse setup reverse jadx-string-decrypt --execute",
		windows: "reverse setup reverse jadx-string-decrypt --execute",
		fallback: "deobfuscate -> android_package_inspect",
	},
	"d810-ng": {
		macos: "reverse setup reverse d810-ng --execute",
		linux: "reverse setup reverse d810-ng --execute",
		windows: "reverse setup reverse d810-ng --execute",
		fallback: "deobfuscate -> r2_inspect or ghidra_inspect",
	},
	simplify: {
		macos: "reverse setup reverse simplify --execute",
		linux: "reverse setup reverse simplify --execute",
		windows: "reverse setup reverse simplify --execute",
		fallback: "deobfuscate -> dex_patch or android_package_inspect",
	},
	msynth: {
		macos: "reverse setup reverse msynth --execute",
		linux: "reverse setup reverse msynth --execute",
		windows: "reverse setup reverse msynth --execute",
		fallback: "deobfuscate -> triton_analyze or r2_inspect",
	},
	blackdex: {
		macos: "reverse setup reverse blackdex --execute",
		linux: "reverse setup reverse blackdex --execute",
		windows: "reverse setup reverse blackdex --execute",
		fallback: "dex_unpack -> android_package_inspect",
	},
	qbdi: {
		macos: "reverse setup reverse qbdi --execute",
		linux: "reverse setup reverse qbdi --execute",
		windows: "reverse setup reverse qbdi --execute",
		fallback: "instruction_trace -> frida or triage",
	},
	instruction_trace: {
		macos: "reverse setup reverse qbdi --execute",
		linux: "reverse setup reverse qbdi --execute",
		windows: "reverse setup reverse qbdi --execute",
		fallback: "instruction_trace -> frida or triage",
	},
	triton: {
		macos: "reverse setup reverse triton --execute",
		linux: "reverse setup reverse triton --execute",
		windows: "reverse setup reverse triton --execute",
		fallback: "triton_analyze -> r2_inspect or triage",
	},
	tritondse: {
		macos: "reverse setup reverse tritondse --execute",
		linux: "reverse setup reverse tritondse --execute",
		windows: "reverse setup reverse tritondse --execute",
		fallback: "native_recover -> triton_analyze",
	},
	native_recover: {
		macos: "reverse setup reverse tritondse --execute",
		linux: "reverse setup reverse tritondse --execute",
		windows: "reverse setup reverse tritondse --execute",
		fallback: "native_recover -> triton_analyze",
	},
	deobfuscate: {
		macos: "reverse setup reverse d810-ng --execute",
		linux: "reverse setup reverse d810-ng --execute",
		windows: "reverse setup reverse d810-ng --execute",
		fallback: "deobfuscate -> r2_inspect or android_package_inspect",
	},
	dex_repair: {
		macos: "python3 (embedded in reverse via dexutil.py)",
		linux: "python3 (embedded in reverse via dexutil.py)",
		windows: "python (embedded in reverse via dexutil.py)",
		fallback: "dex_repair -> dex_patch",
	},
};

/**
 * Find canonical setup command for a missing tool from the capability catalog.
 * Maps tools to their canonical capability setupCommand (e.g. 'reverse setup reverse apktool')
 * or canonical skill tool setup command.
 */
export function getCapabilitySetupCommand(toolName: string): string | undefined {
	const normalized = toolName.toLowerCase().trim();

	// 1. Direct capability match
	const directCap = CAPABILITY_CATALOG[normalized];
	if (directCap?.setupCommand) {
		return directCap.setupCommand;
	}

	// 已定位具体缺失后端时，安装该后端，避免误走同一能力的其他可选实现。
	const skillTool = SKILL_TOOL_CATALOG[normalized];
	if (skillTool) {
		return `reverse setup reverse ${skillTool.id} --execute`;
	}

	// 2. Search capabilities by optional external tools, recommended native tool, or fallbacks
	for (const cap of Object.values(CAPABILITY_CATALOG)) {
		if (
			cap.optionalExternalTools.some(t => t.toLowerCase() === normalized) ||
			cap.recommendedNativeTool?.toLowerCase() === normalized ||
			cap.fallbacks.some(f => f.toLowerCase() === normalized)
		) {
			if (cap.setupCommand) {
				return cap.setupCommand;
			}
		}
	}

	return undefined;
}

export function getPlatformInstallCommand(
	toolName: string,
	platform: NodeJS.Platform = process.platform,
): string | undefined {
	const normalized = toolName.toLowerCase().trim();
	const hint = TOOL_INSTALL_HINTS[normalized];
	if (hint) {
		if (platform === "darwin") return hint.macos;
		if (platform === "win32") return hint.windows;
		return hint.linux;
	}

	const toolDesc = SKILL_TOOL_CATALOG[normalized];
	if (toolDesc?.installCommands) {
		const platKey: SkillToolPlatform = platform === "darwin" ? "darwin" : platform === "win32" ? "win32" : "linux";
		const cmd = toolDesc.installCommands[platKey]?.[0]?.command;
		if (cmd) return cmd;
	}

	return getCapabilitySetupCommand(toolName);
}

export interface FailureClassificationContext {
	tool?: string;
	stepId?: string;
	gate?: string;
	targetPath?: string;
	targetFormat?: string;
	paramsSummary?: Record<string, unknown> | string;
}

/**
 * Classify a step failure into deterministic categories:
 * - missing_dependency
 * - invalid_format
 * - timeout
 * - truncated
 * - device_required
 * - unsupported
 * - unknown
 */
export function classifyFailure(errorMessage: string, context: FailureClassificationContext = {}): FailureAttribution {
	const rawError = errorMessage.trim();

	// 1. Missing Dependency Check
	// Specific tools first
	const toolPatterns: Array<{ name: string; pattern: RegExp }> = [
		{
			name: "radare2",
			pattern:
				/\b(?:r2|radare2)\b.*(?:not found|cannot find|no such file|command not found|enoent)|(?:cannot find|no such command).*\b(?:r2|radare2)\b|r2: command not found/i,
		},
		{
			name: "ghidra",
			pattern:
				/\bghidra\b.*(?:not found|cannot find|no such file|command not found)|ghidra_install_dir|analyzeheadless/i,
		},
		{
			name: "droidasc",
			pattern: /\bdroidasc\b.*(?:not found|cannot find|no such file|command not found|cannot find module)/i,
		},
		{
			name: "jadx",
			pattern: /\bjadx\b.*(?:not found|cannot find|no such file|command not found|please install jadx)/i,
		},
		{ name: "apktool", pattern: /\bapktool\b.*(?:not found|cannot find|no such file|command not found)/i },
		{
			name: "adb",
			pattern:
				/\badb\b.*(?:not found|cannot find|no such file|command not found)|failed to execute adb.*(?:enoent|not found)/i,
		},
		{
			name: "frida",
			pattern: /\bfrida\b(?![-_]dexdump).*(?:not found|cannot find|no such file|command not found|frida-tools)/i,
		},
		{ name: "wabt", pattern: /\b(?:wabt|wasm2wat|wat2wasm)\b.*(?:not found|cannot find|command not found)/i },
		{ name: "tshark", pattern: /\btshark\b.*(?:not found|cannot find|command not found)/i },
		{ name: "vbindiff", pattern: /\bvbindiff\b.*(?:not found|cannot find|command not found)/i },
		{ name: "ast-grep", pattern: /\bast-grep\b.*(?:not found|cannot find|command not found)/i },
		{ name: "unidbg", pattern: /\bunidbg\b.*(?:not found|cannot find|no such file|command not found)/i },
		{
			name: "frida-dexdump",
			pattern:
				/\b(?:frida-dexdump|dex_unpack)\b.*(?:not found|cannot find|no such file|command not found)|(?:not found|cannot find|no such file|command not found).*\b(?:frida-dexdump|dex_unpack)\b/i,
		},
		{
			name: "dexkit",
			pattern: /\b(?:dexkit|dex_search)\b.*(?:not found|cannot find|no such file|command not found)/i,
		},
		{ name: "d810-ng", pattern: /\b(?:d810-ng|d810)\b.*(?:not found|cannot find|no such file|command not found)/i },
		{
			name: "simplify",
			pattern:
				/\bsimplify\b.*(?:not found|cannot find|no such file|command not found)|(?:not found|cannot find|no such file|command not found).*\bsimplify\b/i,
		},
		{ name: "msynth", pattern: /\bmsynth\b.*(?:not found|cannot find|no such file|command not found)/i },
		{ name: "blackdex", pattern: /\bblackdex\b.*(?:not found|cannot find|no such file|command not found)/i },
		{
			name: "qbdi",
			pattern: /\b(?:qbdi|instruction_trace)\b.*(?:not found|cannot find|no such file|command not found)/i,
		},
		{
			name: "triton",
			pattern: /\b(?:triton-library|triton_analyze)\b.*(?:not found|cannot find|no such file|command not found)/i,
		},
		{
			name: "tritondse",
			pattern: /\b(?:tritondse|native_recover)\b.*(?:not found|cannot find|no such file|command not found)/i,
		},
		{ name: "deobfuscate", pattern: /\bdeobfuscate\b.*(?:not found|cannot find|no such file|command not found)/i },
		{
			name: "dex_repair",
			pattern: /\b(?:dex_repair|fart)\b.*(?:not found|cannot find|no such file|command not found)/i,
		},
	];

	for (const tp of toolPatterns) {
		if (tp.pattern.test(rawError)) {
			const installCmd = getPlatformInstallCommand(tp.name);
			const setupCmd = getCapabilitySetupCommand(tp.name);
			return {
				category: "missing_dependency",
				cause: `Required tool or dependency '${tp.name}' is not installed or not found on PATH.`,
				confidence: "high",
				raw_error: rawError,
				matched_pattern: tp.name,
				missing_tool: tp.name,
				install_hint: installCmd ?? setupCmd,
				setup_command: setupCmd,
			};
		}
	}
	// Generic missing dependency
	if (
		/\b(?:command not found|not found on path|is not installed|not installed on the system|spawn .* enoent|executable not found|no such file or directory)\b/i.test(
			rawError,
		) ||
		/cannot find executable|binary not found|please install/i.test(rawError)
	) {
		const toolName = context.tool ?? "required tool";
		const installCmd = context.tool ? getPlatformInstallCommand(context.tool) : undefined;
		const setupCmd = context.tool ? getCapabilitySetupCommand(context.tool) : undefined;
		return {
			category: "missing_dependency",
			cause: `Required executable or external dependency for '${toolName}' was not found in the environment.`,
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "generic_missing_dependency",
			missing_tool: context.tool,
			install_hint: installCmd ?? setupCmd,
			setup_command: setupCmd,
		};
	}

	// 2. Device Required Check
	if (
		/\b(?:no (?:usable )?(?:android )?device|device (?:offline|not found|unauthorized)|no emulator|adb server not running|cannot connect to daemon|unable to connect to.*frida|device not connected|no target device|usb device not detected|device unauthorized)\b/i.test(
			rawError,
		)
	) {
		return {
			category: "device_required",
			cause: "Dynamic analysis tool requires an attached Android device or running emulator, but none was detected.",
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "device_required",
		};
	}

	// 3. Timeout Check
	if (
		/\b(?:timed? out|timeout|etimedout|deadline exceeded|killed after \d+m?s|execution time exceeded|took too long)\b/i.test(
			rawError,
		)
	) {
		return {
			category: "timeout",
			cause: "Tool execution timed out before completion, likely due to large binary size or exhaustive decompilation/analysis.",
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "timeout",
		};
	}

	// 4. Truncated Check
	if (
		/\b(?:truncated|output limit exceeded|buffer (?:overflow|full|limit)|response clipped|maximum .* limit of \d+ bytes|exceeds maximum .* limit|too large)\b/i.test(
			rawError,
		)
	) {
		return {
			category: "truncated",
			cause: "Tool output exceeded buffer or inline capacity. Paging, filtering, or artifact output is required.",
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "truncated",
		};
	}

	// 5. Invalid Format Check
	if (
		/\b(?:invalid (?:magic|header|format|signature|elf|pe|mach-o|apk|dex|zip|wasm|pcap|sqlite)|not a valid (?:elf|pe|mach-o|apk|dex|zip|wasm|pcap|sqlite)|corrupt(?:ed)?|bad magic|unrecognized file format|file format not recognized|unexpected file format|malformed|not an elf binary|not a pe file|not an apk|not a valid sqlite|failed to parse|file is encrypted|packed with unknown packer)\b/i.test(
			rawError,
		)
	) {
		return {
			category: "invalid_format",
			cause: "Target file format does not match expected structure or header is corrupted/packed/encrypted.",
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "invalid_format",
		};
	}

	// 6. Unsupported Check
	if (
		/\b(?:unsupported (?:architecture|arch|format|feature|version|encoding|platform)|not supported|not implemented|unknown architecture|symbol not found|stripped binary|no section table|no debugging symbols|entrypoint not found)\b/i.test(
			rawError,
		)
	) {
		return {
			category: "unsupported",
			cause: "Target contains an unsupported architecture, stripped symbol table, or unimplemented analysis feature.",
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "unsupported",
		};
	}

	// 7. Unknown
	return {
		category: "unknown",
		cause: rawError || "Unclassified failure encountered during step execution.",
		confidence: "low",
		raw_error: rawError,
	};
}

export interface RecoveryPlanOptions {
	error?: string;
	fallbackToolOverride?: string;
	nextParamsOverride?: Record<string, unknown> | string;
	maxAttempts?: number;
	capabilityId?: string;
	installedTool?: string;
	setupCommand?: string;
	verified?: boolean;
	strategy?: "resume_original" | "fallback" | string;
}
export interface VerifyToolOptions {
	cwd?: string;
	platform?: NodeJS.Platform;
	which?: SkillRequirementWhich;
	env?: Record<string, string | undefined>;
	readMcpConfig?: (path: string) => MCPConfigFile | null;
	connection?: "unknown" | "connected" | "disconnected";
}

export interface VerifyToolResult {
	verified: boolean;
	tool_id: string;
	kind: "cli" | "mcp" | "unknown";
	foundPath?: string | null;
	missing_reason?: string;
	setup_command?: string;
}

/**
 * Verify that an external tool is actually installed and available on the host system.
 * User-supplied verified: true is never accepted without fresh host verification.
 */
export function verifyInstalledTool(toolId: string, options: VerifyToolOptions = {}): VerifyToolResult {
	const normalizedId = (toolId ?? "").trim().toLowerCase();
	if (!normalizedId) {
		return {
			verified: false,
			tool_id: toolId,
			kind: "unknown",
			missing_reason: "Tool identifier is empty.",
		};
	}

	// 1. Check MCP service catalog
	const service = getMcpService(normalizedId);
	if (service) {
		const prereqStatuses = checkToolRequirements(
			service.requires.map(id => ({ id, optional: true })),
			{
				platform: options.platform,
				which: options.which,
				env: options.env,
			},
		);
		const missingPrereqs = prereqStatuses
			.filter(s => s.foundPath === null || (s.secondaryMissing?.length ?? 0) > 0)
			.map(s => s.id);
		const prereqsReady = missingPrereqs.length === 0;

		const cwd = options.cwd ?? getProjectDir();
		const configPaths = {
			project: getMCPConfigPath("project", cwd),
			user: getMCPConfigPath("user", cwd),
		};
		const readConfig = options.readMcpConfig ?? readMcpConfigFileSync;
		const configFiles = {
			project: readConfig(configPaths.project),
			user: readConfig(configPaths.user),
		};

		let configured = false;
		let enabled: boolean | null = null;
		for (const scope of ["project", "user"] as const) {
			const file = configFiles[scope];
			const entry = file?.mcpServers?.[service.serverName];
			if (!entry || typeof entry !== "object") continue;
			configured = true;
			const scopeEnabled =
				!file?.disabledServers?.includes(service.serverName) &&
				(entry.enabled !== false || (file?.enabledServers?.includes(service.serverName) ?? false));
			enabled = enabled === null ? scopeEnabled : enabled || scopeEnabled;
		}

		const isConnected = options.connection === "connected";
		const isReady = prereqsReady && configured && enabled !== false && isConnected;
		let missingReason: string | undefined;
		if (!prereqsReady) {
			missingReason = `MCP prerequisite tools missing on PATH: ${missingPrereqs.join(", ")}`;
		} else if (!configured) {
			missingReason = `MCP service '${service.serverName}' is not configured in ${configPaths.project} or ${configPaths.user}`;
		} else if (enabled === false) {
			missingReason = `MCP service '${service.serverName}' is disabled in configuration`;
		} else if (!isConnected) {
			missingReason = `MCP service '${service.serverName}' is configured but connection is unverified (status: connection_unknown). Active connection required.`;
		}

		return {
			verified: isReady,
			tool_id: normalizedId,
			kind: "mcp",
			missing_reason: missingReason,
			setup_command: `reverse setup reverse ${service.id}`,
		};
	}
	// 1b. Check protection toolchain resolver
	if (isProtectionToolId(normalizedId)) {
		const resolved = resolveProtectionTool(normalizedId);
		if (resolved) {
			const isVerified = resolved.installed && resolved.compatible && resolved.canStart;
			let missingReason: string | undefined;
			if (!resolved.installed) {
				missingReason = `Protection tool '${normalizedId}' is not installed in managed or system environment.`;
			} else if (!resolved.compatible) {
				missingReason = `Protection tool '${normalizedId}' is not compatible with host environment.`;
			} else if (!resolved.canStart) {
				missingReason = `Protection tool '${normalizedId}' prerequisites are incomplete.`;
			}
			return {
				verified: isVerified,
				tool_id: normalizedId,
				kind: "cli",
				foundPath: resolved.path || null,
				missing_reason: missingReason,
				setup_command: `reverse setup reverse ${normalizedId} --execute`,
			};
		}
	}

	// 2. Check CLI tool / binary
	const toolStatuses = checkToolRequirements([{ id: normalizedId, optional: true }], {
		platform: options.platform,
		which: options.which,
		env: options.env,
	});
	const status = toolStatuses[0];
	const isInstalled = Boolean(
		status && status.foundPath !== null && (!status.secondaryMissing || status.secondaryMissing.length === 0),
	);

	let setupCommand: string | undefined;
	const desc = SKILL_TOOL_CATALOG[normalizedId];
	if (desc) {
		const plat: SkillToolPlatform =
			(options.platform ?? process.platform) === "win32"
				? "win32"
				: (options.platform ?? process.platform) === "darwin"
					? "darwin"
					: "linux";
		setupCommand =
			desc.installCommands?.[plat]?.[0]?.command ??
			(desc.manualUrl ? `See ${desc.manualUrl}` : `reverse setup reverse ${normalizedId}`);
	}

	let missingReason: string | undefined;
	if (!isInstalled) {
		if (status?.secondaryMissing && status.secondaryMissing.length > 0) {
			missingReason = `Tool '${normalizedId}' found at ${status.foundPath} but secondary dependency missing: ${status.secondaryMissing.join(", ")}`;
		} else {
			missingReason = `Tool '${normalizedId}' executable binary was not found on PATH or catalog search paths.`;
		}
	}

	return {
		verified: isInstalled,
		tool_id: normalizedId,
		kind: desc ? "cli" : "unknown",
		foundPath: status?.foundPath ?? null,
		missing_reason: missingReason,
		setup_command: setupCommand ?? `reverse setup reverse ${normalizedId}`,
	};
}

/**
 * Determine whether a target path or format represents a standalone native binary / shared library
 * rather than an application package container (e.g. .so, .dylib, .dll, ELF).
 */
export function isBareNativeTarget(targetPath?: string, format?: string): boolean {
	if (!targetPath) return format === "ELF" || format === "PE" || format === "Mach-O";
	const lower = targetPath.toLowerCase();
	if (
		lower.endsWith(".so") ||
		lower.endsWith(".dylib") ||
		lower.endsWith(".dll") ||
		lower.endsWith(".elf") ||
		lower.endsWith(".bin")
	) {
		return true;
	}
	return format === "ELF" || format === "PE" || format === "Mach-O";
}

/**
 * Determine whether a target is an Android package container (.apk, .aab, .apks) or Dalvik executable (.dex).
 * If the target path explicitly ends with a native extension like .so, it is treated as native, not APK.
 */
export function isApkTarget(targetPath?: string, format?: string): boolean {
	if (targetPath) {
		const lower = targetPath.toLowerCase();
		if (lower.endsWith(".so") || lower.endsWith(".dylib") || lower.endsWith(".dll") || lower.endsWith(".elf")) {
			return false;
		}
		if (lower.endsWith(".apk") || lower.endsWith(".aab") || lower.endsWith(".apks") || lower.endsWith(".dex")) {
			return true;
		}
	}
	return format === "APK";
}

/**
 * Determine whether a step's action, title, or parameters indicate an intent to decode/inspect AndroidManifest.xml.
 */
export function isManifestIntent(
	parsedParams: Record<string, unknown>,
	step?: WorkflowStepRecord,
	originalTool?: string,
): boolean {
	const actionStr = String(parsedParams.action ?? "").toLowerCase();
	if (actionStr === "manifest" || actionStr === "decode_manifest") return true;
	const targetArtifact = String(parsedParams.target_artifact ?? "").toLowerCase();
	if (targetArtifact.includes("manifest")) return true;
	if (step) {
		const titleLower = (step.title || "").toLowerCase();
		if (titleLower.includes("manifest")) return true;
		const idLower = (step.id || "").toLowerCase();
		if (idLower.includes("manifest")) return true;
		if ("description" in step && typeof step.description === "string") {
			if (step.description.toLowerCase().includes("manifest")) return true;
		}
	}
	if (originalTool === "apktool" && (!parsedParams.action || actionStr === "decode")) {
		return true;
	}
	return false;
}

/**
 * Resolve effective target path from step parameters (handling artifact_path, target, path, etc.)
 * or default to the workflow's target path.
 */
export function resolveStepTargetPath(parsedParams: Record<string, unknown>, defaultTargetPath: string): string {
	const candidate =
		parsedParams.path ??
		parsedParams.artifact_path ??
		parsedParams.target ??
		parsedParams.target_path ??
		parsedParams.capture_path ??
		parsedParams.file ??
		parsedParams.filepath;
	if (typeof candidate === "string" && candidate.trim()) {
		return candidate.trim();
	}
	return defaultTargetPath;
}

export interface AndroidJniEvidenceContext {
	targetPath?: string;
	targetFormat?: string;
	tool?: string;
	intent?: string;
	params?: Record<string, unknown>;
	stepTitle?: string;
	workflowGoal?: string;
}

/**
 * Determine whether there is explicit JNI or Android native evidence for a target.
 * APK containers are packages (not bare .so), and a bare .so extension alone is generic ELF
 * and NOT proof of Android without explicit JNI context.
 */
export function isExplicitAndroidJniTarget(context: AndroidJniEvidenceContext): boolean {
	if (isApkTarget(context.targetPath, context.targetFormat)) {
		return false;
	}
	const tool = (context.tool || "").toLowerCase();
	if (tool === "unidbg" || tool === "android_native_workflow" || tool === "android_lab" || tool === "app_experiment") {
		return true;
	}
	const intent = (context.intent || "").toLowerCase();
	if (intent.includes("jni")) {
		return true;
	}
	const stepTitle = (context.stepTitle || "").toLowerCase();
	if (stepTitle.includes("jni")) {
		return true;
	}
	const workflowGoal = (context.workflowGoal || "").toLowerCase();
	if (workflowGoal.includes("jni")) {
		return true;
	}
	const params = context.params;
	if (params) {
		if (typeof params.class === "string" && params.class) return true;
		if (typeof params.method === "string" && params.method) return true;
		if (typeof params.abi === "string" && params.abi) return true;
		if (typeof params.library === "string" && params.library) return true;
		if (typeof params.so_name === "string" && params.so_name) return true;
		if (typeof params.action === "string" && params.action.toLowerCase().includes("jni")) return true;
	}
	return false;
}

export interface CapabilityRecoveryContext {
	targetPath?: string;
	targetFormat?: string;
	action?: string;
	intent?: string;
	params?: Record<string, unknown>;
}

export interface CapabilityRecoverySuggestion {
	nextTool: string;
	nextParams: Record<string, unknown>;
	prerequisites?: string[];
	capabilityDepth?: CapabilityDepth;
	verificationBoundary?: string;
	remainingAcceptance?: string;
	reasoning?: string;
	alternatives?: string[];
}

/**
 * Resolve canonical fallback recovery suggestion for a capability or external tool.
 * Provides model-actionable next tool, valid parameters, capability depth, and verification boundaries.
 */
export function resolveCapabilityRecovery(
	capIdOrTool: string,
	context: CapabilityRecoveryContext = {},
): CapabilityRecoverySuggestion | undefined {
	const normalized = (capIdOrTool || "").trim().toLowerCase();
	const targetPath = context.targetPath || "";
	const isNative = isBareNativeTarget(targetPath, context.targetFormat);
	const isAndroidJni = isExplicitAndroidJniTarget({
		targetPath,
		targetFormat: context.targetFormat,
		tool: normalized,
		intent: context.intent,
		params: context.params,
	});

	switch (normalized) {
		case "apk_unpacking":
		case "droidasc":
		case "jadx":
		case "apktool": {
			const isManifest =
				context.action === "manifest" ||
				context.intent === "manifest" ||
				(normalized === "apktool" && !context.action);
			if (isManifest) {
				return {
					nextTool: "android_package_inspect",
					nextParams: { path: targetPath, action: "manifest" },
					capabilityDepth: "static",
					prerequisites: ["target_apk_present"],
					verificationBoundary:
						"Zero-dependency static AXML manifest decoding directly from APK container without external decompiler.",
					remainingAcceptance: "Java/Kotlin high-level source decompilation remains unverified.",
					reasoning:
						"Primary decompiler is missing. Routed to built-in 'android_package_inspect' with action 'manifest'.",
					alternatives: ["android_package_inspect", "jadx", "apktool"],
				};
			}
			if (isAndroidJni) {
				return {
					nextTool: "android_native_workflow",
					nextParams: { path: targetPath, action: "inspect" },
					capabilityDepth: "static",
					prerequisites: ["target_binary_present"],
					verificationBoundary:
						"Target is a standalone Android native library (.so/ELF), not an APK container. Routed to native inspection.",
					remainingAcceptance:
						"APK container, manifest, and Dalvik inspection are not applicable to bare .so binaries.",
					reasoning:
						"Target has explicit JNI context. Routed to android_native_workflow for native library inspection instead of APK unpacking.",
					alternatives: ["android_native_workflow", "r2_inspect", "triage"],
				};
			}
			if (isNative) {
				return {
					nextTool: "triage",
					nextParams: { path: targetPath, strings: true, limit: 30 },
					capabilityDepth: "triage",
					prerequisites: ["target_binary_present"],
					verificationBoundary:
						"Target is a generic native binary, not an APK container or Dalvik bytecode. Routed to multi-format triage for raw header and string reconnaissance.",
					remainingAcceptance:
						"APK/Dalvik decompilation criteria are not applicable to generic native binaries without dedicated decompiler.",
					reasoning:
						"Target is a generic native binary, not an Android package or JNI library. Routed to 'triage' for multi-format inspection.",
					alternatives: ["triage", "binary_metadata_inspect"],
				};
			}
			if (context.action === "resources" || context.intent === "resources") {
				return {
					nextTool: "android_package_inspect",
					nextParams: { path: targetPath, action: "resources" },
					capabilityDepth: "static",
					prerequisites: ["target_apk_present"],
					verificationBoundary: "Static ARSC resource table inspection.",
					remainingAcceptance: "High-level resource compilation requires aapt2/apktool.",
					reasoning: "Routed to built-in 'android_package_inspect' for resources.",
					alternatives: ["android_package_inspect", "apktool"],
				};
			}
			if (context.action === "signing" || context.intent === "signing") {
				return {
					nextTool: "android_package_inspect",
					nextParams: { path: targetPath, action: "signing" },
					capabilityDepth: "static",
					prerequisites: ["target_apk_present"],
					verificationBoundary:
						"Zero-dependency signature presence and scheme (v1/v2/v3/v3.1) inspection; v4 scheme requires external .idsig file.",
					remainingAcceptance: "Full certificate chain verification requires apksigner bridge.",
					reasoning: "Routed to built-in 'android_package_inspect' for signing inspection.",
					alternatives: ["android_package_inspect", "apksigner"],
				};
			}
			return {
				nextTool: "android_package_inspect",
				nextParams: { path: targetPath, action: "dex" },
				capabilityDepth: "static",
				prerequisites: ["target_apk_present"],
				verificationBoundary: "Zero-dependency static DEX header and class listing.",
				remainingAcceptance: "High-level Java source reconstruction requires jadx/apktool.",
				reasoning:
					"Primary decompiler is missing. Degraded to built-in 'android_package_inspect' for DEX bytecode inspection.",
				alternatives: ["android_package_inspect", "jadx", "apktool"],
			};
		}

		case "android_native_emulation":
		case "unidbg": {
			return {
				nextTool: "android_native_workflow",
				nextParams: { path: targetPath, action: "inspect" },
				capabilityDepth: "static",
				prerequisites: ["target_binary_present"],
				verificationBoundary:
					"Observation-only static JNI export analysis. Extracts exported symbol names, mangled JNI signatures, and DEX native declarations, but cannot execute native code, evaluate runtime crypto/unpacking logic, or satisfy dynamic JNI experiment acceptance criteria.",
				remainingAcceptance:
					"Dynamic JNI execution, runtime register state, and functional emulation acceptance criteria remain unsatisfied (proxy observation only). A live device or verified emulation harness (e.g. unidbg with JDK 8) is required for dynamic acceptance.",
				reasoning:
					"Unidbg emulator is not available. Degraded to observation-only static JNI export inspection via android_native_workflow; dynamic JNI experiment remains incomplete.",
				alternatives: ["android_native_workflow", "r2_inspect", "triage"],
			};
		}

		case "native_debugger":
		case "gdb":
		case "lldb": {
			return {
				nextTool: "triage",
				nextParams: { path: targetPath, strings: true, limit: 30 },
				capabilityDepth: "triage",
				prerequisites: ["target_binary_present"],
				verificationBoundary:
					"Static zero-prep binary header and string reconnaissance only. Dynamic breakpoint, live register, and memory tracing criteria remain unsatisfied (requires active debugger).",
				remainingAcceptance: "Dynamic breakpoint, live register, and memory tracing criteria remain unsatisfied.",
				reasoning:
					"Native debugger is unavailable. Degraded to zero-dependency static binary triage (or r2_inspect when radare2 is installed).",
				alternatives: ["triage", "r2_inspect", "binary_metadata_inspect"],
			};
		}

		case "websocket_capture":
		case "traffic_interception":
		case "tshark":
		case "mitmproxy": {
			return {
				nextTool: "pcap_inspect",
				nextParams: { path: targetPath, action: "endpoints", limit: 30 },
				capabilityDepth: "static",
				prerequisites: ["target_pcap_present"],
				verificationBoundary:
					"Offline static PCAP packet parsing. Does not perform live network interface capture or active socket interception.",
				remainingAcceptance: "Live network traffic interception and streaming protocol capture remain unverified.",
				reasoning:
					"Live traffic capture unavailable. Degraded to offline static capture analysis via pcap_inspect.",
				alternatives: ["pcap_inspect", "grep"],
			};
		}

		case "binary_diff":
		case "binary_diffing":
		case "vbindiff": {
			const pathA = (context.params?.path_a ?? context.params?.fileA ?? targetPath) as string;
			const pathB = (context.params?.path_b ?? context.params?.fileB ?? targetPath) as string;
			return {
				nextTool: "binary_diff",
				nextParams: { path_a: pathA, path_b: pathB, action: "summary" },
				capabilityDepth: "static",
				prerequisites: ["both_files_present"],
				verificationBoundary: "Static offline binary byte and block diffing.",
				reasoning: "Visual diff utility unavailable. Degraded to built-in 'binary_diff'.",
				alternatives: ["binary_diff"],
			};
		}
		case "dex_runtime_unpacking":
		case "dex_unpack":
		case "frida-dexdump": {
			return {
				nextTool: "android_package_inspect",
				nextParams: { path: targetPath, action: "dex" },
				capabilityDepth: "static",
				prerequisites: ["target_apk_present"],
				verificationBoundary:
					"Static analysis of available DEX files from unpacked APK/container. Cannot dynamically dump in-memory packed or encrypted classes without dex_unpack and an authorized live device.",
				remainingAcceptance:
					"Dynamic runtime unpacking and in-memory DEX extraction criteria remain unsatisfied without live environment.",
				reasoning:
					"Dynamic DEX unpacking tool is unavailable. Degraded smoothly to zero-prep built-in 'android_package_inspect' for static DEX inspection.",
				alternatives: ["android_package_inspect", "dex_repair", "dex_patch"],
			};
		}

		case "dex_codeitem_repair":
		case "dex_repair":
		case "fart": {
			return {
				nextTool: "dex_patch",
				nextParams: { path: targetPath, dry_run: true },
				capabilityDepth: "static",
				prerequisites: ["target_dex_present"],
				verificationBoundary:
					"Static Dalvik bytecode inspection and patch validation; cannot reconstruct stripped CodeItem method bodies without dump records and dex_repair.",
				remainingAcceptance: "Offline CodeItem method restoration from FART dump records remains unsatisfied.",
				reasoning:
					"DEX repair engine is unavailable. Degraded to static Dalvik bytecode inspection via 'dex_patch' in dry-run mode.",
				alternatives: ["dex_patch", "android_package_inspect"],
			};
		}

		case "dex_structural_search":
		case "dex_search":
		case "dexkit": {
			return {
				nextTool: "android_package_inspect",
				nextParams: { path: targetPath, action: "dex" },
				capabilityDepth: "static",
				prerequisites: ["target_apk_present"],
				verificationBoundary:
					"Static DEX class and method signature listing. Deep structural caller/callee graphs and cross-reference queries require dex_search with DexKit.",
				remainingAcceptance: "Structural code search and cross-reference graph queries remain unsatisfied.",
				reasoning:
					"DexKit structural search is unavailable. Degraded to static class listing via built-in 'android_package_inspect'.",
				alternatives: ["android_package_inspect", "droidasc", "jadx"],
			};
		}

		case "instruction_trace_capture":
		case "instruction_trace":
		case "qbdi": {
			return {
				nextTool: isNative ? "r2_inspect" : "triage",
				nextParams: isNative
					? { path: targetPath, action: "functions" }
					: { path: targetPath, strings: true, limit: 30 },
				capabilityDepth: isNative ? "static" : "triage",
				prerequisites: ["target_binary_present"],
				verificationBoundary:
					"Static disassembly and binary reconnaissance only; synchronized instruction-level register and memory trace capture requires instruction_trace with QBDI.",
				remainingAcceptance:
					"Instruction-level trace capture with synchronized registers and memory reads remains unsatisfied.",
				reasoning:
					"Controlled instruction tracer 'instruction_trace' is unavailable. Degraded to static disassembly/triage without automatic execution.",
				alternatives: ["frida", "r2_inspect", "triage"],
			};
		}

		case "bytecode_deobfuscation":
		case "native_cfg_deobfuscation":
		case "mba_simplification":
		case "deobfuscate":
		case "d810-ng":
		case "simplify":
		case "msynth":
		case "jadx-string-decrypt":
		case "blackdex": {
			if (isNative) {
				return {
					nextTool: "r2_inspect",
					nextParams: { path: targetPath, action: "functions" },
					capabilityDepth: "static",
					prerequisites: ["target_binary_present"],
					verificationBoundary:
						"Static function disassembly and CFG inspection; automated control-flow unflattening and MBA algebraic simplification require deobfuscate.",
					remainingAcceptance: "Automated CFG normalization and MBA algebraic simplification remain unsatisfied.",
					reasoning: "Deobfuscation engine is unavailable. Degraded to static disassembly via r2_inspect.",
					alternatives: ["r2_inspect", "ghidra_inspect", "triage"],
				};
			}
			return {
				nextTool: "android_package_inspect",
				nextParams: { path: targetPath, action: "dex" },
				capabilityDepth: "static",
				prerequisites: ["target_apk_present"],
				verificationBoundary:
					"Static DEX class listing; automated bytecode deobfuscation and string decryption require deobfuscate.",
				remainingAcceptance: "Automated Dalvik bytecode deobfuscation remains unsatisfied.",
				reasoning:
					"Bytecode deobfuscation tool is unavailable. Degraded to static DEX inspection via android_package_inspect.",
				alternatives: ["android_package_inspect", "dex_patch"],
			};
		}

		case "native_path_recovery":
		case "native_recover":
		case "tritondse": {
			return {
				nextTool: "triton_analyze",
				nextParams: { action: "status" },
				capabilityDepth: "static",
				verificationBoundary:
					"Single-path concolic execution or status check; multi-path branch inversion, handler semantic extraction, and differential verification across domain require native_recover.",
				remainingAcceptance:
					"Multi-path DSE exploration and differential equivalence verification remain unsatisfied.",
				reasoning:
					"Bounded native recovery engine 'native_recover' is unavailable. Degraded to status check via triton_analyze without arbitrary seed defaults.",
				alternatives: ["triton_analyze", "r2_inspect", "triage"],
			};
		}

		case "symbolic_trace_analysis":
		case "triton_analyze":
		case "triton": {
			return {
				nextTool: "r2_inspect",
				nextParams: { path: targetPath, action: "functions" },
				capabilityDepth: "static",
				prerequisites: ["target_binary_present"],
				verificationBoundary:
					"Static disassembly and CFG audit; symbolic trace replay and AST synthesis require triton_analyze with triton-library.",
				remainingAcceptance: "Symbolic trace replay and synthesized AST expression remain unsatisfied.",
				reasoning: "Triton symbolic engine is unavailable. Degraded to static disassembly via r2_inspect.",
				alternatives: ["r2_inspect", "ghidra_inspect", "triage"],
			};
		}

		default: {
			const cap = CAPABILITY_CATALOG[normalized];
			if (cap?.recommendedNativeTool) {
				return {
					nextTool: cap.recommendedNativeTool,
					nextParams: { path: targetPath },
					capabilityDepth: "static",
					reasoning: `Recommended native fallback for capability '${cap.name}': ${cap.recommendedNativeTool}.`,
					alternatives: [...cap.fallbacks],
				};
			}
			return undefined;
		}
	}
}

/**
 * Generate a deterministic recovery plan for a failed step.
 * Proposes bounded next attempts, parameter correction, and native tool fallback.
 */
export function generateRecoveryPlan(
	step: WorkflowStepRecord,
	workflow: ReverseWorkflowRecord,
	options: RecoveryPlanOptions = {},
): RecoveryPlan {
	const rawError = options.error ?? step.error ?? step.recovery_metadata?.failure_reason ?? "Step execution failed";
	const targetPath = workflow.target_abs_path || workflow.target;
	const originalTool = step.tool;
	const originalParams = step.params_summary;
	let parsedOriginalParams: Record<string, unknown> = {};
	if (typeof originalParams === "object" && originalParams !== null) {
		parsedOriginalParams = { ...originalParams };
	} else if (typeof originalParams === "string") {
		try {
			const parsed = JSON.parse(originalParams);
			if (typeof parsed === "object" && parsed !== null) {
				parsedOriginalParams = parsed;
			}
		} catch {
			// Not valid JSON string
		}
	}

	const maxAttempts =
		typeof options.maxAttempts === "number" && options.maxAttempts > 0
			? Math.min(options.maxAttempts, HARD_MAX_ATTEMPTS)
			: step.max_attempts || DEFAULT_MAX_ATTEMPTS;

	const currentAttempts = step.attempts ?? 0;
	const exhausted = currentAttempts >= maxAttempts;

	const attribution = classifyFailure(rawError, {
		tool: originalTool,
		stepId: step.id,
		gate: step.gate,
		targetPath,
		targetFormat: workflow.format,
		paramsSummary: originalParams,
	});

	// If exhausted, bounded recovery stops here
	if (exhausted) {
		return {
			attribution,
			suggested_action: "abort",
			original_tool: originalTool,
			next_tool: originalTool,
			original_params: originalParams,
			next_params: originalParams,
			alternatives: [],
			reasoning: `Maximum retry limit reached (${currentAttempts}/${maxAttempts} attempts). Automated retries are bounded to prevent infinite recovery loops.`,
			can_retry: false,
			current_attempts: currentAttempts,
			max_attempts: maxAttempts,
			exhausted: true,
			install_hint: attribution.install_hint,
			setup_command: attribution.setup_command,
		};
	}

	// If caller indicates an external tool was installed to recover from the failure
	if (options.installedTool) {
		const verification = verifyInstalledTool(options.installedTool, {
			cwd: workflow.target_abs_path ? path.dirname(workflow.target_abs_path) : undefined,
		});

		// User supplied verified:true isn't proof; host check is authoritative
		const isVerified = verification.verified;
		const resumeStrategy =
			options.strategy ?? (options.installedTool === originalTool ? "resume_original" : "fallback");
		const resumeMeta: StepResumeMetadata = {
			capability_id: options.capabilityId,
			installed_tool: options.installedTool,
			setup_command: options.setupCommand ?? verification.setup_command ?? attribution.setup_command,
			verified: isVerified,
			strategy: resumeStrategy,
			resumed_at: new Date().toISOString(),
			resumed_params: isVerified ? (options.nextParamsOverride ?? originalParams) : originalParams,
		};

		if (!isVerified) {
			// Unavailable tools return structured missing state without replacing original step or running target
			return {
				attribution,
				suggested_action: "abort",
				original_tool: originalTool,
				next_tool: originalTool,
				original_params: originalParams,
				next_params: originalParams,
				alternatives: [originalTool, ...(attribution.missing_tool ? [attribution.missing_tool] : [])],
				reasoning: `Tool '${options.installedTool}' could not be verified on the host system (${verification.missing_reason ?? "missing binary or unconfigured service"}). Run '${resumeMeta.setup_command}' before resuming execution.`,
				can_retry: false,
				current_attempts: currentAttempts,
				max_attempts: maxAttempts,
				exhausted: false,
				install_hint: verification.setup_command ?? attribution.install_hint,
				setup_command: resumeMeta.setup_command,
				resume: resumeMeta,
			};
		}

		const nextTool =
			options.fallbackToolOverride ?? (resumeStrategy === "resume_original" ? originalTool : options.installedTool);
		const nextParams = options.nextParamsOverride ?? originalParams;
		return {
			attribution,
			suggested_action: nextTool !== originalTool ? "fallback" : "retry",
			original_tool: originalTool,
			next_tool: nextTool,
			original_params: originalParams,
			next_params: nextParams,
			alternatives: [nextTool, ...(attribution.missing_tool ? [attribution.missing_tool] : [])],
			reasoning: `Tool '${options.installedTool}' is installed (verified: true) for capability '${resumeMeta.capability_id || "reverse"}'. Resuming execution via ${resumeStrategy}: tool='${nextTool}'.`,
			can_retry: true,
			current_attempts: currentAttempts,
			max_attempts: maxAttempts,
			exhausted: false,
			install_hint: attribution.install_hint,
			setup_command: attribution.setup_command,
			resume: resumeMeta,
		};
	}

	// Caller overrides take highest priority
	if (options.fallbackToolOverride || options.nextParamsOverride !== undefined) {
		const nextTool = options.fallbackToolOverride ?? originalTool;
		const nextParams = options.nextParamsOverride ?? originalParams;
		return {
			attribution,
			suggested_action: nextTool !== originalTool ? "fallback" : "retry",
			original_tool: originalTool,
			next_tool: nextTool,
			original_params: originalParams,
			next_params: nextParams,
			alternatives: [nextTool],
			reasoning: `Applying caller-provided recovery configuration: tool='${nextTool}'.`,
			can_retry: true,
			current_attempts: currentAttempts,
			max_attempts: maxAttempts,
			exhausted: false,
			install_hint: attribution.install_hint,
			setup_command: attribution.setup_command,
		};
	}

	// Deterministic recovery proposals based on attribution category
	let nextTool = originalTool;
	let nextParams: Record<string, unknown> | string = { ...parsedOriginalParams };
	let alternatives: string[] = [];
	let reasoning = "";
	let suggestedAction: "retry" | "fallback" | "adjust_params" | "abort" = "retry";
	let canRetry = true;
	let prerequisites: string[] = [];
	let capabilityDepth: CapabilityDepth = "static";
	let verificationBoundary: string | undefined;
	let remainingAcceptance: string | undefined;

	const effectiveTargetPath = resolveStepTargetPath(parsedOriginalParams, targetPath);
	const isNative = isBareNativeTarget(effectiveTargetPath, workflow.format);
	const isAndroidNativeSo = isExplicitAndroidJniTarget({
		targetPath: effectiveTargetPath,
		targetFormat: workflow.format,
		tool: originalTool,
		params: parsedOriginalParams,
		stepTitle: step.title,
		workflowGoal: workflow.goal,
	});
	const isApk = isApkTarget(effectiveTargetPath, workflow.format);

	switch (attribution.category) {
		case "missing_dependency": {
			suggestedAction = "fallback";
			if (originalTool === "unidbg") {
				if (isAndroidNativeSo) {
					nextTool = "android_native_workflow";
					nextParams = { path: effectiveTargetPath, action: "inspect" };
					alternatives = ["android_native_workflow", "r2_inspect", "triage"];
					capabilityDepth = "static";
					prerequisites = ["target_binary_present"];
					verificationBoundary =
						"Observation-only static JNI export analysis. Extracts exported symbol names, mangled JNI signatures, and DEX native declarations, but cannot execute native code, evaluate runtime crypto or decryption, or complete dynamic JNI experiments.";
					remainingAcceptance =
						"Dynamic JNI execution, runtime register state, and functional emulation acceptance criteria remain unsatisfied (proxy observation only). A live device or verified emulation harness (e.g. unidbg with JDK 8) is required for dynamic acceptance.";
					reasoning =
						"Unidbg emulator is not available. Degraded to observation-only static JNI export inspection via android_native_workflow; dynamic JNI experiment remains incomplete.";
				} else if (isNative) {
					nextTool = "triage";
					nextParams = { path: effectiveTargetPath, strings: true, limit: 30 };
					alternatives = ["triage", "binary_metadata_inspect"];
					capabilityDepth = "triage";
					prerequisites = ["target_binary_present"];
					verificationBoundary =
						"Target is a generic native binary, not an Android package or JNI library. Routed to multi-format triage.";
					remainingAcceptance = "JNI emulation criteria are not applicable to generic native binaries.";
					reasoning =
						"Unidbg emulator is not applicable to non-Android native binary. Degraded to generic binary triage.";
				} else {
					nextTool = "android_native_workflow";
					nextParams = { path: effectiveTargetPath, action: "inspect" };
					alternatives = ["android_native_workflow", "android_package_inspect"];
					capabilityDepth = "static";
					prerequisites = ["target_apk_present"];
					verificationBoundary =
						"Observation-only static JNI and native library mapping from APK. Does not execute JNI code or run dynamic emulation.";
					remainingAcceptance = "Dynamic JNI execution criteria remain unsatisfied.";
					reasoning =
						"Unidbg emulator is not available. Falling back to android_native_workflow for static JNI export and DEX native mapping.";
				}
			} else if (originalTool === "droidasc" || originalTool === "jadx" || originalTool === "apktool") {
				if (isManifestIntent(parsedOriginalParams, step, originalTool)) {
					nextTool = "android_package_inspect";
					nextParams = { path: effectiveTargetPath, action: "manifest" };
					alternatives = ["android_package_inspect", "jadx", "apktool"];
					capabilityDepth = "static";
					prerequisites = ["target_apk_present"];
					verificationBoundary =
						"Zero-dependency static AXML manifest decoding directly from APK container. Inspects package declaration, components (activities, services, receivers, providers), permissions, and intent filters without decompiling Java/Kotlin source code.";
					remainingAcceptance =
						"Java/Kotlin high-level source decompilation and runtime component activation remain unsatisfied.";
					reasoning = `Primary Android decompilation tool '${originalTool}' is missing. Routed to built-in 'android_package_inspect' with action 'manifest' to decode AndroidManifest.xml directly from APK container without external dependencies.`;
				} else if (isAndroidNativeSo) {
					nextTool = "android_native_workflow";
					nextParams = { path: effectiveTargetPath, action: "inspect" };
					alternatives = ["android_native_workflow", "r2_inspect", "triage"];
					capabilityDepth = "static";
					prerequisites = ["target_binary_present"];
					verificationBoundary =
						"Target is a standalone Android native library (.so), not an APK container. APK decompilers cannot decompile native ELF shared objects. Routed to native inspection.";
					remainingAcceptance = "APK container and manifest criteria are not applicable to bare .so binaries.";
					reasoning = `Target '${effectiveTargetPath}' is a bare native library (.so), not an APK container. Decompilation tool '${originalTool}' is incompatible with native shared objects. Degraded to 'android_native_workflow' for native inspection.`;
				} else if (isNative) {
					nextTool = "triage";
					nextParams = { path: effectiveTargetPath, strings: true, limit: 50 };
					alternatives = ["triage", "binary_metadata_inspect"];
					capabilityDepth = "triage";
					prerequisites = ["target_binary_present"];
					verificationBoundary =
						"Target is a generic standalone native binary, not an APK container or Dalvik executable. Decompilation tools for Dalvik/APK are inapplicable. Routed to multi-format triage.";
					remainingAcceptance = "APK/Dalvik decompilation criteria are not applicable to generic native binaries.";
					reasoning = `Target '${effectiveTargetPath}' is a native binary (${workflow.format || "native"}), not an APK container. Routed to 'triage' for multi-format header and string reconnaissance.`;
				} else if (
					parsedOriginalParams.action === "resources" ||
					(step.title || "").toLowerCase().includes("resource")
				) {
					nextTool = "android_package_inspect";
					nextParams = { path: effectiveTargetPath, action: "resources" };
					alternatives = ["android_package_inspect", "apktool"];
					capabilityDepth = "static";
					prerequisites = ["target_apk_present"];
					verificationBoundary = "Zero-dependency static ARSC resource table inspection.";
					remainingAcceptance = "High-level resource compilation/decompilation requires aapt2/apktool.";
					reasoning = `Primary tool '${originalTool}' is missing. Routed to built-in 'android_package_inspect' with action 'resources' for ARSC table inspection.`;
				} else if (parsedOriginalParams.action === "signing" || (step.title || "").toLowerCase().includes("sign")) {
					nextTool = "android_package_inspect";
					nextParams = { path: effectiveTargetPath, action: "signing" };
					alternatives = ["android_package_inspect", "apksigner"];
					capabilityDepth = "static";
					prerequisites = ["target_apk_present"];
					verificationBoundary =
						"Zero-dependency signature presence and scheme (v1/v2/v3/v3.1) inspection; v4 scheme requires external .idsig file.";
					remainingAcceptance = "Full cryptographic certificate chain verification requires apksigner bridge.";
					reasoning = `Primary tool '${originalTool}' is missing. Routed to built-in 'android_package_inspect' with action 'signing' for signature inspection.`;
				} else {
					nextTool = "android_package_inspect";
					const dexParams: Record<string, unknown> = { path: effectiveTargetPath, action: "dex" };
					if (parsedOriginalParams.filter) dexParams.filter = parsedOriginalParams.filter;
					if (parsedOriginalParams.dex) dexParams.dex = parsedOriginalParams.dex;
					if (typeof parsedOriginalParams.limit === "number") {
						dexParams.limit = Math.min(parsedOriginalParams.limit, 200);
					}
					nextParams = dexParams;
					alternatives = ["android_package_inspect", "jadx", "apktool"];
					capabilityDepth = "static";
					prerequisites = ["target_apk_present"];
					verificationBoundary =
						"Zero-dependency static Dalvik DEX header and class listing. Inspects method signatures and class definitions; does not decompile to high-level Java/Kotlin source.";
					remainingAcceptance = "High-level Java source reconstruction requires jadx/apktool.";
					reasoning = `Primary Android decompilation tool '${originalTool}' is missing. Degraded smoothly to zero-prep built-in tool 'android_package_inspect' for DEX bytecode and package inspection.`;
				}
			} else if (originalTool === "r2_inspect") {
				nextTool = "triage";
				nextParams = { path: effectiveTargetPath, strings: true, limit: 50 };
				alternatives = ["ghidra_inspect", "triage", "binary_metadata_inspect", "read"];
				capabilityDepth = "triage";
				prerequisites = ["target_binary_present"];
				verificationBoundary = "Header and string triage only; no interactive disassembly or CFG reconstruction.";
				remainingAcceptance = "Function disassembly, cross-references, and decompilation remain unverified.";
				reasoning = `Primary disassembly tool 'r2_inspect' is missing. Degraded to built-in 'triage' for section headers and strings inspection.`;
			} else if (originalTool === "ghidra_inspect") {
				nextTool = "r2_inspect";
				nextParams = { path: effectiveTargetPath, action: "functions" };
				alternatives = ["r2_inspect", "triage", "binary_metadata_inspect"];
				capabilityDepth = "static";
				prerequisites = ["radare2_installed", "target_binary_present"];
				verificationBoundary =
					"Static function and disassembly analysis via radare2 (requires radare2 on host). No high-level C/C++ decompilation or AST lifting.";
				remainingAcceptance = "High-level decompiled C/C++ source code criteria remain unverified.";
				reasoning = `Primary decompiler 'ghidra_inspect' is missing. Degraded to 'r2_inspect' (requires radare2 dependency) for function and section analysis.`;
			} else if (originalTool === "gdb" || originalTool === "lldb") {
				nextTool = "triage";
				nextParams = { path: effectiveTargetPath, strings: true, limit: 30 };
				alternatives = ["triage", "r2_inspect", "binary_metadata_inspect"];
				capabilityDepth = "triage";
				prerequisites = ["target_binary_present"];
				verificationBoundary =
					"Static zero-prep binary header and string reconnaissance only. Dynamic breakpoint, live register, and memory tracing criteria remain unsatisfied (requires active debugger).";
				remainingAcceptance = "Dynamic breakpoint, live register, and memory tracing criteria remain unsatisfied.";
				reasoning = `Native debugger '${originalTool}' is unavailable. Degraded to zero-dependency static binary triage (or r2_inspect if radare2 is installed).`;
			} else if (originalTool === "tshark") {
				nextTool = "pcap_inspect";
				let pcapAction = "endpoints";
				if (
					parsedOriginalParams.action &&
					["info", "list", "endpoints", "conversations", "dns"].includes(String(parsedOriginalParams.action))
				) {
					pcapAction = String(parsedOriginalParams.action);
				}
				const pcapPath = resolveStepTargetPath(parsedOriginalParams, targetPath);
				const pcapParams: Record<string, unknown> = {
					path: pcapPath,
					action: pcapAction,
					limit: typeof parsedOriginalParams.limit === "number" ? Math.min(parsedOriginalParams.limit, 200) : 30,
				};
				if (parsedOriginalParams.protocol) pcapParams.protocol = parsedOriginalParams.protocol;
				if (parsedOriginalParams.ip) pcapParams.ip = parsedOriginalParams.ip;
				if (parsedOriginalParams.port) pcapParams.port = parsedOriginalParams.port;
				nextParams = pcapParams;
				alternatives = ["pcap_inspect", "grep"];
				capabilityDepth = "static";
				prerequisites = ["target_pcap_present"];
				verificationBoundary =
					"Offline static PCAP packet parsing. Does not perform live network interface capture or active socket interception.";
				remainingAcceptance = "Live network traffic interception and streaming protocol capture remain unverified.";
				reasoning = `Packet analyzer 'tshark' is missing. Degraded to native zero-dependency 'pcap_inspect'.`;
			} else if (originalTool === "wabt" || originalTool === "wasm2wat") {
				nextTool = "wasm_inspect";
				nextParams = { path: effectiveTargetPath, action: "wat", limit: 50 };
				alternatives = ["wasm_inspect", "read"];
				capabilityDepth = "static";
				prerequisites = ["target_wasm_present"];
				verificationBoundary = "Static WebAssembly bytecode and WAT disassembly.";
				reasoning = `WASM disassembler 'wabt' is missing. Degraded to built-in 'wasm_inspect'.`;
			} else if (originalTool === "vbindiff") {
				nextTool = "binary_diff";
				const pathA =
					parsedOriginalParams.path_a ??
					parsedOriginalParams.path1 ??
					parsedOriginalParams.fileA ??
					parsedOriginalParams.file_a ??
					parsedOriginalParams.original_path ??
					parsedOriginalParams.artifact_path ??
					effectiveTargetPath;
				const pathB =
					parsedOriginalParams.path_b ??
					parsedOriginalParams.path2 ??
					parsedOriginalParams.fileB ??
					parsedOriginalParams.file_b ??
					parsedOriginalParams.modified_path ??
					effectiveTargetPath;
				let diffAction = "summary";
				if (
					parsedOriginalParams.action &&
					["summary", "blocks", "bytes", "headers"].includes(String(parsedOriginalParams.action))
				) {
					diffAction = String(parsedOriginalParams.action);
				} else if (parsedOriginalParams.mode === "bytes") {
					diffAction = "bytes";
				}
				nextParams = {
					path_a: String(pathA),
					path_b: String(pathB),
					action: diffAction,
				};
				alternatives = ["binary_diff"];
				capabilityDepth = "static";
				prerequisites = ["both_files_present"];
				verificationBoundary = "Static offline binary byte and block diffing.";
				reasoning = `Visual diff utility 'vbindiff' is missing. Degraded to built-in 'binary_diff' with valid parameters (path_a, path_b, action).`;
			} else if (originalTool === "ast-grep") {
				nextTool = "grep";
				nextParams = { path: effectiveTargetPath, pattern: String(parsedOriginalParams.pattern ?? "function") };
				alternatives = ["ast_grep", "grep"];
				capabilityDepth = "static";
				verificationBoundary = "Regex pattern matching only; no structural AST awareness.";
				reasoning = `External CLI 'ast-grep' is missing. Degraded to regex search via 'grep'.`;
			} else if (originalTool === "dex_unpack" || originalTool === "frida-dexdump") {
				nextTool = "android_package_inspect";
				nextParams = { path: effectiveTargetPath, action: "dex" };
				alternatives = ["android_package_inspect", "dex_repair", "dex_patch"];
				capabilityDepth = "static";
				prerequisites = ["target_apk_present"];
				verificationBoundary =
					"Static package and DEX inspection; runtime in-memory unpacking requires an attached device and frida-dexdump.";
				remainingAcceptance =
					"Dynamic runtime in-memory extraction of packed DEX remains unsatisfied without device and unpacker.";
				reasoning = `DEX unpacker '${originalTool}' is missing or device is unavailable. Degraded to built-in 'android_package_inspect' for static DEX inspection without automatic device execution.`;
			} else if (originalTool === "dex_repair" || originalTool === "fart") {
				nextTool = "dex_patch";
				nextParams = { path: effectiveTargetPath, dry_run: true };
				alternatives = ["dex_patch", "android_package_inspect"];
				capabilityDepth = "static";
				prerequisites = ["target_dex_present"];
				verificationBoundary =
					"Static Dalvik bytecode inspection and patch validation; cannot reconstruct stripped CodeItems without dump records and FART repair engine.";
				remainingAcceptance = "Offline CodeItem restoration from FART dump records remains unsatisfied.";
				reasoning = `DEX repair tool '${originalTool}' is missing. Degraded to built-in 'dex_patch' with dry_run: true.`;
			} else if (originalTool === "dex_search" || originalTool === "dexkit") {
				nextTool = "android_package_inspect";
				nextParams = { path: effectiveTargetPath, action: "dex" };
				alternatives = ["android_package_inspect", "droidasc"];
				capabilityDepth = "static";
				prerequisites = ["target_apk_present"];
				verificationBoundary =
					"Static DEX class and method listing; deep cross-reference and structural search require dex_search with DexKit.";
				remainingAcceptance = "DexKit structural code search criteria remain unsatisfied.";
				reasoning = `DexKit structural search '${originalTool}' is missing. Degraded to built-in 'android_package_inspect'.`;
			} else if (originalTool === "instruction_trace" || originalTool === "qbdi") {
				nextTool = isNative ? "r2_inspect" : "triage";
				nextParams = isNative
					? { path: effectiveTargetPath, action: "functions" }
					: { path: effectiveTargetPath, strings: true, limit: 30 };
				alternatives = ["frida", "r2_inspect", "triage"];
				capabilityDepth = isNative ? "static" : "triage";
				prerequisites = ["target_binary_present"];
				verificationBoundary =
					"Static disassembly and triage only; instruction-level dynamic execution trace capture requires instruction_trace with QBDI.";
				remainingAcceptance = "Synchronized instruction, register, and memory trace capture remains unsatisfied.";
				reasoning = `Instruction trace tool '${originalTool}' is missing. Degraded to static disassembly/triage without automatic execution.`;
			} else if (originalTool === "deobfuscate") {
				if (isNative) {
					nextTool = "r2_inspect";
					nextParams = { path: effectiveTargetPath, action: "functions" };
					alternatives = ["r2_inspect", "ghidra_inspect", "triage"];
					capabilityDepth = "static";
					prerequisites = ["target_binary_present"];
					verificationBoundary =
						"Static function disassembly; automated control-flow unflattening and MBA algebraic simplification require deobfuscate.";
					remainingAcceptance = "Automated CFG normalization and MBA simplification remain unsatisfied.";
					reasoning = `Deobfuscation tool '${originalTool}' is missing. Degraded to static disassembly via r2_inspect.`;
				} else {
					nextTool = "android_package_inspect";
					nextParams = { path: effectiveTargetPath, action: "dex" };
					alternatives = ["android_package_inspect", "dex_patch"];
					capabilityDepth = "static";
					prerequisites = ["target_apk_present"];
					verificationBoundary =
						"Static DEX class listing; automated bytecode deobfuscation and string decryption require deobfuscate.";
					remainingAcceptance = "Automated Dalvik bytecode deobfuscation remains unsatisfied.";
					reasoning = `Deobfuscation tool '${originalTool}' is missing. Degraded to static DEX inspection via android_package_inspect.`;
				}
			} else if (originalTool === "native_recover" || originalTool === "tritondse") {
				nextTool = "triton_analyze";
				nextParams = { action: "status" };
				alternatives = ["triton_analyze", "r2_inspect", "triage"];
				capabilityDepth = "static";
				verificationBoundary =
					"Single-path concolic execution or status check; multi-path branch inversion, handler semantic extraction, and differential verification across domain require native_recover.";
				remainingAcceptance =
					"Multi-path DSE exploration and differential equivalence verification remain unsatisfied.";
				reasoning = `Bounded native recovery tool '${originalTool}' is missing. Degraded to status check via triton_analyze without arbitrary seed defaults.`;
			} else if (originalTool === "triton_analyze" || originalTool === "triton") {
				nextTool = "r2_inspect";
				nextParams = { path: effectiveTargetPath, action: "functions" };
				alternatives = ["r2_inspect", "ghidra_inspect", "triage"];
				capabilityDepth = "static";
				prerequisites = ["target_binary_present"];
				verificationBoundary =
					"Static disassembly only; symbolic trace replay and AST synthesis require triton_analyze with triton-library.";
				remainingAcceptance = "Symbolic execution trace replay and AST simplification remain unsatisfied.";
				reasoning = `Triton symbolic engine '${originalTool}' is missing. Degraded to static disassembly via r2_inspect.`;
			} else {
				nextTool = "triage";
				nextParams = { path: effectiveTargetPath, strings: true, limit: 30 };
				alternatives = ["triage", "binary_metadata_inspect"];
				capabilityDepth = "triage";
				verificationBoundary = "Exploratory header and string triage only.";
				remainingAcceptance = `Detailed analysis criteria unverified due to missing tool '${originalTool}'.`;
				reasoning = `Tool '${originalTool}' is missing dependency. Degraded to zero-dependency binary triage.`;
			}
			break;
		}

		case "invalid_format": {
			suggestedAction = "fallback";
			if (
				isAndroidNativeSo &&
				(originalTool === "android_package_inspect" || originalTool === "droidasc" || originalTool === "apktool")
			) {
				nextTool = "android_native_workflow";
				nextParams = { path: effectiveTargetPath, action: "inspect" };
				alternatives = ["android_native_workflow", "r2_inspect", "triage"];
				capabilityDepth = "static";
				prerequisites = ["target_binary_present"];
				verificationBoundary =
					"Target is a native ELF shared library (.so), not an APK/ZIP archive. Switched to native library inspection.";
				reasoning = `Target is a native ELF shared library (.so), not an APK/ZIP archive. Switched to 'android_native_workflow' for native symbol inspection.`;
			} else if (
				isNative &&
				(originalTool === "android_package_inspect" || originalTool === "droidasc" || originalTool === "apktool")
			) {
				nextTool = "triage";
				nextParams = { path: effectiveTargetPath, strings: true, limit: 50 };
				alternatives = ["triage", "binary_metadata_inspect", "read"];
				capabilityDepth = "triage";
				prerequisites = ["target_binary_present"];
				verificationBoundary =
					"Target is a generic native binary, not an APK container. APK tool is incompatible. Switched to multi-format triage.";
				reasoning = `Target is a native binary (${workflow.format || "native"}), not an APK container. Switched to 'triage' for header and string reconnaissance.`;
			} else {
				nextTool = "triage";
				nextParams = { path: effectiveTargetPath, strings: true, limit: 50 };
				alternatives = ["triage", "binary_metadata_inspect", "read"];
				capabilityDepth = "triage";
				verificationBoundary = "Raw header and entropy analysis to diagnose corrupt/packed/encrypted container.";
				remainingAcceptance =
					"Format validation and decompilation criteria remain unsatisfied until format is clarified.";
				reasoning = `Target format mismatch or corrupted/packed structure detected. Falling back to multi-format triage and entropy analysis to inspect raw headers and determine true format.`;
			}
			break;
		}

		case "timeout": {
			suggestedAction = "adjust_params";
			nextTool = originalTool;
			const adjusted = { ...parsedOriginalParams };
			if (typeof adjusted.limit === "number" && adjusted.limit > 20) {
				adjusted.limit = 20;
			} else if (!("limit" in adjusted)) {
				adjusted.limit = 20;
			}
			if (originalTool === "r2_inspect" && adjusted.action === "decompile") {
				adjusted.action = "disasm";
				adjusted.limit = 30;
			} else if (originalTool === "triage") {
				adjusted.strings = false;
				adjusted.limit = 30;
			}
			nextParams = adjusted;
			alternatives = ["adjust_params", "triage", "binary_metadata_inspect"];
			capabilityDepth = "static";
			verificationBoundary = "Scope-bounded execution to avoid timeout.";
			reasoning = `Tool execution timed out. Adjusted parameters to bound analysis scope (reduced limit to 20, lighter action) to avoid subsequent timeout.`;
			break;
		}

		case "truncated": {
			suggestedAction = "adjust_params";
			nextTool = originalTool;
			const adjusted = { ...parsedOriginalParams };
			adjusted.limit = 25;
			adjusted.offset = 0;
			nextParams = adjusted;
			alternatives = ["adjust_params", "to_artifact"];
			capabilityDepth = "static";
			verificationBoundary = "Bounded paging parameters (limit: 25, offset: 0) to avoid output buffer overflow.";
			reasoning = `Tool output exceeded inline capacity. Adjusted parameters to use bounded paging (limit: 25, offset: 0).`;
			break;
		}

		case "device_required": {
			suggestedAction = "fallback";
			if (isAndroidNativeSo) {
				nextTool = "android_native_workflow";
				nextParams = { path: effectiveTargetPath, action: "inspect" };
				alternatives = ["android_native_workflow", "r2_inspect", "triage"];
				capabilityDepth = "static";
				prerequisites = ["target_binary_present"];
				verificationBoundary =
					"Observation-only static extraction. Collects static JNI exports, symbol bindings, and DEX native declarations, but cannot execute native code, evaluate dynamic crypto/unpacking logic, or satisfy dynamic JNI experiment acceptance criteria.";
				remainingAcceptance =
					"Dynamic JNI execution, runtime register state, and functional emulation acceptance criteria remain unsatisfied (proxy observation only). A live device or verified emulation harness is required for dynamic acceptance.";
				reasoning =
					"Dynamic analysis requires an attached device or emulator, but none was detected. Target is an Android native library (.so). Degraded to observation-only static inspection via android_native_workflow; JNI dynamic experiment remains incomplete.";
			} else if (isApk) {
				const isManifest = isManifestIntent(parsedOriginalParams, step, originalTool);
				nextTool = "android_package_inspect";
				nextParams = { path: effectiveTargetPath, action: isManifest ? "manifest" : "info" };
				alternatives = ["android_package_inspect", "android_native_workflow", "droidasc"];
				capabilityDepth = "static";
				prerequisites = ["target_apk_present"];
				verificationBoundary =
					"Observation-only static container and manifest analysis. Dynamic device hooks, live memory state, and runtime component activation cannot be verified without an active device.";
				remainingAcceptance =
					"Dynamic runtime execution and live device-dependent acceptance criteria remain unsatisfied (proxy observation only). Requires active device or emulator.";
				reasoning = `Dynamic analysis requires an attached device or emulator, but none was detected. Pivoted to android_package_inspect for offline static container and manifest analysis.`;
			} else {
				nextTool = "triage";
				nextParams = { path: effectiveTargetPath, strings: true, limit: 30 };
				alternatives = ["triage", "r2_inspect"];
				capabilityDepth = "triage";
				prerequisites = ["target_binary_present"];
				verificationBoundary =
					"Observation-only static binary triage. Dynamic runtime debugging and live memory analysis cannot be performed without a live environment.";
				remainingAcceptance = "Dynamic execution and runtime behavior criteria remain unsatisfied.";
				reasoning = `Dynamic analysis requires a live device environment. Degraded to offline static binary triage.`;
			}
			break;
		}

		case "unsupported": {
			if (
				isAndroidNativeSo &&
				(originalTool === "android_package_inspect" || originalTool === "droidasc" || originalTool === "apktool")
			) {
				suggestedAction = "fallback";
				nextTool = "android_native_workflow";
				nextParams = { path: effectiveTargetPath, action: "inspect" };
				alternatives = ["android_native_workflow", "r2_inspect", "triage"];
				capabilityDepth = "static";
				prerequisites = ["target_binary_present"];
				verificationBoundary = `Target is a standalone native library (.so), not an APK container. APK tool '${originalTool}' is incompatible. Routed to native inspection.`;
				remainingAcceptance = "APK container/manifest criteria are not applicable to bare .so binaries.";
				reasoning = `Target '${targetPath}' is a bare native library (.so) which is not supported by APK tool '${originalTool}'. Routed to 'android_native_workflow' for native inspection.`;
			} else if (
				isNative &&
				(originalTool === "android_package_inspect" || originalTool === "droidasc" || originalTool === "apktool")
			) {
				suggestedAction = "fallback";
				nextTool = "triage";
				nextParams = { path: effectiveTargetPath, strings: true, limit: 50 };
				alternatives = ["triage", "binary_metadata_inspect", "grep"];
				capabilityDepth = "triage";
				prerequisites = ["target_binary_present"];
				verificationBoundary = `Target is a generic native binary, not an APK container. APK tool '${originalTool}' is incompatible. Routed to multi-format triage.`;
				remainingAcceptance = "APK container/manifest criteria are not applicable to generic native binaries.";
				reasoning = `Target '${targetPath}' is a native binary, not an APK container. Routed to 'triage' for multi-format reconnaissance.`;
			} else if (!workflow.format || workflow.format === "unknown") {
				suggestedAction = "abort";
				canRetry = false;
				nextTool = originalTool;
				nextParams = originalParams;
				capabilityDepth = "triage";
				verificationBoundary = "Target format is unknown or unsupported; no automated fallback can proceed.";
				remainingAcceptance = "All workflow acceptance criteria remain unsatisfied due to unsupported target.";
				reasoning = `Target format '${workflow.format || "unknown"}' or architecture is unsupported by '${originalTool}'. No automated fallback can fulfill the requested capability without format conversion or architectural support.`;
			} else {
				suggestedAction = "fallback";
				nextTool = "triage";
				nextParams = { path: targetPath, strings: true, limit: 50 };
				alternatives = ["triage", "binary_metadata_inspect", "grep"];
				capabilityDepth = "triage";
				verificationBoundary = `Exploratory binary triage and raw string reconnaissance only. Target architecture/format is unsupported for semantic analysis by '${originalTool}'; this fallback cannot satisfy functional, decompilation, or architectural acceptance criteria.`;
				remainingAcceptance =
					"All workflow acceptance criteria remain unsatisfied due to unsupported target format/architecture.";
				reasoning = `Target contains an unsupported architecture or feature in '${originalTool}'. Proposing exploratory binary triage for raw symbol and string reconnaissance, but this cannot complete the original analysis.`;
			}
			break;
		}

		default: {
			suggestedAction = "retry";
			nextTool = originalTool;
			nextParams = parsedOriginalParams;
			alternatives = [originalTool, "triage"];
			capabilityDepth = "static";
			reasoning = `Unclassified failure. Proposing retry with current parameters (Attempt ${currentAttempts + 1}/${maxAttempts}).`;
			break;
		}
	}

	const discoveryGuidance: DiscoveryGuidance = {
		tool_doc: `read xd://${nextTool}`,
		dispatch_method: "write JSON arguments",
		current_step_only: true,
		notice: `Read xd://${nextTool} before dispatching; emit current step-only progress notices.`,
		next_action_preview: `${nextTool}(${typeof nextParams === "object" ? JSON.stringify(nextParams) : nextParams})`,
	};

	return {
		attribution,
		suggested_action: suggestedAction,
		original_tool: originalTool,
		next_tool: nextTool,
		original_params: originalParams,
		next_params: nextParams,
		alternatives,
		reasoning,
		can_retry: canRetry,
		current_attempts: currentAttempts,
		max_attempts: maxAttempts,
		exhausted: exhausted || !canRetry,
		install_hint: attribution.install_hint,
		setup_command: attribution.setup_command,
		resume: step.recovery_metadata?.resume,
		prerequisites,
		capability_depth: capabilityDepth,
		verification_boundary: verificationBoundary,
		remaining_acceptance: remainingAcceptance,
		discovery_guidance: discoveryGuidance,
	};
}

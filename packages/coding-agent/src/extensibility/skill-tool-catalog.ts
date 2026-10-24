// oxlint-disable no-template-curly-in-string -- catalog paths intentionally carry ${VAR} placeholders expanded by the generic resolver.

/**
 * Built-in catalog of external tools for skills and reverse engineering workflows.
 *
 * Skills only name a logical tool id (`metadata.requires: jadx, adb`). Detection
 * paths and install hints live here so a skill can never smuggle an executable
 * command or an arbitrary search directory into the agent's context: an id that
 * is not in this catalog is still probed on PATH, but it never produces an
 * install hint.
 *
 * Every command in this catalog is client-vetted, trusted, and structured.
 * Automated commands are only ever executed after explicit user selection
 * and interactive confirmation in the setup panel.
 */
import * as child_process from "node:child_process";
import * as fs from "node:fs";
import { $which } from "@reverse/utils";
import { enumeratePythonRuntimes } from "../eval/py/runtime";
import { probeIdaRequirement } from "../ida/install";
import { locateUnidbg } from "./unidbg-detect";
import { resolveVmpTool } from "./vmp-toolchain";
import { probeLiefRequirement, resolveLiefPython, LIEF_VERSION, LIEF_PYPI_PACKAGE } from "./lief-install";
import { resolveSoFixer, normalizeSoFixerArch, canBuildSoFixer, SOFIXER_VERSION } from "./sofixer-toolchain";
import {
	resolveGhidraFindCrypt,
	canBuildGhidraFindCrypt,
	FINDCRYPT_VERSION,
	FINDCRYPT_ANALYZER_NAME,
} from "./findcrypt-install";
export { resolveLiefPython, probeLiefRequirement, LIEF_VERSION, LIEF_PYPI_PACKAGE };
export { resolveSoFixer, normalizeSoFixerArch, canBuildSoFixer, SOFIXER_VERSION };
export { resolveGhidraFindCrypt, canBuildGhidraFindCrypt, FINDCRYPT_VERSION, FINDCRYPT_ANALYZER_NAME };
import { resolveBlutter, resolveHbctool, resolveHermesDec, resolveIl2CppDumper } from "./runtime-toolchain";
export { resolveBlutter, resolveHbctool, resolveHermesDec, resolveIl2CppDumper };
import {
	evaluateUnidbgReadiness,
	evaluateApkUnpackingReadiness,
	type UnidbgReadiness,
	type ApkUnpackingReadiness,
} from "./readiness-evaluator";
import { validateJdk8 } from "./unidbg-builder";
export { evaluateUnidbgReadiness, evaluateApkUnpackingReadiness, type UnidbgReadiness, type ApkUnpackingReadiness };
import type { SkillRequirementWhich } from "./skill-requirements";
import { getAdapterConfigs, resolveAdapter } from "../dap/config";
import type { Settings } from "../config/settings";
import type { ToolSession } from "../tools/index";
export type SkillToolPlatform = "darwin" | "linux" | "win32";

export type ToolCategory = "android" | "binary" | "decompiler" | "web" | "network" | "system" | "general";

/** Environment variable that points at a directory holding the tool. */
export interface SkillToolEnvPath {
	/** Environment variable name, e.g. `ANDROID_HOME`. */
	env: string;
	/** Suffix appended to the variable's value, e.g. `/platform-tools`. */
	suffix?: string;
}

/** Trusted package manager installation recipe. */
export interface PackageInstallCommand {
	/** Package manager identifier, e.g. "brew", "apt", "choco", "winget", "pipx", "pip", "npm", "cargo". */
	manager: string;
	/** Display command string, e.g. "brew install jadx". */
	command: string;
	/** Argv array to execute directly without shell interpolation. */
	argv: readonly string[];
	/** Explanatory risk, prerequisite, or privilege warning. */
	riskNote?: string;
}

/**
 * Canonical model-facing usage guidance for one tool or helper service.
 *
 * Kept next to the trusted detection/install metadata so agents can learn the
 * supported operation, prerequisites, output discipline, and fallback without
 * treating a bare tool name as an instruction manual.
 */
export interface ToolUsageGuide {
	/** Canonical command or operation to reach for first. */
	canonical: string;
	/** When this tool is the right choice. */
	whenToUse: string;
	/** Catalog ids or runtime requirements that must be present first. */
	prerequisites?: readonly string[];
	/** Output discipline: what to keep out of the conversation context. */
	outputLimits?: string;
	/** Lower-tier substitute when this tool is unavailable or fails. */
	fallback?: string;
	/** Trusted, copy-pastable examples. */
	examples: readonly { description: string; command: string }[];
}

/** How to find and install one external tool. */
export interface SkillToolDescriptor {
	/** Logical id used by `metadata.requires` and setup commands. */
	id: string;
	/** Human-friendly name of the tool. */
	name?: string;
	/** Functional category of the reverse tool. */
	category?: ToolCategory;
	/** Brief summary of what the tool does. */
	description?: string;
	/** Whether this tool is optional rather than a core requirement. Defaults to false. */
	optional?: boolean;
	/** Whether this is a standard OS/system utility (strings, file). */
	systemTool?: boolean;
	/** Executable names tried in order. Empty when `probe` owns detection. */
	binaries: readonly string[];
	/** Environment-derived directories prepended to PATH for the lookup. */
	envPaths?: readonly SkillToolEnvPath[];
	/** Extra directories per platform; `~` and `${VAR}` are expanded. */
	searchPaths?: Partial<Record<SkillToolPlatform, readonly string[]>>;
	/** Companion binaries that must also exist (e.g. `java` for `jadx`). */
	secondary?: readonly string[];
	/** Trusted, display-only install hints per platform. */
	installHints?: Partial<Record<SkillToolPlatform, readonly string[]>>;
	/** Custom synchronous detector (used for installs that are not PATH commands). */
	probe?: (deps?: {
		env?: Record<string, string | undefined>;
		platform?: SkillToolPlatform;
		which?: SkillRequirementWhich;
		settings?: Settings;
		cwd?: string;
	}) => string | { path: string; secondaryMissing?: string[]; adapterError?: string } | null;
	/** Official download page or release repository URL for manual installation. */
	manualUrl?: string;
	/** Manual installation instructions per platform when automated install is unavailable. */
	manualInstructions?: Partial<Record<SkillToolPlatform, string>>;
	/** Trusted, client-vetted installation commands grouped by platform. */
	installCommands?: Partial<Record<SkillToolPlatform, readonly PackageInstallCommand[]>>;
	/** Canonical model-facing usage guidance, when the tool needs more than a name. */
	usage?: ToolUsageGuide;
}

/**
 * Canonical reverse engineering capability descriptor.
 *
 * Maps high-level analysis scenarios/capabilities (e.g. android native emulation,
 * APK unpacking, browser debugging) to native built-in tools, optional external tools,
 * fallbacks, trusted setup commands, and post-installation dispatch instructions.
 */
export interface CapabilityDescriptor {
	/** Canonical capability identifier, e.g. "android_native_emulation". */
	id: string;
	/** Human-friendly name of the capability. */
	name: string;
	/** Functional category of the reverse capability. */
	category: ToolCategory;
	/** Short scenario summary describing when to reach for this capability. */
	scenario: string;
	/** Detailed operational description of what this capability does. */
	description: string;
	/** Why this capability / tool is needed over generic techniques. */
	why: string;
	/** Recommended native or built-in tool / agent capability to try first. */
	recommendedNativeTool?: string;
	/** Optional external catalog tool or service IDs that empower this capability. */
	optionalExternalTools: readonly string[];
	/** Prerequisites required before installing or running tools for this capability (e.g. Java, Node). */
	prerequisites?: readonly string[];
	/** Lower-tier fallbacks when external tools are unavailable. */
	fallbacks: readonly string[];
	/** Trusted, client-vetted setup command to install or configure the capability. */
	setupCommand: string;
	/** Instructions on how the agent or user routes and invokes the tool immediately after installation. */
	postInstallInvocation: string;
}

/** External tool status reference within a resolved capability. */
export interface CapabilityToolRef {
	id: string;
	name: string;
	status: "installed" | "missing" | "ready" | "configured" | "unconfigured";
	prerequisitesReady?: boolean;
	configured?: boolean;
	enabled?: boolean | null;
	connection?: "unknown" | string;
	packageManager?: string | null;
	installCommand?: string | null;
}

/** Resolved capability status for runtime discovery and setup reporting. */
export interface ReverseCapabilityStatus {
	id: string;
	name: string;
	category: ToolCategory;
	scenario: string;
	description: string;
	why: string;
	/** Overall capability readiness status. */
	status: "ready" | "available_with_fallbacks" | "missing";
	/** Whether the capability is fully ready with primary/external tools. */
	ready: boolean;
	/** Recommended native tool if any. */
	recommendedNativeTool?: string;
	/** Detailed statuses of the optional external tools associated with this capability. */
	optionalExternalTools: readonly CapabilityToolRef[];
	/** Prerequisites required by the capability tools. */
	prerequisites?: readonly string[];
	/** All defined fallbacks. */
	fallbacks: readonly string[];
	/** Defined fallbacks that are currently available on this machine. */
	availableFallbacks: readonly string[];
	/** Setup command to offer the user. */
	setupCommand: string;
	/** How to invoke the tool after installation completes. */
	postInstallInvocation: string;
	/** Blocked external tools or prerequisites preventing full readiness. */
	blockedRequirements?: readonly string[];
	/** Pipeline readiness breakdown distinguishing offline operations from signed generation and device verification. */
	pipelineStages?: {
		offline: { ready: boolean; requiredTools: readonly string[]; missingTools: readonly string[] };
		signing: { ready: boolean; requiredTools: readonly string[]; missingTools: readonly string[] };
		device: {
			ready: boolean;
			hostPrerequisitesReady: boolean;
			requiredTools: readonly string[];
			missingTools: readonly string[];
			deviceConnected?: boolean;
		};
	};
	/** ELF repair pipeline breakdown distinguishing offline repair from runtime process memory dumping. */
	elfRepairStages?: {
		offline: { ready: boolean; requiredTools: readonly string[]; missingTools: readonly string[] };
		dump: { ready: boolean; requiredTools: readonly string[]; missingTools: readonly string[] };
	};
	/** Whether the capability execution can be initiated (prerequisites met, even if runtime session not connected). */
	canStart?: boolean;
	/** Whether an active runtime session/service/debugger is actively connected and running. */
	runtimeReady?: boolean;
	/** Whether tool dependencies meet version compatibility constraints (e.g. JDK 8 for Unidbg). */
	compatible?: boolean;
	/** Target binding and actual execution are independent of host and connection readiness. */
	targetMatched?: boolean | "unknown";
	executedVerified?: boolean | "unknown";
	/** APK unpacking pipeline breakdown distinguishing zero-dependency baseline extraction from high-level decompilation. */
	unpackingStages?: ApkUnpackingReadiness["stages"];
	/** Unidbg emulation pipeline breakdown distinguishing launch prerequisites from active runtime session. */
	emulationStages?: {
		launchPrerequisites: {
			ready: boolean;
			canStart: boolean;
			installed: boolean;
			compatible: boolean;
			missingRequirements: readonly string[];
			error?: string;
			remedy?: string;
		};
		runtimeSession: {
			connected: boolean;
			activeHarnessCount: number;
			serverName?: string;
			port?: number;
		};
	};
}

/** Options for resolving capability availability on the host system. */
export interface ResolveCapabilitiesOptions {
	platform?: SkillToolPlatform;
	cwd?: string;
	which?: SkillRequirementWhich;
	/** Whether the DAP-based 'debug' agent tool is enabled in current session settings (defaults to true). */
	debugToolEnabled?: boolean;
	/** Optional filter to restrict resolution to a specific canonical capability ID. */
	filterCapability?: string;
	/** Optional filter to restrict resolution to capabilities matching a specific category. */
	filterCategory?: ToolCategory | string;
	/** Optional filter to restrict resolution to capabilities associated with a specific tool. */
	filterTool?: string;
	/** Current tool session for live runtime state resolution. */
	session?: ToolSession | object;
	/** Bypass cached version checks when evaluating environment. */
	refresh?: boolean;
	/** Target file or URL for binding inspection. */
	target?: string;
	/** Host environment variables. */
	env?: Record<string, string | undefined>;
	toolStatuses?: readonly {
		id: string;
		name?: string;
		status: "installed" | "missing";
		packageManager?: string | null;
		installCommand?: string | null;
	}[];
	serviceStatuses?: readonly {
		id: string;
		name?: string;
		ready?: boolean;
		prerequisitesReady?: boolean;
		installed?: boolean;
		configured?: boolean;
		enabled?: boolean | null;
		connection?: "unknown" | string;
		packageManager?: string | null;
		installCommand?: string | null;
	}[];
	/**
	 * Explicit DAP adapter availability overrides (e.g. ['lldb-dap', 'gdb', 'codelldb']).
	 * When provided, bypasses filesystem/PATH DAP config inspection for deterministic capability resolution.
	 */
	dapAdapters?: readonly string[];
}

const UNIX_SEARCH_PATHS = ["/usr/local/bin", "/opt/homebrew/bin", "~/.local/bin", "/snap/bin"] as const;

const ANDROID_PLATFORM_PATHS = {
	darwin: ["~/Library/Android/sdk/platform-tools"],
	linux: ["~/Android/Sdk/platform-tools", "~/Android/sdk/platform-tools"],
	win32: [
		"${LOCALAPPDATA}/Android/Sdk/platform-tools",
		"~/AppData/Local/Android/Sdk/platform-tools",
		"${ProgramFiles}/Android/platform-tools",
	],
} as const;

const ANDROID_BUILD_TOOLS_PATHS = {
	darwin: [
		"/opt/homebrew/bin",
		"/usr/local/bin",
		"${ANDROID_HOME}/build-tools/*",
		"${ANDROID_SDK_ROOT}/build-tools/*",
		"~/Library/Android/sdk/build-tools/*",
		"~/Library/Android/sdk/build-tools/35.0.0",
		"~/Library/Android/sdk/build-tools/34.0.0",
		"~/Library/Android/sdk/build-tools/33.0.0",
	],
	linux: [
		"/usr/bin",
		"/usr/local/bin",
		"${ANDROID_HOME}/build-tools/*",
		"${ANDROID_SDK_ROOT}/build-tools/*",
		"~/Android/Sdk/build-tools/*",
		"~/Android/Sdk/build-tools/35.0.0",
		"~/Android/Sdk/build-tools/34.0.0",
		"~/Android/Sdk/build-tools/33.0.0",
	],
	win32: [
		"${ANDROID_HOME}/build-tools/*",
		"${ANDROID_SDK_ROOT}/build-tools/*",
		"${LOCALAPPDATA}/Android/Sdk/build-tools/*",
		"${LOCALAPPDATA}/Android/Sdk/build-tools/35.0.0",
		"${LOCALAPPDATA}/Android/Sdk/build-tools/34.0.0",
		"${LOCALAPPDATA}/Android/Sdk/build-tools/33.0.0",
	],
} as const;

/**
 * Built-in catalog of external tools for reverse engineering and skill requirements.
 */
export const SKILL_TOOL_CATALOG: Readonly<Record<string, SkillToolDescriptor>> = {
	strings: {
		id: "strings",
		name: "strings",
		category: "system",
		description: "Find and display printable character sequences in binary files",
		systemTool: true,
		optional: false,
		binaries: ["strings"],
		searchPaths: {
			darwin: ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"],
			linux: ["/usr/bin", "/usr/local/bin"],
			win32: ["${ProgramFiles}/Git/usr/bin", "C:/msys64/usr/bin", "${LOCALAPPDATA}/Programs/Git/usr/bin"],
		},
		installHints: {
			darwin: ["xcode-select --install"],
			linux: ["apt install binutils"],
			win32: ["Install Git for Windows or Sysinternals Suite"],
		},
		manualUrl: "https://sourceware.org/binutils/docs/binutils/strings.html",
		manualInstructions: {
			darwin: "Standard macOS tool. Run 'xcode-select --install' if Command Line Tools are missing.",
			linux: "Install binutils package via your system package manager (e.g. sudo apt install binutils).",
			win32: "Install Git for Windows or download Strings from Microsoft Sysinternals.",
		},
		installCommands: {
			darwin: [
				{
					manager: "manual",
					command: "xcode-select --install",
					argv: ["xcode-select", "--install"],
					riskNote: "Triggers Apple Command Line Tools installer dialog.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y binutils",
					argv: ["apt", "install", "-y", "binutils"],
					riskNote: "Installs binutils package via apt. May require root/sudo.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y git",
					argv: ["choco", "install", "-y", "git"],
					riskNote: "Installs Git for Windows (includes strings) via Chocolatey.",
				},
			],
		},
	},

	file: {
		id: "file",
		name: "file",
		category: "system",
		description: "Recognize file types, formats, and architecture headers",
		systemTool: true,
		optional: false,
		binaries: ["file"],
		searchPaths: {
			darwin: ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"],
			linux: ["/usr/bin", "/usr/local/bin"],
			win32: ["${ProgramFiles}/Git/usr/bin", "C:/msys64/usr/bin", "${LOCALAPPDATA}/Programs/Git/usr/bin"],
		},
		installHints: {
			darwin: ["Standard macOS system utility"],
			linux: ["apt install file"],
			win32: ["Install Git for Windows or MSYS2"],
		},
		manualUrl: "https://www.darwinsys.com/file/",
		manualInstructions: {
			darwin: "Pre-installed standard macOS utility.",
			linux: "Install file package via your system package manager (e.g. sudo apt install file).",
			win32: "Install Git for Windows or MSYS2 which includes the file utility.",
		},
		installCommands: {
			linux: [
				{
					manager: "apt",
					command: "apt install -y file",
					argv: ["apt", "install", "-y", "file"],
					riskNote: "Installs file utility via apt. May require root/sudo.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y git",
					argv: ["choco", "install", "-y", "git"],
					riskNote: "Installs Git for Windows (includes file) via Chocolatey.",
				},
			],
		},
	},

	jadx: {
		id: "jadx",
		name: "JADX (Dex to Java decompiler)",
		category: "android",
		description: "Dex to Java decompiler with command line and GUI interfaces",
		optional: true,
		binaries: ["jadx", "jadx-cli"],
		envPaths: [{ env: "JADX_HOME", suffix: "/bin" }],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${LOCALAPPDATA}/Programs/jadx/bin", "~/AppData/Local/Programs/jadx/bin"],
		},
		secondary: ["java"],
		installHints: {
			darwin: ["brew install jadx"],
			linux: ["apt install jadx"],
			win32: ["choco install jadx"],
		},
		manualUrl: "https://github.com/skylot/jadx/releases",
		manualInstructions: {
			darwin: "Download the zip distribution from GitHub releases, unpack it, and add bin/jadx to PATH.",
			linux: "Download the zip distribution from GitHub releases, unpack it to /opt/jadx, and symlink bin/jadx to /usr/local/bin.",
			win32: "Download the zip distribution from GitHub releases, unpack it, and add the bin folder to your PATH.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install jadx",
					argv: ["brew", "install", "jadx"],
					riskNote: "Downloads prebuilt package from Homebrew. Requires Java runtime.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y jadx",
					argv: ["apt", "install", "-y", "jadx"],
					riskNote: "Installs jadx package via apt. Requires Java runtime and root/sudo.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y jadx",
					argv: ["choco", "install", "-y", "jadx"],
					riskNote: "Installs jadx via Chocolatey. Requires Administrator privileges.",
				},
				{
					manager: "winget",
					command: "winget install -e --id Skylot.Jadx",
					argv: ["winget", "install", "-e", "--id", "Skylot.Jadx"],
					riskNote: "Installs jadx via Windows Package Manager.",
				},
			],
		},
	},

	apktool: {
		id: "apktool",
		name: "Apktool",
		category: "android",
		description: "Reverse engineer Android APK files (decode resources, disassemble smali, rebuild)",
		optional: true,
		binaries: ["apktool"],
		envPaths: [{ env: "APKTOOL_HOME", suffix: "/bin" }],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${LOCALAPPDATA}/apktool", "~/AppData/Local/apktool"],
		},
		secondary: ["java"],
		installHints: {
			darwin: ["brew install apktool"],
			linux: ["apt install apktool"],
			win32: ["choco install apktool"],
		},
		manualUrl: "https://github.com/iBotPeaches/Apktool/releases",
		manualInstructions: {
			darwin:
				"Download apktool jar and wrapper script from https://apktool.org/docs/install and put them in /usr/local/bin.",
			linux: "Download apktool jar and wrapper script from https://apktool.org/docs/install and put them in /usr/local/bin.",
			win32: "Download apktool jar and apktool.bat from https://apktool.org/docs/install and put them in C:\\Windows.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install apktool",
					argv: ["brew", "install", "apktool"],
					riskNote: "Installs apktool via Homebrew. Requires Java runtime.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y apktool",
					argv: ["apt", "install", "-y", "apktool"],
					riskNote: "Installs apktool via apt. Requires Java runtime and root/sudo.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y apktool",
					argv: ["choco", "install", "-y", "apktool"],
					riskNote: "Installs apktool via Chocolatey. Requires Administrator privileges.",
				},
			],
		},
	},

	adb: {
		id: "adb",
		name: "ADB (Android Debug Bridge)",
		category: "android",
		description: "Communicate with connected Android devices or emulators",
		optional: true,
		binaries: ["adb"],
		envPaths: [
			{ env: "ANDROID_HOME", suffix: "/platform-tools" },
			{ env: "ANDROID_SDK_ROOT", suffix: "/platform-tools" },
		],
		searchPaths: ANDROID_PLATFORM_PATHS,
		installHints: {
			darwin: ["brew install --cask android-platform-tools"],
			linux: ["apt install android-tools-adb"],
			win32: ["choco install adb"],
		},
		manualUrl: "https://developer.android.com/tools/releases/platform-tools",
		manualInstructions: {
			darwin: "Download Android SDK Platform-Tools from Google and extract to ~/Library/Android/sdk/platform-tools.",
			linux: "Download Android SDK Platform-Tools zip from Google and add platform-tools to PATH.",
			win32: "Download SDK Platform-Tools for Windows and extract to C:\\platform-tools, then add to PATH.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install --cask android-platform-tools",
					argv: ["brew", "install", "--cask", "android-platform-tools"],
					riskNote: "Installs Android Platform Tools cask via Homebrew.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y android-tools-adb",
					argv: ["apt", "install", "-y", "android-tools-adb"],
					riskNote: "Installs Android tools via apt. May require root/sudo.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y adb",
					argv: ["choco", "install", "-y", "adb"],
					riskNote: "Installs ADB via Chocolatey.",
				},
				{
					manager: "winget",
					command: "winget install -e --id Google.PlatformTools",
					argv: ["winget", "install", "-e", "--id", "Google.PlatformTools"],
					riskNote: "Installs Android Platform Tools via winget.",
				},
			],
		},
	},

	frida: {
		id: "frida",
		name: "Frida Tools",
		category: "binary",
		description: "Dynamic code instrumentation and inspection toolkit",
		optional: true,
		binaries: ["frida", "frida-ps", "frida-ls-devices"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: [
				"${APPDATA}/Python/Scripts",
				"${LOCALAPPDATA}/Programs/Python/Python312/Scripts",
				"${LOCALAPPDATA}/Programs/Python/Python311/Scripts",
			],
		},
		installHints: {
			darwin: ["pipx install frida-tools"],
			linux: ["pipx install frida-tools"],
			win32: ["py -m pip install --user frida-tools"],
		},
		manualUrl: "https://frida.re/docs/installation/",
		manualInstructions: {
			darwin: "Run 'pipx install frida-tools' or 'python3 -m pip install --user frida-tools'.",
			linux: "Run 'pipx install frida-tools' or 'python3 -m pip install --user frida-tools'.",
			win32: "Run 'py -m pip install --user frida-tools'.",
		},
		installCommands: {
			darwin: [
				{
					manager: "pipx",
					command: "pipx install frida-tools",
					argv: ["pipx", "install", "frida-tools"],
					riskNote: "Installs into an isolated Python environment via pipx.",
				},
				{
					manager: "pip",
					command: "python3 -m pip install --user frida-tools",
					argv: ["python3", "-m", "pip", "install", "--user", "frida-tools"],
					riskNote: "Installs into user Python packages directory.",
				},
			],
			linux: [
				{
					manager: "pipx",
					command: "pipx install frida-tools",
					argv: ["pipx", "install", "frida-tools"],
					riskNote: "Installs into an isolated Python environment via pipx.",
				},
				{
					manager: "pip",
					command: "python3 -m pip install --user frida-tools",
					argv: ["python3", "-m", "pip", "install", "--user", "frida-tools"],
					riskNote: "Installs into user Python packages directory.",
				},
			],
			win32: [
				{
					manager: "pipx",
					command: "pipx install frida-tools",
					argv: ["pipx", "install", "frida-tools"],
					riskNote: "Installs into an isolated Python environment via pipx.",
				},
				{
					manager: "pip",
					command: "py -m pip install --user frida-tools",
					argv: ["py", "-m", "pip", "install", "--user", "frida-tools"],
					riskNote: "Installs into user site-packages.",
				},
			],
		},
		usage: {
			canonical: "frida(action: 'ps', usb: true)",
			whenToUse:
				"Dynamic code instrumentation, custom scripts, runtime hooking, device discovery, process listing, or module inspection via built-in frida.",
			prerequisites: ["frida"],
			outputLimits:
				"Scripts print only matched arguments/return values; write full traces to ./artifacts and read bounded ranges.",
			fallback: "adb logcat plus static smali/native analysis when the runtime cannot be instrumented.",
			examples: [
				{
					description: "Attach to the frontmost Android app and load a hook script",
					command: "frida -U -l hook.js -f com.example.app",
				},
				{
					description: "List attachable processes without spawning",
					command: "frida-ps -U",
				},
			],
		},
	},

	radare2: {
		id: "radare2",
		name: "Radare2",
		category: "binary",
		description: "Complete framework for reverse engineering, disassembly, and binary analysis",
		optional: true,
		binaries: ["r2", "radare2"],
		envPaths: [{ env: "R2_PREFIX", suffix: "/bin" }],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${LOCALAPPDATA}/Programs/radare2/bin", "~/radare2/bin"],
		},
		installHints: {
			darwin: ["brew install radare2"],
			linux: ["apt install radare2"],
			win32: ["choco install radare2"],
		},
		manualUrl: "https://github.com/radareorg/radare2/releases",
		manualInstructions: {
			darwin: "Install via brew or download release tarball from https://github.com/radareorg/radare2/releases.",
			linux: "Install via apt/pacman or build from git: git clone https://github.com/radareorg/radare2 && sys/install.sh.",
			win32: "Download the Windows release zip from GitHub releases and extract to PATH.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install radare2",
					argv: ["brew", "install", "radare2"],
					riskNote: "Installs radare2 framework and CLI utilities via Homebrew.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y radare2",
					argv: ["apt", "install", "-y", "radare2"],
					riskNote: "Installs radare2 via apt. May require root/sudo.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y radare2",
					argv: ["choco", "install", "-y", "radare2"],
					riskNote: "Installs radare2 via Chocolatey.",
				},
			],
		},
		usage: {
			canonical: 'r2 -qc "<commands>" <binary>',
			whenToUse:
				"Headless binary triage and disassembly when IDA/idalib is unavailable: headers, imports, sections, strings, xrefs, and single-function disassembly.",
			prerequisites: ["radare2"],
			outputLimits:
				"Query one concern per invocation; use 'pd 40 @ <addr>' style bounds instead of dumping whole functions or files.",
			fallback: "readelf/objdump, llvm-objdump, or strings + file for baseline triage.",
			examples: [
				{
					description: "Show binary info, sections, and imports in one pass",
					command: 'r2 -qc "iI; iS; ii" ./sample.bin',
				},
				{
					description: "Analyze and disassemble 40 instructions at a function",
					command: 'r2 -qc "aaa; s main; pd 40" ./sample.bin',
				},
				{
					description: "Find callers of a symbol",
					command: 'r2 -qc "aaa; axt @ sym.imp.malloc" ./sample.bin',
				},
			],
		},
	},
	ghidra: {
		id: "ghidra",
		name: "Ghidra",
		category: "decompiler",
		description: "NSA software reverse engineering framework with headless analysis and decompiler",
		optional: true,
		binaries: ["analyzeHeadless", "ghidra"],
		envPaths: [
			{ env: "GHIDRA_INSTALL_DIR", suffix: "/support" },
			{ env: "GHIDRA_HOME", suffix: "/support" },
			{ env: "GHIDRA_INSTALL_DIR" },
			{ env: "GHIDRA_HOME" },
		],
		searchPaths: {
			darwin: [
				"/Applications/ghidra*/support",
				"/opt/homebrew/Caskroom/ghidra/*/ghidra_*/support",
				"/opt/homebrew/bin",
				...UNIX_SEARCH_PATHS,
			],
			linux: ["/opt/ghidra/support", "/usr/share/ghidra/support", ...UNIX_SEARCH_PATHS],
			win32: ["C:/ghidra/support", "${LOCALAPPDATA}/Programs/ghidra/support", "~/ghidra/support"],
		},
		secondary: ["java"],
		installHints: {
			darwin: ["brew install --cask ghidra"],
			linux: ["apt install ghidra", "snap install ghidra --classic"],
			win32: ["choco install ghidra", "winget install NationalSecurityAgency.Ghidra"],
		},
		manualUrl: "https://ghidra-sre.org/",
		manualInstructions: {
			darwin:
				"Install via 'brew install --cask ghidra' or extract release zip and set GHIDRA_INSTALL_DIR (requires JDK 17+).",
			linux: "Install via package manager or extract release zip to /opt/ghidra and set GHIDRA_INSTALL_DIR (requires JDK 17+).",
			win32: "Install via 'choco install ghidra' or extract release zip and set GHIDRA_INSTALL_DIR (requires JDK 17+).",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install --cask ghidra",
					argv: ["brew", "install", "--cask", "ghidra"],
					riskNote: "Installs Ghidra SRE suite via Homebrew Cask (requires JDK 17+).",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y ghidra",
					argv: ["apt", "install", "-y", "ghidra"],
					riskNote: "Installs Ghidra via apt. May require root/sudo.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y ghidra",
					argv: ["choco", "install", "-y", "ghidra"],
					riskNote: "Installs Ghidra via Chocolatey.",
				},
			],
		},
		usage: {
			canonical: "analyzeHeadless <project_dir> <project_name> -import <binary> -readOnly",
			whenToUse: "Headless binary analysis, decompilation, and batch reverse engineering when IDA is unavailable.",
			prerequisites: ["ghidra"],
			outputLimits:
				"Query specific functions or bounded export regions; avoid dumping entire binary listings into context.",
			fallback: "r2_inspect or native triage for lightweight inspection.",
			examples: [
				{
					description: "Run headless analysis on a binary",
					command: "analyzeHeadless /tmp/ghidra_proj temp_proj -import sample.bin -readOnly -deleteProject",
				},
			],
		},
	},

	droidasc: {
		id: "droidasc",
		name: "droidasc",
		category: "android",
		description: "Android reverse analysis and APK inspection companion",
		optional: true,
		binaries: ["droidasc"],
		searchPaths: {
			darwin: [
				"~/.local/bin",
				"~/Library/Python/3.12/bin",
				"~/Library/Python/3.11/bin",
				"/opt/homebrew/bin",
				"/usr/local/bin",
			],
			linux: UNIX_SEARCH_PATHS,
			win32: [
				"${APPDATA}/Python/Scripts",
				"${APPDATA}/Python/Python312/Scripts",
				"${LOCALAPPDATA}/Programs/Python/Python312/Scripts",
			],
		},
		installHints: {
			darwin: ["pipx install droidasc", "python -m pip install droidasc"],
			linux: ["pipx install droidasc", "python -m pip install droidasc"],
			win32: ["pipx install droidasc", "python -m pip install droidasc"],
		},
		manualUrl: "https://github.com/MG1937/ASC",
		manualInstructions: {
			darwin: "Run 'pipx install droidasc' or 'python3 -m pip install --user droidasc'.",
			linux: "Run 'pipx install droidasc' or 'python3 -m pip install --user droidasc'.",
			win32: "Run 'pipx install droidasc' or 'py -m pip install --user droidasc'.",
		},
		installCommands: {
			darwin: [
				{
					manager: "pipx",
					command: "pipx install droidasc",
					argv: ["pipx", "install", "droidasc"],
					riskNote: "Installs droidasc into an isolated user Python environment.",
				},
				{
					manager: "pip",
					command: "python3 -m pip install --user droidasc",
					argv: ["python3", "-m", "pip", "install", "--user", "droidasc"],
					riskNote: "Installs droidasc via pip into user site-packages.",
				},
			],
			linux: [
				{
					manager: "pipx",
					command: "pipx install droidasc",
					argv: ["pipx", "install", "droidasc"],
					riskNote: "Installs droidasc into an isolated user Python environment.",
				},
				{
					manager: "pip",
					command: "python3 -m pip install --user droidasc",
					argv: ["python3", "-m", "pip", "install", "--user", "droidasc"],
					riskNote: "Installs droidasc via pip into user site-packages.",
				},
			],
			win32: [
				{
					manager: "pipx",
					command: "pipx install droidasc",
					argv: ["pipx", "install", "droidasc"],
					riskNote: "Installs droidasc into user environment via pipx.",
				},
				{
					manager: "pip",
					command: "py -m pip install --user droidasc",
					argv: ["py", "-m", "pip", "install", "--user", "droidasc"],
					riskNote: "Installs droidasc via pip.",
				},
			],
		},
	},

	"ast-grep": {
		id: "ast-grep",
		name: "ast-grep",
		category: "general",
		description: "Fast AST-based code search, linting, and rewriting CLI",
		optional: true,
		binaries: ["ast-grep"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${APPDATA}/npm", "${LOCALAPPDATA}/Programs/ast-grep/bin"],
		},
		installHints: {
			darwin: ["brew install ast-grep"],
			linux: ["npm install --global @ast-grep/cli"],
			win32: ["npm install --global @ast-grep/cli"],
		},
		manualUrl: "https://ast-grep.github.io/",
		manualInstructions: {
			darwin: "Install via 'brew install ast-grep' or 'npm install --global @ast-grep/cli'.",
			linux: "Install via 'npm install --global @ast-grep/cli' or download from GitHub releases.",
			win32: "Install via 'npm install --global @ast-grep/cli' or 'choco install ast-grep'.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install ast-grep",
					argv: ["brew", "install", "ast-grep"],
					riskNote: "Installs native ast-grep binary via Homebrew.",
				},
				{
					manager: "npm",
					command: "npm install --global @ast-grep/cli",
					argv: ["npm", "install", "--global", "@ast-grep/cli"],
					riskNote: "Installs @ast-grep/cli package globally via npm.",
				},
			],
			linux: [
				{
					manager: "npm",
					command: "npm install --global @ast-grep/cli",
					argv: ["npm", "install", "--global", "@ast-grep/cli"],
					riskNote: "Installs @ast-grep/cli package globally via npm.",
				},
				{
					manager: "brew",
					command: "brew install ast-grep",
					argv: ["brew", "install", "ast-grep"],
					riskNote: "Installs ast-grep via Linuxbrew.",
				},
			],
			win32: [
				{
					manager: "npm",
					command: "npm install --global @ast-grep/cli",
					argv: ["npm", "install", "--global", "@ast-grep/cli"],
					riskNote: "Installs @ast-grep/cli package globally via npm.",
				},
				{
					manager: "choco",
					command: "choco install -y ast-grep",
					argv: ["choco", "install", "-y", "ast-grep"],
					riskNote: "Installs ast-grep via Chocolatey.",
				},
			],
		},
	},

	wabt: {
		id: "wabt",
		name: "WABT (WebAssembly Binary Toolkit)",
		category: "web",
		description: "WebAssembly disassembly and conversion toolset (wasm2wat, wat2wasm, wasm-objdump)",
		optional: true,
		binaries: ["wasm2wat", "wat2wasm"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: [
				"${LOCALAPPDATA}/Programs/wabt/bin",
				"${LOCALAPPDATA}/Programs/wabt",
				"${USERPROFILE}/.reverse/agent/tools/wabt/bin",
				"~/.reverse/agent/tools/wabt/bin",
				"~/wabt/bin",
			],
		},
		installHints: {
			darwin: ["brew install wabt"],
			linux: ["apt install wabt"],
			win32: [
				"reverse setup reverse wabt",
				"scoop install wabt",
				"Download prebuilt release from https://github.com/WebAssembly/wabt/releases",
			],
		},
		manualUrl: "https://github.com/WebAssembly/wabt/releases",
		manualInstructions: {
			darwin: "Install via 'brew install wabt' or download prebuilt tarball from GitHub releases.",
			linux: "Install via 'apt install wabt' or download prebuilt release from GitHub releases.",
			win32: "Download wabt-*-windows-x64.tar.gz from https://github.com/WebAssembly/wabt/releases and unpack to %LOCALAPPDATA%\\Programs\\wabt\\bin.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install wabt",
					argv: ["brew", "install", "wabt"],
					riskNote: "Installs WABT utilities (wasm2wat, wat2wasm, wasm-decompile) via Homebrew.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y wabt",
					argv: ["apt", "install", "-y", "wabt"],
					riskNote: "Installs wabt utilities via apt. May require root/sudo.",
				},
			],
			win32: [
				{
					manager: "portable",
					command: "reverse setup reverse wabt",
					argv: ["reverse", "setup", "reverse", "wabt", "--execute"],
					riskNote: "Downloads portable WABT windows-x64 release from GitHub into agent tools directory.",
				},
				{
					manager: "scoop",
					command: "scoop install wabt",
					argv: ["scoop", "install", "wabt"],
					riskNote: "Installs wabt via Scoop.",
				},
			],
		},
	},

	upx: {
		id: "upx",
		name: "UPX",
		category: "binary",
		description: "Ultimate Packer for eXecutables (binary packer, unpacker, and compression analyzer)",
		optional: true,
		binaries: ["upx"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${LOCALAPPDATA}/Programs/upx", "~/upx"],
		},
		installHints: {
			darwin: ["brew install upx"],
			linux: ["apt install upx-ucl"],
			win32: ["choco install upx"],
		},
		manualUrl: "https://github.com/upx/upx/releases",
		manualInstructions: {
			darwin: "Install via 'brew install upx' or extract release tarball from GitHub releases.",
			linux: "Install via 'apt install upx-ucl' (or 'apt install upx') or extract from GitHub releases.",
			win32: "Install via 'choco install upx' or download release zip from GitHub releases and extract to PATH.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install upx",
					argv: ["brew", "install", "upx"],
					riskNote: "Installs UPX packer/unpacker via Homebrew.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y upx-ucl",
					argv: ["apt", "install", "-y", "upx-ucl"],
					riskNote: "Installs UPX via apt. May require root/sudo.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y upx",
					argv: ["choco", "install", "-y", "upx"],
					riskNote: "Installs UPX via Chocolatey.",
				},
				{
					manager: "winget",
					command: "winget install -e --id UPX.UPX",
					argv: ["winget", "install", "-e", "--id", "UPX.UPX"],
					riskNote: "Installs UPX via winget.",
				},
			],
		},
	},

	aapt2: {
		id: "aapt2",
		name: "AAPT2",
		category: "android",
		description: "Android Asset Packaging Tool 2 (inspect APK resources, parse manifest, dump badging)",
		optional: true,
		binaries: ["aapt2"],
		envPaths: [
			{ env: "ANDROID_HOME", suffix: "/build-tools" },
			{ env: "ANDROID_SDK_ROOT", suffix: "/build-tools" },
		],
		searchPaths: ANDROID_BUILD_TOOLS_PATHS,
		installHints: {
			darwin: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
			linux: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
			win32: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
		},
		manualUrl: "https://developer.android.com/tools/aapt2",
		manualInstructions: {
			darwin:
				"Install via Android Studio SDK Manager or CLI: sdkmanager 'build-tools;35.0.0'. Add build-tools to PATH.",
			linux: "Install via Android Studio SDK Manager or CLI: sdkmanager 'build-tools;35.0.0'. Add build-tools to PATH.",
			win32: "Install via Android Studio SDK Manager -> SDK Tools -> Android SDK Build-Tools.",
		},
		installCommands: {
			darwin: [
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y aapt",
					argv: ["apt", "install", "-y", "aapt"],
					riskNote: "Installs aapt package via apt. Requires root/sudo.",
				},
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
			win32: [
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
		},
	},

	zipalign: {
		id: "zipalign",
		name: "zipalign",
		category: "android",
		description: "Archive alignment tool for Android application (.apk) files",
		optional: true,
		binaries: ["zipalign"],
		envPaths: [
			{ env: "ANDROID_HOME", suffix: "/build-tools" },
			{ env: "ANDROID_SDK_ROOT", suffix: "/build-tools" },
		],
		searchPaths: ANDROID_BUILD_TOOLS_PATHS,
		installHints: {
			darwin: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
			linux: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
			win32: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
		},
		manualUrl: "https://developer.android.com/tools/zipalign",
		manualInstructions: {
			darwin:
				"Install via Android Studio SDK Manager or CLI: sdkmanager 'build-tools;35.0.0'. Add build-tools to PATH.",
			linux: "Install via Android Studio SDK Manager or CLI: sdkmanager 'build-tools;35.0.0'. Add build-tools to PATH.",
			win32: "Install via Android Studio SDK Manager -> SDK Tools -> Android SDK Build-Tools.",
		},
		installCommands: {
			darwin: [
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y zipalign",
					argv: ["apt", "install", "-y", "zipalign"],
					riskNote: "Installs zipalign package via apt. Requires root/sudo.",
				},
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
			win32: [
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
		},
	},

	apksigner: {
		id: "apksigner",
		name: "apksigner",
		category: "android",
		description: "Verify APK signatures and inspect APK signing schemes (v1, v2, v3, v4)",
		optional: true,
		binaries: ["apksigner"],
		envPaths: [
			{ env: "ANDROID_HOME", suffix: "/build-tools" },
			{ env: "ANDROID_SDK_ROOT", suffix: "/build-tools" },
		],
		searchPaths: ANDROID_BUILD_TOOLS_PATHS,
		secondary: ["java"],
		installHints: {
			darwin: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
			linux: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
			win32: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
		},
		manualUrl: "https://developer.android.com/tools/apksigner",
		manualInstructions: {
			darwin: "Install via Android Studio SDK Manager or CLI: sdkmanager 'build-tools;35.0.0'. Requires Java.",
			linux: "Install via Android Studio SDK Manager or CLI: sdkmanager 'build-tools;35.0.0'. Requires Java.",
			win32: "Install via Android Studio SDK Manager -> SDK Tools -> Android SDK Build-Tools. Requires Java.",
		},
		installCommands: {
			darwin: [
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y apksigner",
					argv: ["apt", "install", "-y", "apksigner"],
					riskNote: "Installs apksigner package via apt. Requires root/sudo.",
				},
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
			win32: [
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
		},
	},

	dexdump: {
		id: "dexdump",
		name: "dexdump",
		category: "android",
		description: "Disassemble Android Dalvik Executable (DEX) bytecode and classes",
		optional: true,
		binaries: ["dexdump"],
		envPaths: [
			{ env: "ANDROID_HOME", suffix: "/build-tools" },
			{ env: "ANDROID_SDK_ROOT", suffix: "/build-tools" },
		],
		searchPaths: ANDROID_BUILD_TOOLS_PATHS,
		installHints: {
			darwin: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
			linux: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
			win32: ["Install via Android SDK build-tools (sdkmanager 'build-tools;35.0.0')"],
		},
		manualUrl: "https://developer.android.com/tools/releases/build-tools",
		manualInstructions: {
			darwin:
				"Available in Android SDK build-tools directory (e.g. ~/Library/Android/sdk/build-tools/<version>/dexdump).",
			linux: "Install via Android Studio SDK Manager or CLI: sdkmanager 'build-tools;35.0.0'.",
			win32: "Located inside %LOCALAPPDATA%\\Android\\Sdk\\build-tools\\<version>\\dexdump.exe.",
		},
		installCommands: {
			darwin: [
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
			linux: [
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
			win32: [
				{
					manager: "sdkmanager",
					command: 'sdkmanager "build-tools;35.0.0"',
					argv: ["sdkmanager", "build-tools;35.0.0"],
					riskNote:
						"Installs Android build-tools 35.0.0 via sdkmanager. Requires previously accepted Android SDK terms; run 'sdkmanager --licenses' manually first; setup cannot auto-accept.",
				},
			],
		},
	},

	sdkmanager: {
		id: "sdkmanager",
		name: "Android SDK Manager",
		category: "android",
		description: "Official Android command-line SDK package manager",
		optional: true,
		binaries: ["sdkmanager"],
		secondary: ["java"],
		envPaths: [
			{ env: "ANDROID_HOME", suffix: "/cmdline-tools/latest/bin" },
			{ env: "ANDROID_HOME", suffix: "/cmdline-tools/bin" },
			{ env: "ANDROID_HOME", suffix: "/tools/bin" },
			{ env: "ANDROID_SDK_ROOT", suffix: "/cmdline-tools/latest/bin" },
		],
		searchPaths: {
			darwin: [
				"~/Library/Android/sdk/cmdline-tools/latest/bin",
				"~/Library/Android/sdk/cmdline-tools/*/bin",
				"~/Library/Android/sdk/tools/bin",
				...UNIX_SEARCH_PATHS,
			],
			linux: [
				"~/Android/Sdk/cmdline-tools/latest/bin",
				"~/Android/Sdk/cmdline-tools/*/bin",
				"~/Android/Sdk/tools/bin",
				...UNIX_SEARCH_PATHS,
			],
			win32: ["${LOCALAPPDATA}/Android/Sdk/cmdline-tools/latest/bin", "${LOCALAPPDATA}/Android/Sdk/tools/bin"],
		},
		installHints: {
			darwin: ["brew install --cask android-commandlinetools"],
			linux: ["Install via Android Studio or download commandlinetools"],
			win32: ["winget install Google.AndroidStudio"],
		},
		manualUrl: "https://developer.android.com/tools/sdkmanager",
		manualInstructions: {
			darwin: "Install Android Command-line Tools via Homebrew: brew install --cask android-commandlinetools",
			linux: "Download commandlinetools from developer.android.com and extract to ~/Android/Sdk/cmdline-tools/latest",
			win32: "Install Android Studio SDK Manager or commandlinetools",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install --cask android-commandlinetools",
					argv: ["brew", "install", "--cask", "android-commandlinetools"],
					riskNote: "Installs Android Command-line Tools via Homebrew cask.",
				},
			],
		},
	},

	unidbg: {
		id: "unidbg",
		name: "Unidbg (ARM32/ARM64 Android Native Library Emulator)",
		category: "android",
		description:
			"Emulate Android ARM32 and ARM64 native JNI libraries (.so) on the host JVM via Maven Java test harness (manual integration required)",
		optional: true,
		binaries: [],
		probe: deps => locateUnidbg({ cwd: deps?.cwd, env: deps?.env }),
		envPaths: [{ env: "UNIDBG_HOME" }, { env: "UNIDBG_ROOT" }, { env: "UNIDBG_JAR" }],
		searchPaths: {
			darwin: ["~/.unidbg", "/usr/local/share/unidbg", "~/unidbg", ...UNIX_SEARCH_PATHS],
			linux: ["~/.unidbg", "/opt/unidbg", "~/unidbg", ...UNIX_SEARCH_PATHS],
			win32: ["${USERPROFILE}/unidbg", "C:/unidbg", "D:/unidbg", "${ProgramFiles}/unidbg"],
		},
		secondary: ["java", "jdk8"],
		installHints: {
			darwin: [
				"git clone https://github.com/zhkl0228/unidbg.git && cd unidbg && ./mvnw -DskipTests package (JDK 8 required)",
			],
			linux: [
				"git clone https://github.com/zhkl0228/unidbg.git && cd unidbg && ./mvnw -DskipTests package (JDK 8 required)",
			],
			win32: [
				"winget install EclipseAdoptium.Temurin.8.JDK && git clone https://github.com/zhkl0228/unidbg.git && cd unidbg && mvnw.cmd -DskipTests package (JDK 8 required)",
			],
		},
		manualUrl: "https://github.com/zhkl0228/unidbg",
		manualInstructions: {
			darwin:
				"Clone https://github.com/zhkl0228/unidbg, compile with './mvnw -DskipTests package' using JDK 8. To enable AI integration, launch McpServer (SSE at http://localhost:9239/sse) or use McpToolkit.",
			linux: "Clone https://github.com/zhkl0228/unidbg, compile with './mvnw -DskipTests package' using JDK 8. To enable AI integration, launch McpServer (SSE at http://localhost:9239/sse) or use McpToolkit.",
			win32: "Clone https://github.com/zhkl0228/unidbg, compile with 'mvnw.cmd -DskipTests package' using JDK 8. To enable AI integration, launch McpServer (SSE at http://localhost:9239/sse) or use McpToolkit.",
		},
		installCommands: {},
		usage: {
			canonical: "reverse unidbg scaffold <target> --entry <func> && reverse unidbg launch <harness>",
			whenToUse:
				"Emulating Android JNI native cryptographic algorithms, token generators, or anti-debug routines on host JVM without an Android device or emulator; or connecting via Unidbg MCP Server.",
			prerequisites: ["jdk8"],
			outputLimits:
				"Capture bounded execution traces and returned buffers; avoid full memory block dumps in conversation context.",
			fallback: "Native ELF triage via readelf/r2_inspect or dynamic device instrumentation via frida_session.",
			examples: [
				{
					description: "Scaffold and launch Android JNI native emulation harness with MCP debugger",
					command:
						"reverse unidbg scaffold libcrypto.so --class com/example/Crypto --entry encrypt && reverse unidbg launch Harness.java",
				},
			],
		},
	},

	bundletool: {
		id: "bundletool",
		name: "bundletool (Android App Bundle tool)",
		category: "android",
		description:
			"Inspect Android App Bundles (.aab), extract APKs, and convert AAB containers to standalone APK sets",
		optional: true,
		binaries: ["bundletool", "bundletool.jar"],
		envPaths: [{ env: "BUNDLETOOL_HOME", suffix: "/bin" }, { env: "BUNDLETOOL_HOME" }],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: [
				"${LOCALAPPDATA}/Programs/bundletool",
				"~/AppData/Local/Programs/bundletool",
				"${USERPROFILE}/.reverse/agent/tools/bundletool",
				"~/.reverse/agent/tools/bundletool",
			],
		},
		secondary: ["java"],
		installHints: {
			darwin: ["brew install bundletool"],
			linux: ["Download bundletool jar from https://github.com/google/bundletool/releases and wrap in shell script"],
			win32: ["reverse setup reverse bundletool"],
		},
		manualUrl: "https://github.com/google/bundletool/releases",
		manualInstructions: {
			darwin:
				"Download the bundletool-all jar from GitHub releases and place an executable wrapper script in /usr/local/bin.",
			linux: "Download the bundletool-all jar from GitHub releases and place an executable wrapper script in /usr/local/bin.",
			win32: "Download the bundletool-all jar from GitHub releases and create a bundletool.bat wrapper in your PATH.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install bundletool",
					argv: ["brew", "install", "bundletool"],
					riskNote: "Installs bundletool via Homebrew. Requires Java runtime.",
				},
			],
			win32: [
				{
					manager: "portable",
					command: "reverse setup reverse bundletool",
					argv: ["reverse", "setup", "reverse", "bundletool", "--execute"],
					riskNote:
						"Downloads portable bundletool-all.jar from GitHub into agent tools directory and generates launcher shim. Requires Java runtime.",
				},
			],
		},
		usage: {
			canonical: "bundletool build-apks --bundle=app.aab --output=app.apks --mode=universal",
			whenToUse:
				"Converting Android App Bundles (.aab) into deployable and inspectable APK packages for reverse engineering.",
			prerequisites: ["java"],
			outputLimits: "Target extracted universal APK; avoid multi-gigabyte device APKS sets in analysis.",
			examples: [
				{
					description: "Convert AAB to universal APK set",
					command: "bundletool build-apks --bundle=release.aab --output=release.apks --mode=universal",
				},
				{
					description: "Dump manifest from Android App Bundle",
					command: "bundletool dump manifest --bundle=release.aab",
				},
			],
		},
	},

	dex2jar: {
		id: "dex2jar",
		name: "dex2jar (Dex to Java conversion tool)",
		category: "android",
		description:
			"Convert Android .dex Dalvik executable bytecode into standard Java .class/.jar files for decompilation",
		optional: true,
		binaries: ["d2j-dex2jar", "dex2jar", "d2j-dex2jar.sh", "d2j-dex2jar.bat"],
		envPaths: [{ env: "DEX2JAR_HOME", suffix: "/bin" }, { env: "DEX2JAR_HOME" }],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${LOCALAPPDATA}/dex2jar", "~/AppData/Local/dex2jar"],
		},
		secondary: ["java"],
		installHints: {
			darwin: ["brew install dex2jar"],
			linux: ["apt install -y dex2jar"],
			win32: ["choco install dex2jar"],
		},
		manualUrl: "https://github.com/pxb1988/dex2jar/releases",
		manualInstructions: {
			darwin:
				"Download the zip archive from GitHub releases, unpack, and add the directory containing d2j-dex2jar.sh to PATH.",
			linux: "Download the zip archive from GitHub releases, unpack to /opt/dex2jar, and symlink d2j-dex2jar.sh to /usr/local/bin.",
			win32: "Download the zip archive from GitHub releases, unpack, and add the folder containing d2j-dex2jar.bat to PATH.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install dex2jar",
					argv: ["brew", "install", "dex2jar"],
					riskNote: "Installs dex2jar via Homebrew. Requires Java runtime.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y dex2jar",
					argv: ["apt", "install", "-y", "dex2jar"],
					riskNote: "Installs dex2jar package via apt. Requires Java runtime and root/sudo.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y dex2jar",
					argv: ["choco", "install", "-y", "dex2jar"],
					riskNote: "Installs dex2jar via Chocolatey. Requires Administrator privileges.",
				},
			],
		},
		usage: {
			canonical: "d2j-dex2jar classes.dex -o classes-dex2jar.jar",
			whenToUse:
				"Converting DEX bytecode to Java JAR when feeding Dalvik code into third-party Java decompilers (CFR, Fernflower, Procyon).",
			prerequisites: ["java"],
			examples: [
				{
					description: "Convert classes.dex to JAR file",
					command: "d2j-dex2jar classes.dex -o classes.jar",
				},
			],
		},
	},

	baksmali: {
		id: "baksmali",
		name: "baksmali (Dalvik bytecode disassembler)",
		category: "android",
		description: "Disassemble Android Dalvik Executable (DEX) bytecode into precise human-readable smali assembly",
		optional: true,
		binaries: ["baksmali", "smali"],
		envPaths: [{ env: "SMALI_HOME", suffix: "/bin" }, { env: "SMALI_HOME" }],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: [
				"${LOCALAPPDATA}/Programs/smali",
				"${LOCALAPPDATA}/smali",
				"~/AppData/Local/smali",
				"${USERPROFILE}/.reverse/agent/tools/smali",
				"~/.reverse/agent/tools/smali",
			],
		},
		secondary: ["java"],
		installHints: {
			darwin: ["brew install smali"],
			linux: ["apt install -y smali"],
			win32: [
				"reverse setup reverse baksmali (portable upstream download)",
				"Download baksmali and smali jars from Bitbucket and wrap in PATH",
			],
		},
		manualUrl: "https://bitbucket.org/JesusFreke/smali/downloads/",
		manualInstructions: {
			darwin: "Download baksmali.jar from GitHub releases and wrap it in an executable script in /usr/local/bin.",
			linux: "Download baksmali.jar from GitHub releases and wrap it in an executable script in /usr/local/bin.",
			win32: "Download baksmali-2.5.2.jar and smali-2.5.2.jar from https://bitbucket.org/JesusFreke/smali/downloads/ and wrap them in baksmali.bat and smali.bat in PATH.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install smali",
					argv: ["brew", "install", "smali"],
					riskNote: "Installs smali and baksmali via Homebrew. Requires Java runtime.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y smali",
					argv: ["apt", "install", "-y", "smali"],
					riskNote: "Installs smali and baksmali via apt. Requires Java runtime and root/sudo.",
				},
			],
			win32: [
				{
					manager: "portable",
					command: "reverse setup reverse baksmali (portable upstream download)",
					argv: ["reverse", "setup", "reverse", "baksmali", "--execute"],
					riskNote:
						"Downloads portable baksmali and smali JARs from Bitbucket into agent tools directory and generates launcher shims. Requires Java runtime.",
				},
			],
		},
		usage: {
			canonical: "baksmali d classes.dex -o ./out_smali",
			whenToUse:
				"Disassembling DEX files to smali for low-level bytecode inspection, register tracing, and manual instruction patching.",
			prerequisites: ["java"],
			examples: [
				{
					description: "Disassemble classes.dex into smali directory",
					command: "baksmali d classes.dex -o ./smali_out",
				},
			],
		},
	},

	scrcpy: {
		id: "scrcpy",
		name: "scrcpy (Android screen mirroring and control)",
		category: "android",
		description: "Low-latency display and control of physical Android devices over USB or TCP/IP without root",
		optional: true,
		binaries: ["scrcpy"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${LOCALAPPDATA}/Programs/scrcpy", "~/AppData/Local/Programs/scrcpy", "${ProgramFiles}/scrcpy"],
		},
		secondary: ["adb"],
		installHints: {
			darwin: ["brew install scrcpy"],
			linux: ["apt install -y scrcpy"],
			win32: ["winget install Genymobile.scrcpy", "choco install scrcpy"],
		},
		manualUrl: "https://github.com/Genymobile/scrcpy",
		manualInstructions: {
			darwin: "Install via Homebrew with 'brew install scrcpy'.",
			linux: "Install via your package manager ('apt install scrcpy' or 'snap install scrcpy').",
			win32: "Download the release archive from GitHub releases or install via winget/choco.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install scrcpy",
					argv: ["brew", "install", "scrcpy"],
					riskNote: "Installs scrcpy via Homebrew. Requires ADB and platform-tools.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y scrcpy",
					argv: ["apt", "install", "-y", "scrcpy"],
					riskNote: "Installs scrcpy via apt. Requires ADB and root/sudo.",
				},
			],
			win32: [
				{
					manager: "winget",
					command: "winget install -e --id Genymobile.scrcpy",
					argv: ["winget", "install", "-e", "--id", "Genymobile.scrcpy"],
					riskNote: "Installs scrcpy via Windows Package Manager.",
				},
				{
					manager: "choco",
					command: "choco install -y scrcpy",
					argv: ["choco", "install", "-y", "scrcpy"],
					riskNote: "Installs scrcpy via Chocolatey.",
				},
			],
		},
		usage: {
			canonical: "scrcpy --stay-awake --turn-screen-off",
			whenToUse:
				"Observing physical Android device screen, interacting with target application UI, and capturing UI layout during dynamic reverse engineering.",
			prerequisites: ["adb"],
			examples: [
				{
					description: "Launch mirroring with screen kept awake",
					command: "scrcpy -S",
				},
			],
		},
	},

	"hermes-dec": {
		id: "hermes-dec",
		name: "hermes-dec",
		category: "web",
		description: "Disassembler and decompiler for Facebook Hermes JavaScript bytecode",
		optional: true,
		binaries: ["hbc-disassembler", "hbc-decompiler", "hermes-dec"],
		probe: deps => resolveHermesDec(deps)?.path ?? null,
		searchPaths: {
			darwin: ["~/.reverse/agent/tools/hermes-dec/bin", ...UNIX_SEARCH_PATHS],
			linux: ["~/.reverse/agent/tools/hermes-dec/bin", ...UNIX_SEARCH_PATHS],
			win32: [
				"${USERPROFILE}/.reverse/agent/tools/hermes-dec/Scripts",
				"${APPDATA}/Python/Scripts",
				"${LOCALAPPDATA}/Programs/Python/Python312/Scripts",
			],
		},
		installHints: {
			darwin: ["pipx install hermes-dec", "python3 -m pip install hermes-dec"],
			linux: ["pipx install hermes-dec", "python3 -m pip install hermes-dec"],
			win32: ["pipx install hermes-dec", "py -m pip install hermes-dec"],
		},
		manualUrl: "https://github.com/P1sec/hermes-dec",
		manualInstructions: {
			darwin:
				"Install hermes-dec via pipx ('pipx install hermes-dec') or pip ('python3 -m pip install hermes-dec').",
			linux: "Install hermes-dec via pipx ('pipx install hermes-dec') or pip ('python3 -m pip install hermes-dec').",
			win32: "Install hermes-dec via pipx ('pipx install hermes-dec') or pip ('py -m pip install hermes-dec').",
		},
		installCommands: {},
		usage: {
			canonical: "hbc-disassembler <target.hbc> <output_dir>",
			whenToUse: "Disassembling and decompiling Hermes bytecode (HBC) bundles found in React Native apps.",
			prerequisites: ["python3"],
			outputLimits:
				"Direct disassembled output can be large; inspect specific functions or bytecode sections in output_dir.",
			fallback: "strings or file",
			examples: [
				{
					description: "Disassemble React Native index.android.bundle into instruction stream",
					command: "hbc-disassembler index.android.bundle ./artifacts/hermes_out",
				},
			],
		},
	},

	hbctool: {
		id: "hbctool",
		name: "hbctool",
		category: "web",
		description: "Hermes Bytecode disassembler and assembler tool",
		optional: true,
		binaries: ["hbctool"],
		probe: deps => resolveHbctool(deps)?.path ?? null,
		searchPaths: {
			darwin: [
				"~/.reverse/agent/tools/hbctool/bin",
				"~/.reverse/agent/tools/hbctool/.venv/bin",
				...UNIX_SEARCH_PATHS,
			],
			linux: [
				"~/.reverse/agent/tools/hbctool/bin",
				"~/.reverse/agent/tools/hbctool/.venv/bin",
				...UNIX_SEARCH_PATHS,
			],
			win32: ["${USERPROFILE}/.reverse/agent/tools/hbctool/Scripts", "${APPDATA}/Python/Scripts"],
		},
		installHints: {
			darwin: ["pipx install hbctool"],
			linux: ["pipx install hbctool"],
			win32: ["pipx install hbctool"],
		},
		manualUrl: "https://github.com/bongtrop/hbctool",
		manualInstructions: {
			darwin: "Run 'pipx install hbctool' or 'python3 -m pip install --user hbctool'.",
			linux: "Run 'pipx install hbctool' or 'python3 -m pip install --user hbctool'.",
			win32: "Run 'pipx install hbctool' or 'py -m pip install --user hbctool'.",
		},
		installCommands: {
			darwin: [
				{
					manager: "pipx",
					command: "pipx install hbctool",
					argv: ["pipx", "install", "hbctool"],
					riskNote: "Installs hbctool into user Python environment.",
				},
			],
			linux: [
				{
					manager: "pipx",
					command: "pipx install hbctool",
					argv: ["pipx", "install", "hbctool"],
					riskNote: "Installs hbctool into user Python environment.",
				},
			],
			win32: [
				{
					manager: "pipx",
					command: "pipx install hbctool",
					argv: ["pipx", "install", "hbctool"],
					riskNote: "Installs hbctool into user Python environment.",
				},
			],
		},
	},

	il2cppdumper: {
		id: "il2cppdumper",
		name: "Il2CppDumper",
		category: "binary",
		description: "Restore DLL and header files for Unity Il2Cpp binaries",
		optional: true,
		binaries: ["il2cppdumper", "Il2CppDumper", "Il2CppDumper.exe"],
		probe: deps => resolveIl2CppDumper(deps)?.path ?? null,
		searchPaths: {
			darwin: [
				"~/.reverse/agent/tools/il2cppdumper",
				"~/.reverse/agent/tools/il2cppdumper/bin",
				...UNIX_SEARCH_PATHS,
			],
			linux: [
				"~/.reverse/agent/tools/il2cppdumper",
				"~/.reverse/agent/tools/il2cppdumper/bin",
				...UNIX_SEARCH_PATHS,
			],
			win32: [
				"${LOCALAPPDATA}/Programs/Il2CppDumper",
				"~/Il2CppDumper",
				"${USERPROFILE}/.reverse/agent/tools/Il2CppDumper",
				"~/.reverse/agent/tools/Il2CppDumper",
				"${USERPROFILE}/.reverse/agent/tools/il2cppdumper",
				"${USERPROFILE}/.reverse/agent/tools/il2cppdumper/bin",
			],
		},
		installHints: {
			darwin: ["Download release from https://github.com/Perfare/Il2CppDumper/releases"],
			linux: ["Download release from https://github.com/Perfare/Il2CppDumper/releases"],
			win32: [
				"reverse setup reverse il2cppdumper (portable upstream download)",
				"Download GitHub release Il2CppDumper-win-v*.zip",
			],
		},
		manualUrl: "https://github.com/Perfare/Il2CppDumper/releases",
		manualInstructions: {
			darwin: "Download the cross-platform release from GitHub releases and run with dotnet.",
			linux: "Download the release from GitHub releases and run with dotnet.",
			win32: "Download Il2CppDumper-win-v*.zip from GitHub releases and extract into %LOCALAPPDATA%\\Programs\\Il2CppDumper or agent tools directory.",
		},
		installCommands: {
			win32: [
				{
					manager: "portable",
					command: "reverse setup reverse il2cppdumper (portable upstream download)",
					argv: ["reverse", "setup", "reverse", "il2cppdumper", "--execute"],
					riskNote: "Downloads portable Il2CppDumper release from GitHub into agent tools directory.",
				},
			],
		},
	},

	blutter: {
		id: "blutter",
		name: "Blutter (Flutter Android libapp.so AOT Symbol & Class Recovery)",
		category: "decompiler",
		description: "Flutter Android libapp.so AOT reverse engineering and symbol recovery tool",
		optional: true,
		binaries: ["blutter", "blutter.py"],
		probe: deps => resolveBlutter(deps)?.path ?? null,
		searchPaths: {
			darwin: [
				"${HOME}/.reverse/agent/tools/blutter",
				"~/.reverse/agent/tools/blutter",
				"~/.blutter",
				"~/blutter",
				"/usr/local/share/blutter",
				...UNIX_SEARCH_PATHS,
			],
			linux: [
				"${HOME}/.reverse/agent/tools/blutter",
				"~/.reverse/agent/tools/blutter",
				"~/.blutter",
				"~/blutter",
				"/opt/blutter",
				...UNIX_SEARCH_PATHS,
			],
			win32: [
				"${USERPROFILE}/.reverse/agent/tools/blutter",
				"${USERPROFILE}/blutter",
				"C:/blutter",
				"D:/blutter",
				"${ProgramFiles}/blutter",
			],
		},
		secondary: ["python3"],
		installHints: {
			darwin: ["git clone https://github.com/worawit/blutter ~/.reverse/agent/tools/blutter"],
			linux: ["git clone https://github.com/worawit/blutter ~/.reverse/agent/tools/blutter"],
			win32: ["git clone https://github.com/worawit/blutter %USERPROFILE%\\.reverse\\agent\\tools\\blutter"],
		},
		manualUrl: "https://github.com/worawit/blutter",
		manualInstructions: {
			darwin:
				"Clone https://github.com/worawit/blutter into ~/.reverse/agent/tools/blutter, install requirements in a virtual environment ('python3 -m venv venv && ./venv/bin/pip install -r requirements.txt'), and run 'python3 blutter.py <indir> <outdir>'. Requires C++20 compiler, cmake, ninja, pkg-config, libicu, libcapstone.",
			linux: "Clone https://github.com/worawit/blutter into ~/.reverse/agent/tools/blutter, install requirements in a virtual environment ('python3 -m venv venv && ./venv/bin/pip install -r requirements.txt'), and run 'python3 blutter.py <indir> <outdir>'. Requires C++20 compiler, cmake, ninja, pkg-config, libicu, libcapstone.",
			win32: "Clone https://github.com/worawit/blutter into %USERPROFILE%\\.reverse\\agent\\tools\\blutter, install requirements in a virtual environment ('py -m venv venv && .\\venv\\Scripts\\pip install -r requirements.txt'), and run 'python blutter.py <indir> <outdir>'. Requires MSVC C++20, cmake, ninja, git.",
		},
		installCommands: {},
		usage: {
			canonical: "python3 blutter.py <libapp_dir> <output_dir>",
			whenToUse:
				"Recovering Dart classes, method offsets, and symbol names from Flutter Android libapp.so AOT snapshots.",
			prerequisites: ["python3"],
			outputLimits:
				"Disassembled code can be several hundred megabytes; inspect recovered headers or specific class files in output_dir.",
			fallback: "r2_inspect or strings",
			examples: [
				{
					description: "Recover symbols and classes from Flutter libapp.so directory",
					command: "python3 blutter.py ./artifacts/extracted_so/lib/arm64-v8a ./artifacts/blutter_out",
				},
			],
		},
	},

	"wasm-tools": {
		id: "wasm-tools",
		name: "wasm-tools",
		category: "web",
		description: "CLI suite for validating, manipulating, inspecting, and converting WebAssembly binaries",
		optional: true,
		binaries: ["wasm-tools"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["~/.cargo/bin", "${LOCALAPPDATA}/Programs/wasm-tools"],
		},
		installHints: {
			darwin: ["brew install wasm-tools or cargo install wasm-tools"],
			linux: ["cargo install wasm-tools or brew install wasm-tools"],
			win32: ["winget install BytecodeAlliance.wasm-tools or cargo install wasm-tools"],
		},
		manualUrl: "https://github.com/bytecodealliance/wasm-tools/releases",
		manualInstructions: {
			darwin: "Install via 'brew install wasm-tools' or 'cargo install wasm-tools'.",
			linux: "Install via 'cargo install wasm-tools' or download release binary from GitHub.",
			win32: "Install via 'winget install -e --id BytecodeAlliance.wasm-tools' or 'cargo install wasm-tools'.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install wasm-tools",
					argv: ["brew", "install", "wasm-tools"],
					riskNote: "Installs prebuilt wasm-tools binary via Homebrew.",
				},
				{
					manager: "cargo",
					command: "cargo install wasm-tools",
					argv: ["cargo", "install", "wasm-tools"],
					riskNote: "Compiles wasm-tools from crates.io via Cargo.",
				},
			],
			linux: [
				{
					manager: "cargo",
					command: "cargo install wasm-tools",
					argv: ["cargo", "install", "wasm-tools"],
					riskNote: "Compiles wasm-tools from crates.io via Cargo.",
				},
				{
					manager: "brew",
					command: "brew install wasm-tools",
					argv: ["brew", "install", "wasm-tools"],
					riskNote: "Installs wasm-tools via Linuxbrew.",
				},
			],
			win32: [
				{
					manager: "winget",
					command: "winget install -e --id BytecodeAlliance.wasm-tools",
					argv: ["winget", "install", "-e", "--id", "BytecodeAlliance.wasm-tools"],
					riskNote: "Installs wasm-tools via Windows Package Manager.",
				},
				{
					manager: "cargo",
					command: "cargo install wasm-tools",
					argv: ["cargo", "install", "wasm-tools"],
					riskNote: "Compiles wasm-tools via Cargo.",
				},
			],
		},
	},

	readelf: {
		id: "readelf",
		name: "readelf",
		category: "binary",
		description: "Display information about ELF object files, section headers, and symbols",
		optional: true,
		binaries: ["readelf", "greadelf", "llvm-readelf"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${ProgramFiles}/Git/usr/bin", "C:/msys64/usr/bin", "${LOCALAPPDATA}/Programs/binutils/bin"],
		},
		installHints: {
			darwin: ["brew install binutils"],
			linux: ["apt install binutils"],
			win32: ["choco install binutils"],
		},
		manualUrl: "https://sourceware.org/binutils/docs/binutils/readelf.html",
		manualInstructions: {
			darwin: "Install GNU binutils via 'brew install binutils' (provides greadelf).",
			linux: "Install binutils via system package manager (e.g. sudo apt install binutils).",
			win32: "Install binutils via Chocolatey or MSYS2.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install binutils",
					argv: ["brew", "install", "binutils"],
					riskNote: "Installs GNU binutils via Homebrew (provides greadelf).",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y binutils",
					argv: ["apt", "install", "-y", "binutils"],
					riskNote: "Installs binutils package via apt. May require root/sudo.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y binutils",
					argv: ["choco", "install", "-y", "binutils"],
					riskNote: "Installs binutils via Chocolatey.",
				},
			],
		},
		usage: {
			canonical: "crashdump_inspect(action: 'info', path: 'core.dump')",
			whenToUse:
				"Use native crashdump_inspect for zero-prep offline analysis of core dumps (threads, registers, memory mappings, exception codes); use readelf -n to inspect raw ELF note segments.",
			examples: [
				{
					command: "readelf -n core.dump",
					description: "Display ELF core dump note segments (NT_PRSTATUS, NT_PRPSINFO, NT_FILE)",
				},
			],
		},
	},

	binwalk: {
		id: "binwalk",
		name: "Binwalk",
		category: "binary",
		description: "Firmware analysis and extraction tool",
		optional: true,
		binaries: ["binwalk"],
		searchPaths: {
			darwin: ["~/.cargo/bin", ...UNIX_SEARCH_PATHS],
			linux: ["~/.cargo/bin", ...UNIX_SEARCH_PATHS],
			win32: ["~/.cargo/bin", "${USERPROFILE}/.cargo/bin", "${LOCALAPPDATA}/Programs/binwalk", "C:/binwalk"],
		},
		installHints: {
			darwin: ["brew install binwalk", "cargo install binwalk"],
			linux: ["apt install binwalk", "cargo install binwalk"],
			win32: ["cargo install binwalk"],
		},
		manualUrl: "https://github.com/ReFirmLabs/binwalk",
		manualInstructions: {
			darwin: "Install via Homebrew: brew install binwalk or cargo: cargo install binwalk.",
			linux: "Install via system package manager (e.g. sudo apt install binwalk) or cargo: cargo install binwalk.",
			win32: "Install via Cargo (Rust rewrite v3.x): cargo install binwalk.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install binwalk",
					argv: ["brew", "install", "binwalk"],
					riskNote: "Installs binwalk via Homebrew.",
				},
				{
					manager: "cargo",
					command: "cargo install binwalk",
					argv: ["cargo", "install", "binwalk"],
					riskNote: "Installs binwalk (v3.x Rust rewrite) via Cargo.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y binwalk",
					argv: ["apt", "install", "-y", "binwalk"],
					riskNote: "Installs binwalk package via apt. May require root/sudo.",
				},
				{
					manager: "cargo",
					command: "cargo install binwalk",
					argv: ["cargo", "install", "binwalk"],
					riskNote: "Installs binwalk (v3.x Rust rewrite) via Cargo.",
				},
			],
			win32: [
				{
					manager: "cargo",
					command: "cargo install binwalk",
					argv: ["cargo", "install", "binwalk"],
					riskNote: "Installs binwalk (v3.x Rust rewrite) via Cargo.",
				},
			],
		},
		usage: {
			canonical: "firmware_inspect(action: 'info', path: 'firmware.bin')",
			whenToUse:
				"Use native firmware_inspect for offline zero-prep container, partition, entropy, and archive analysis; use binwalk CLI for deep multi-stage signature extraction or external carvers.",
			examples: [
				{
					command: "binwalk -B firmware.bin",
					description: "Scan firmware image for known file signatures",
				},
			],
		},
	},
	vbindiff: {
		id: "vbindiff",
		name: "VBinDiff",
		category: "binary",
		description: "Visual binary diffing tool for displaying files in hex and ASCII",
		optional: true,
		binaries: ["vbindiff"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: [
				"${LOCALAPPDATA}/Programs/vbindiff",
				"C:/vbindiff",
				"~/vbindiff",
				"${USERPROFILE}/.reverse/agent/tools/vbindiff",
				"~/.reverse/agent/tools/vbindiff",
			],
		},
		installHints: {
			darwin: ["brew install vbindiff"],
			linux: ["apt install vbindiff"],
			win32: [
				"reverse setup reverse vbindiff (portable upstream download)",
				"Download VBinDiff from https://www.cjmweb.net/vbindiff/",
			],
		},
		manualUrl: "https://www.cjmweb.net/vbindiff/",
		manualInstructions: {
			darwin: "Install via Homebrew: brew install vbindiff.",
			linux: "Install via package manager: apt install vbindiff.",
			win32: "Download VBinDiff-3.0_beta5.zip from https://www.cjmweb.net/vbindiff/ and extract vbindiff.exe into PATH.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install vbindiff",
					argv: ["brew", "install", "vbindiff"],
					riskNote: "Installs vbindiff via Homebrew.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y vbindiff",
					argv: ["apt", "install", "-y", "vbindiff"],
					riskNote: "Installs vbindiff via apt. May require root/sudo.",
				},
			],
			win32: [
				{
					manager: "portable",
					command: "reverse setup reverse vbindiff (portable upstream download)",
					argv: ["reverse", "setup", "reverse", "vbindiff", "--execute"],
					riskNote: "Downloads portable VBinDiff from cjmweb.net into agent tools directory.",
				},
			],
		},
		usage: {
			canonical: "binary_diff(path_a: 'v1.bin', path_b: 'v2.bin')",
			whenToUse:
				"Use native binary_diff for offline deterministic hashes, similarity score, and block/byte diffs; use vbindiff CLI for visual interactive side-by-side terminal hex inspection.",
			examples: [
				{
					command: "vbindiff fileA.bin fileB.bin",
					description: "Visual side-by-side binary comparison",
				},
			],
		},
	},

	cargo_auditable: {
		id: "cargo_auditable",
		name: "Cargo Auditable",
		category: "binary",
		description: "Embed and inspect dependency trees in compiled Rust binaries",
		optional: true,
		binaries: ["cargo-auditable"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${USERPROFILE}/.cargo/bin"],
		},
		installHints: {
			darwin: ["cargo install cargo-auditable"],
			linux: ["cargo install cargo-auditable"],
			win32: ["cargo install cargo-auditable"],
		},
		manualUrl: "https://github.com/rust-secure-code/cargo-auditable",
		manualInstructions: {
			darwin: "Install via cargo: cargo install cargo-auditable.",
			linux: "Install via cargo: cargo install cargo-auditable.",
			win32: "Install via cargo: cargo install cargo-auditable.",
		},
		installCommands: {
			darwin: [
				{
					manager: "cargo",
					command: "cargo install cargo-auditable",
					argv: ["cargo", "install", "cargo-auditable"],
					riskNote: "Compiles and installs cargo-auditable binary.",
				},
			],
			linux: [
				{
					manager: "cargo",
					command: "cargo install cargo-auditable",
					argv: ["cargo", "install", "cargo-auditable"],
					riskNote: "Compiles and installs cargo-auditable binary.",
				},
			],
			win32: [
				{
					manager: "cargo",
					command: "cargo install cargo-auditable",
					argv: ["cargo", "install", "cargo-auditable"],
					riskNote: "Compiles and installs cargo-auditable binary.",
				},
			],
		},
		usage: {
			canonical: "binary_metadata_inspect(action: 'rust', path: 'target_binary')",
			whenToUse:
				"Use native binary_metadata_inspect for offline Go/Rust metadata and dependency audit parsing; use cargo-auditable CLI when compiling Rust binaries with auditable metadata.",
			examples: [
				{
					command: "cargo auditable build --release",
					description: "Compile Rust crate embedding dependency tree in .dep-v0 section",
				},
			],
		},
	},

	cast: {
		id: "cast",
		name: "Foundry Cast",
		category: "binary",
		description: "CLI tool for Ethereum RPC queries, calldata encoding, and bytecode inspection",
		optional: true,
		binaries: ["cast", "chisel"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${USERPROFILE}/.foundry/bin"],
		},
		installHints: {
			darwin: ["curl -L https://foundry.paradigm.xyz | bash && foundryup"],
			linux: ["curl -L https://foundry.paradigm.xyz | bash && foundryup"],
			win32: ["curl -L https://foundry.paradigm.xyz | bash && foundryup"],
		},
		manualUrl: "https://book.getfoundry.sh/",
		manualInstructions: {
			darwin: "Install via Foundry installer script or brew.",
			linux: "Install via Foundry installer script: curl -L https://foundry.paradigm.xyz | bash && foundryup.",
			win32: "Install via Foundryup or cargo install --locked foundry-cli.",
		},
		installCommands: {},
		usage: {
			canonical: "evm_inspect(action: 'info', code: '0x...')",
			whenToUse:
				"Use native evm_inspect for offline zero-prep EVM bytecode disassembly and function selector extraction; use cast CLI for on-chain contract state retrieval or ABI signature encoding.",
			examples: [
				{
					command: "cast disasm 0x6080604052348015...",
					description: "Disassemble EVM hex string with Foundry Cast",
				},
			],
		},
	},

	mitmproxy: {
		id: "mitmproxy",
		name: "mitmproxy",
		category: "network",
		description: "Interactive TLS-capable intercepting HTTP proxy for reverse engineering network traffic",
		optional: true,
		binaries: ["mitmproxy", "mitmdump", "mitmweb"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${APPDATA}/Python/Scripts", "${ProgramFiles}/mitmproxy/bin"],
		},
		installHints: {
			darwin: ["brew install mitmproxy or pipx install mitmproxy"],
			linux: ["apt install mitmproxy or pipx install mitmproxy"],
			win32: ["choco install mitmproxy or pipx install mitmproxy"],
		},
		manualUrl: "https://mitmproxy.org/",
		manualInstructions: {
			darwin: "Install via 'brew install mitmproxy' or 'pipx install mitmproxy'.",
			linux: "Install via 'apt install mitmproxy' or 'pipx install mitmproxy'.",
			win32: "Install via 'choco install mitmproxy' or download Windows installer from https://mitmproxy.org.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install mitmproxy",
					argv: ["brew", "install", "mitmproxy"],
					riskNote: "Installs mitmproxy suite via Homebrew.",
				},
				{
					manager: "pipx",
					command: "pipx install mitmproxy",
					argv: ["pipx", "install", "mitmproxy"],
					riskNote: "Installs mitmproxy into user Python environment via pipx.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y mitmproxy",
					argv: ["apt", "install", "-y", "mitmproxy"],
					riskNote: "Installs mitmproxy via apt. May require root/sudo.",
				},
				{
					manager: "pipx",
					command: "pipx install mitmproxy",
					argv: ["pipx", "install", "mitmproxy"],
					riskNote: "Installs mitmproxy via pipx.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y mitmproxy",
					argv: ["choco", "install", "-y", "mitmproxy"],
					riskNote: "Installs mitmproxy via Chocolatey.",
				},
				{
					manager: "pipx",
					command: "pipx install mitmproxy",
					argv: ["pipx", "install", "mitmproxy"],
					riskNote: "Installs mitmproxy into user environment via pipx.",
				},
			],
		},
		usage: {
			canonical: "mitmdump -p 8080 -w flows.mitm",
			whenToUse:
				"Capture and replay authorized HTTP(S) traffic to recover API schemas, signatures, and TLS pinning behavior; use mitmproxy interactively for breakpoints.",
			prerequisites: ["mitmproxy"],
			outputLimits:
				"Write flows to disk; filter with --flow-filter or scripts instead of printing every request into context.",
			fallback: "curl/fetch against authorized endpoints plus HAR or browser DevTools captures.",
			examples: [
				{
					description: "Capture all traffic to a flow file behind a local listener",
					command: "mitmdump -p 8080 -w ./artifacts/flows.mitm",
				},
				{
					description: "Show only requests to one host",
					command: "mitmdump -p 8080 --flow-filter '~d api.example.com'",
				},
			],
		},
	},

	tshark: {
		id: "tshark",
		name: "tshark",
		category: "network",
		description: "Terminal network packet analyzer and capture utility",
		optional: true,
		binaries: ["tshark"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${ProgramFiles}/Wireshark", "${ProgramFiles(x86)}/Wireshark"],
		},
		installHints: {
			darwin: ["brew install wireshark"],
			linux: ["apt install tshark"],
			win32: ["choco install wireshark"],
		},
		manualUrl: "https://www.wireshark.org/",
		manualInstructions: {
			darwin: "Install via 'brew install wireshark' or download Wireshark installer from https://www.wireshark.org.",
			linux: "Install via 'apt install tshark' (sudo dpkg-reconfigure wireshark-common to configure capture permissions).",
			win32: "Install via 'choco install wireshark' or download installer from https://www.wireshark.org.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install wireshark",
					argv: ["brew", "install", "wireshark"],
					riskNote: "Installs Wireshark CLI suite (including tshark) via Homebrew.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y tshark",
					argv: ["apt", "install", "-y", "tshark"],
					riskNote: "Installs tshark via apt. May prompt for non-superuser packet capture permissions.",
				},
			],
			win32: [
				{
					manager: "choco",
					command: "choco install -y wireshark",
					argv: ["choco", "install", "-y", "wireshark"],
					riskNote: "Installs Wireshark and WinPcap/Npcap via Chocolatey.",
				},
			],
		},
		usage: {
			canonical: "pcap_inspect(action: 'info', path: 'capture.pcap')",
			whenToUse:
				"Use native pcap_inspect for offline zero-prep analysis of PCAP/PCAPNG packets, endpoints, and DNS; use tshark for live capture, deep custom dissectors, or protocol extraction.",
			examples: [
				{
					command: "tshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri",
					description: "Filter HTTP requests and extract host and URI fields",
				},
			],
		},
	},

	sqlite3: {
		id: "sqlite3",
		name: "sqlite3 CLI",
		category: "general",
		description: "Command-line interface for SQLite databases with read-only inspection and querying",
		optional: true,
		binaries: ["sqlite3"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${ProgramFiles}/sqlite", "${LOCALAPPDATA}/Programs/sqlite"],
		},
		installHints: {
			darwin: ["brew install sqlite"],
			linux: ["apt install sqlite3"],
			win32: ["winget install SQLite.SQLite", "choco install sqlite"],
		},
		manualUrl: "https://www.sqlite.org/",
		manualInstructions: {
			darwin:
				"Install via 'brew install sqlite' or download precompiled binaries from https://www.sqlite.org/download.html.",
			linux: "Install via 'apt install sqlite3' or your distribution's package manager.",
			win32: "Install via 'winget install SQLite.SQLite' or download sqlite-tools from https://www.sqlite.org/download.html.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install sqlite",
					argv: ["brew", "install", "sqlite"],
					riskNote: "Installs SQLite CLI suite via Homebrew.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y sqlite3",
					argv: ["apt", "install", "-y", "sqlite3"],
					riskNote: "Installs sqlite3 CLI via apt.",
				},
			],
			win32: [
				{
					manager: "winget",
					command: "winget install -e --id SQLite.SQLite",
					argv: ["winget", "install", "-e", "--id", "SQLite.SQLite"],
					riskNote: "Installs SQLite via winget.",
				},
			],
		},
		usage: {
			canonical: "sqlite_inspect(action: 'info', path: 'database.db')",
			whenToUse:
				"Use native sqlite_inspect for safe, bounded, read-only analysis of schema, tables, indexes, rows, and WAL metadata; use sqlite3 CLI for manual query execution.",
			examples: [
				{
					command: "sqlite3 -readonly database.db '.schema'",
					description: "Inspect schema with sqlite3 CLI in read-only mode",
				},
			],
		},
	},

	node: {
		id: "node",
		name: "Node.js",
		category: "general",
		description: "JavaScript runtime and npm/npx launcher used by browser and web-analysis helper services",
		optional: true,
		binaries: ["node"],
		secondary: ["npx"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${ProgramFiles}/nodejs", "${APPDATA}/npm"],
		},
		installHints: {
			darwin: ["brew install node"],
			linux: ["apt install nodejs npm"],
			win32: ["winget install OpenJS.NodeJS.LTS"],
		},
		manualUrl: "https://nodejs.org/en/download",
		manualInstructions: {
			darwin: "Install the current LTS release from nodejs.org or run 'brew install node'.",
			linux: "Install Node.js LTS from your distribution (nodejs + npm) or nodejs.org.",
			win32: "Install the LTS Windows installer from nodejs.org or run 'winget install OpenJS.NodeJS.LTS'.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install node",
					argv: ["brew", "install", "node"],
					riskNote: "Installs Node.js and npm/npx via Homebrew.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y nodejs npm",
					argv: ["apt", "install", "-y", "nodejs", "npm"],
					riskNote: "Installs the distribution Node.js and npm packages. May require root/sudo.",
				},
			],
			win32: [
				{
					manager: "winget",
					command: "winget install -e --id OpenJS.NodeJS.LTS",
					argv: ["winget", "install", "-e", "--id", "OpenJS.NodeJS.LTS"],
					riskNote: "Installs the Node.js LTS package via winget.",
				},
			],
		},
	},

	java: {
		id: "java",
		name: "Java Runtime Environment (JRE/JDK)",
		category: "system",
		systemTool: true,
		description: "Java runtime environment required to run Android reverse-engineering tools (JADX, Apktool, Unidbg)",
		optional: true,
		binaries: ["java"],
		envPaths: [{ env: "JAVA_HOME", suffix: "/bin" }, { env: "JAVA_HOME" }],
		searchPaths: {
			darwin: [
				"/opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home/bin",
				"/opt/homebrew/opt/openjdk*/bin",
				"/usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home/bin",
				"/usr/local/opt/openjdk*/bin",
				"/Library/Java/JavaVirtualMachines/*/Contents/Home/bin",
				...UNIX_SEARCH_PATHS,
			],
			linux: ["/usr/lib/jvm/*/bin", "/usr/lib/jvm/*", "/etc/alternatives", ...UNIX_SEARCH_PATHS],
			win32: [
				"${ProgramFiles}/Java/*/bin",
				"${ProgramFiles}/Eclipse Adoptium/*/bin",
				"${ProgramFiles}/Microsoft/*/bin",
			],
		},
		installHints: {
			darwin: ["brew install openjdk"],
			linux: ["apt install -y default-jre"],
			win32: ["winget install Microsoft.OpenJDK.17", "choco install openjdk"],
		},
		manualUrl: "https://www.oracle.com/java/technologies/downloads/",
		manualInstructions: {
			darwin: "Install OpenJDK via Homebrew ('brew install openjdk') or download from Adoptium / Oracle.",
			linux: "Install default-jre via apt ('apt install default-jre') or package manager.",
			win32: "Install OpenJDK via winget ('winget install Microsoft.OpenJDK.17') or download installer.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install openjdk",
					argv: ["brew", "install", "openjdk"],
					riskNote: "Installs OpenJDK via Homebrew.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y default-jre",
					argv: ["apt", "install", "-y", "default-jre"],
					riskNote: "Installs default-jre via apt. Requires root/sudo.",
				},
			],
			win32: [
				{
					manager: "winget",
					command: "winget install -e --id Microsoft.OpenJDK.17",
					argv: ["winget", "install", "-e", "--id", "Microsoft.OpenJDK.17"],
					riskNote: "Installs Microsoft OpenJDK via winget.",
				},
				{
					manager: "choco",
					command: "choco install -y openjdk",
					argv: ["choco", "install", "-y", "openjdk"],
					riskNote: "Installs OpenJDK via Chocolatey.",
				},
			],
		},
	},

	jdk8: {
		id: "jdk8",
		name: "Java Development Kit 8 (JDK 8 / 1.8)",
		category: "system",
		systemTool: true,
		description: "Strict JDK 8 environment required by Unidbg native emulation (incompatible with JDK 9+)",
		optional: true,
		binaries: [],
		probe: deps => {
			const res = validateJdk8(deps?.env?.JAVA_HOME, deps?.env);
			if (res.valid) {
				return res.javaHome ?? res.javaBin ?? "jdk8";
			}
			return null;
		},
		installHints: {
			darwin: ["brew install --cask temurin@8"],
			linux: ["apt install -y openjdk-8-jdk"],
			win32: ["winget install EclipseAdoptium.Temurin.8.JDK", "choco install openjdk8"],
		},
		manualUrl: "https://adoptium.net/temurin/releases/?version=8",
		manualInstructions: {
			darwin: "Install Eclipse Adoptium Temurin 8 ('brew install --cask temurin@8') and set JAVA_HOME.",
			linux: "Install OpenJDK 8 ('apt install openjdk-8-jdk') and set JAVA_HOME to /usr/lib/jvm/java-8-openjdk.",
			win32: "Install Eclipse Adoptium Temurin 8 ('winget install EclipseAdoptium.Temurin.8.JDK') and set JAVA_HOME.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install --cask temurin@8",
					argv: ["brew", "install", "--cask", "temurin@8"],
					riskNote: "Installs Eclipse Adoptium Temurin JDK 8 via Homebrew Cask.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y openjdk-8-jdk",
					argv: ["apt", "install", "-y", "openjdk-8-jdk"],
					riskNote: "Installs OpenJDK 8 via apt. Requires root/sudo.",
				},
			],
			win32: [
				{
					manager: "winget",
					command: "winget install -e --id EclipseAdoptium.Temurin.8.JDK",
					argv: ["winget", "install", "-e", "--id", "EclipseAdoptium.Temurin.8.JDK"],
					riskNote: "Installs Eclipse Adoptium Temurin JDK 8 via winget.",
				},
				{
					manager: "choco",
					command: "choco install -y openjdk8",
					argv: ["choco", "install", "-y", "openjdk8"],
					riskNote: "Installs OpenJDK 8 via Chocolatey.",
				},
			],
		},
	},

	python: {
		id: "python",
		name: "Python 3 Runtime",
		category: "system",
		systemTool: true,
		description: "Python 3.9+ runtime used by reverse engineering analysis workers and DEX/APK tool pipelines",
		optional: true,
		binaries: ["python3", "python"],
		probe: deps => probePythonTool(deps),
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${LOCALAPPDATA}/Programs/Python/Python3*", "${ProgramFiles}/Python3*", "${SystemDrive}/Python3*"],
		},
		installHints: {
			darwin: ["brew install python3"],
			linux: ["apt install -y python3"],
			win32: ["winget install Python.Python.3.12"],
		},
		manualUrl: "https://www.python.org/downloads/",
		manualInstructions: {
			darwin: "Install Python 3 via Homebrew ('brew install python3') or download from python.org.",
			linux: "Install Python 3 via your package manager ('apt install python3' or 'dnf install python3').",
			win32: "Install Python 3 via winget ('winget install Python.Python.3.12') or download from python.org.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install python3",
					argv: ["brew", "install", "python3"],
					riskNote: "Installs Python 3 via Homebrew.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y python3",
					argv: ["apt", "install", "-y", "python3"],
					riskNote: "Installs python3 via apt. Requires root/sudo.",
				},
			],
			win32: [
				{
					manager: "winget",
					command: "winget install -e --id Python.Python.3.12",
					argv: ["winget", "install", "-e", "--id", "Python.Python.3.12"],
					riskNote: "Installs Python 3.12 via winget.",
				},
			],
		},
		usage: {
			canonical: "python3 -c 'import sys; print(sys.version)'",
			whenToUse:
				"Executing Python-based reverse engineering analysis workers and DEX/APK bytecode processing pipelines.",
			fallback: "Native dexdump, droidasc, or smali disassembly through apktool.",
			examples: [
				{
					description: "Check Python interpreter version",
					command: "python3 --version",
				},
			],
		},
	},

	triton: {
		id: "triton",
		name: "Triton Binary Analysis",
		category: "binary",
		description:
			"Dynamic symbolic execution, taint analysis, expression synthesis and optional LLVM lifting using triton-library.",
		optional: true,
		binaries: [],
		probe: deps => resolveVmpTool("triton", deps),
		installHints: {
			darwin: ["reverse setup reverse triton --execute"],
			linux: ["reverse setup reverse triton --execute"],
			win32: ["reverse setup reverse triton --execute"],
		},
		manualUrl: "https://github.com/JonathanSalwan/Triton",
		manualInstructions: {
			darwin:
				"Use the managed installer to provision triton-library in an isolated Python environment. LLVM support is probed separately.",
			linux: "Use the managed installer to provision triton-library in an isolated Python environment. LLVM support is probed separately.",
			win32: "Use the managed installer to provision triton-library in an isolated Python environment. LLVM support is probed separately.",
		},
		usage: {
			canonical: 'triton_analyze(action: "status") -> triton_analyze(action: "replay", ...)',
			whenToUse:
				"Recover input/output expressions from captured instruction traces, simplify MBA expressions, and inspect path predicates without executing the target on the host.",
			outputLimits:
				"Declare input and output registers or memory explicitly; bound replay instructions and keep full expressions and LLVM IR in artifacts. Recovery covers supplied paths only.",
			fallback:
				"Inspect the original trace with native debuggers or disassemblers; preserve unresolved expressions and state gaps as evidence.",
			examples: [
				{
					description: "Inspect binary-analysis Triton and optional features",
					command: 'triton_analyze(action: "status")',
				},
			],
		},
	},
	vmpdump: {
		id: "vmpdump",
		name: "VMPDump",
		category: "binary",
		description:
			"Windows x64 VMProtect process dumping and import-table repair after unpacking has reached the original entry point.",
		optional: true,
		binaries: [],
		probe: deps => resolveVmpTool("vmpdump", deps),
		installHints: {
			darwin: ["Run reverse setup reverse vmpdump --execute on a Windows x64 host"],
			linux: ["Run reverse setup reverse vmpdump --execute on a Windows x64 host"],
			win32: ["reverse setup reverse vmpdump --execute"],
		},
		manualUrl: "https://github.com/0xnobody/vmpdump/releases/tag/v1.2",
		manualInstructions: {
			darwin:
				"VMPDump requires a Windows process. Transfer the sample and use the confirmed installation panel on that Windows host.",
			linux: "VMPDump requires a Windows process. Transfer the sample and use the confirmed installation panel on that Windows host.",
			win32: "Install the pinned upstream VMPDump release through the reverse tools panel; operate on an explicitly approved process after observing OEP.",
		},
		usage: {
			canonical: 'vmp_dump(action: "status") -> vmp_dump(action: "dump", ...)',
			whenToUse:
				"Preserve an unpacked VMProtect 3.x x64 module and rebuild its import calls/table from an already running Windows process.",
			outputLimits:
				"Record PID, module identity, image base and observed OEP; retain the generated dump as an artifact. Dumping does not recover virtualized function semantics.",
			fallback:
				"Collect an approved debugger memory dump and preserve unresolved import evidence for manual repair.",
			examples: [
				{ description: "Check host support and VMPDump availability", command: 'vmp_dump(action: "status")' },
			],
		},
	},
	mergen: {
		id: "mergen",
		name: "Mergen",
		category: "binary",
		description:
			"Function-level x64 PE lifting to LLVM IR for deobfuscation and devirtualization; self-modifying code is unsupported.",
		optional: true,
		binaries: [],
		probe: deps => resolveVmpTool("mergen", deps),
		installHints: {
			darwin: ["Build the upstream native lifter or install the pinned release on Windows x64"],
			linux: ["Build the upstream native lifter or install the pinned release on Windows x64"],
			win32: ["reverse setup reverse mergen --execute"],
		},
		manualUrl: "https://github.com/NaC-L/Mergen",
		manualInstructions: {
			darwin:
				"The managed prebuilt release is Windows x64. Build an upstream native lifter and configure its path, or analyze on a Windows host.",
			linux: "The managed prebuilt release is Windows x64. Build an upstream native lifter and configure its path, or analyze on a Windows host.",
			win32: "Install the pinned upstream Mergen lifter through the reverse tools panel. Supply an x64 PE and a function virtual address.",
		},
		usage: {
			canonical:
				'native_devirtualize(action: "status", backend: "mergen") -> native_devirtualize(action: "lift", backend: "mergen", ...)',
			whenToUse:
				"Lift a selected x64 PE function to LLVM IR for semantic analysis. VMP 3.8.x has targeted upstream coverage; VMP 3.6 is best-effort.",
			outputLimits:
				"Select one function and bounded execution. Preserve the original PE, produced IR and diagnostics; verify behavior independently before replacing code.",
			fallback:
				"Use Triton on captured paths for self-modifying code or unsupported static lifting, or inspect the function in Ghidra/IDA.",
			examples: [
				{
					description: "Inspect Mergen backend availability",
					command: 'native_devirtualize(action: "status", backend: "mergen")',
				},
			],
		},
	},
	novmp: {
		id: "novmp",
		name: "NoVmp",
		category: "binary",
		description: "Experimental static devirtualization of unpacked VMProtect 3.0–3.5 x64 routines into VTIL.",
		optional: true,
		binaries: [],
		probe: deps => resolveVmpTool("novmp", deps),
		installHints: {
			darwin: ["Build the upstream x86-64 tool or install the pinned release on Windows x64"],
			linux: ["Build the upstream x86-64 tool or install the pinned release on Windows x64"],
			win32: ["reverse setup reverse novmp --execute"],
		},
		manualUrl: "https://github.com/can1357/NoVmp",
		manualInstructions: {
			darwin:
				"The managed prebuilt release is Windows x64. Upstream source uses x86-64 intrinsics; use a compatible build environment or Windows host.",
			linux: "The managed prebuilt release is Windows x64. Build upstream with its pinned VTIL submodule in an x86-64 environment, or use Windows.",
			win32: "Install the pinned upstream NoVmp release through the reverse tools panel; provide an unpacked PE, VM-entry RVAs and original image base when needed.",
		},
		usage: {
			canonical:
				'native_devirtualize(action: "status", backend: "novmp") -> native_devirtualize(action: "lift", backend: "novmp", ...)',
			whenToUse:
				"Analyze unpacked older VMProtect 3.0–3.5 x64 functions with known VM-entry RVAs, producing VTIL for inspection.",
			outputLimits:
				"Limit selected VM entries and keep full VTIL in artifacts. Original input stays unchanged; experimental recompilation requires separate explicit intent.",
			fallback: "Use Mergen for compatible function lifting or Triton for captured-path semantic recovery.",
			examples: [
				{
					description: "Inspect legacy backend availability",
					command: 'native_devirtualize(action: "status", backend: "novmp")',
				},
			],
		},
	},

	ida: {
		id: "ida",
		name: "IDA Pro",
		category: "decompiler",
		description: "Interactive Disassembler and decompiler with idalib integration",
		optional: true,
		binaries: ["ida", "ida64", "idat", "idat64"],
		probe: deps => probeIdaRequirement(deps),
		envPaths: [{ env: "IDADIR" }],
		searchPaths: {
			darwin: ["/Applications/IDA*/Contents/MacOS", "~/Applications/IDA*/Contents/MacOS", ...UNIX_SEARCH_PATHS],
			linux: ["~/ida*", "/opt/ida*", ...UNIX_SEARCH_PATHS],
			win32: [
				"${IDADIR}",
				"${ProgramFiles}/IDA*",
				"C:/Program Files/IDA*",
				"D:/Program Files/IDA*",
				"${LOCALAPPDATA}/Programs/IDA*",
				"${USERPROFILE}/.local/bin",
			],
		},
		installHints: {
			darwin: ["Install IDA Pro with idalib, then set ida.installDir or IDADIR"],
			linux: ["Install IDA Pro with idalib, then set ida.installDir or IDADIR"],
			win32: ["Install IDA Pro with idalib, then set ida.installDir or IDADIR"],
		},
		manualUrl: "https://hex-rays.com/ida-pro/",
		manualInstructions: {
			darwin:
				"Commercial software. Install IDA Pro with idalib, then configure ida.installDir in settings or export IDADIR.",
			linux: "Commercial software. Install IDA Pro with idalib, then configure ida.installDir in settings or export IDADIR.",
			win32: "Commercial software. Install IDA Pro with idalib, then configure ida.installDir in settings or export IDADIR.",
		},
		installCommands: {},
	},
	lief: {
		id: "lief",
		name: "LIEF (Library to Instrument Executable Formats)",
		category: "binary",
		description: "Deep ELF header, segment, section, dynamic entry, relocation and constructor analysis library.",
		optional: true,
		binaries: [],
		secondary: ["python"],
		probe: deps => probeLiefRequirement(deps),
		installHints: {
			darwin: ["reverse setup reverse lief --execute", "pip install lief==1.0.0"],
			linux: ["reverse setup reverse lief --execute", "pip install lief==1.0.0"],
			win32: ["reverse setup reverse lief --execute", "py -m pip install lief==1.0.0"],
		},
		manualUrl: "https://lief.re/",
		manualInstructions: {
			darwin:
				"Install pinned lief (1.0.0) into an isolated virtual environment via 'reverse setup reverse lief --execute' or 'python3 -m pip install lief==1.0.0'.",
			linux: "Install pinned lief (1.0.0) into an isolated virtual environment via 'reverse setup reverse lief --execute' or 'python3 -m pip install lief==1.0.0'.",
			win32: "Install pinned lief (1.0.0) into an isolated virtual environment via 'reverse setup reverse lief --execute' or 'py -m pip install lief==1.0.0'.",
		},
		installCommands: {
			darwin: [
				{
					manager: "pip",
					command: "reverse setup reverse lief (managed venv)",
					argv: ["reverse", "setup", "reverse", "lief", "--execute"],
					riskNote:
						"Provisions an isolated virtual environment in the agent directory and installs pinned lief (1.0.0, Apache-2.0).",
				},
			],
			linux: [
				{
					manager: "pip",
					command: "reverse setup reverse lief (managed venv)",
					argv: ["reverse", "setup", "reverse", "lief", "--execute"],
					riskNote:
						"Provisions an isolated virtual environment in the agent directory and installs pinned lief (1.0.0, Apache-2.0).",
				},
			],
			win32: [
				{
					manager: "pip",
					command: "reverse setup reverse lief (managed venv)",
					argv: ["reverse", "setup", "reverse", "lief", "--execute"],
					riskNote:
						"Provisions an isolated virtual environment in the agent directory and installs pinned lief (1.0.0, Apache-2.0).",
				},
			],
		},
		usage: {
			canonical:
				'elf_inspect(action: "query", path: "<lib.so>", query_type: "all") -> elf_inspect(action: "query", path: "<lib.so>", query_type: "constructors")',
			whenToUse:
				"Deep structural analysis of ELF binaries, dynamic tags, relocations, address-to-file offsets, and .init_array / .fini_array constructors without running the target.",
			prerequisites: ["python", "lief"],
			outputLimits:
				"Filter large section listings and symbol tables; extract only queried relocations, segments or constructors into context.",
			fallback: "binary_metadata_inspect or r2_inspect or readelf for lightweight triage.",
			examples: [
				{
					description: "Inspect ELF file structure, segments and dynamic tags",
					command: 'elf_inspect(action: "query", path: "libnative.so", query_type: "all")',
				},
				{
					description: "Query constructor routines from .init_array",
					command: 'elf_inspect(action: "query", path: "libnative.so", query_type: "constructors")',
				},
			],
		},
	},
	sofixer: {
		id: "sofixer",
		name: "SoFixer",
		category: "binary",
		description:
			"Reconstruct and repair corrupted ELF sections and PT_LOAD segment headers from memory-dumped Android shared libraries (.so).",
		optional: true,
		binaries: ["sofixer", "SoFixer", "sofixer64", "SoFixer64", "sofixer32", "SoFixer32"],
		probe: deps => {
			const res = resolveSoFixer(deps);
			return res ? { path: res.path } : null;
		},
		installHints: {
			darwin: ["reverse setup reverse sofixer --execute"],
			linux: ["reverse setup reverse sofixer --execute"],
			win32: ["reverse setup reverse sofixer --execute"],
		},
		manualUrl: "https://github.com/F8LEFT/SoFixer",
		manualInstructions: {
			darwin:
				"Build 32-bit and 64-bit SoFixer executables from upstream F8LEFT/SoFixer (tag v2.1.7) using CMake and clang++, or run 'reverse setup reverse sofixer --execute'.",
			linux: "Build 32-bit and 64-bit SoFixer executables from upstream F8LEFT/SoFixer (tag v2.1.7) using CMake and g++, or run 'reverse setup reverse sofixer --execute'.",
			win32: "Build 32-bit and 64-bit SoFixer executables from upstream F8LEFT/SoFixer (tag v2.1.7) using CMake and MSVC, or run 'reverse setup reverse sofixer --execute'.",
		},
		installCommands: {
			darwin: [
				{
					manager: "build",
					command: "reverse setup reverse sofixer --execute",
					argv: ["reverse", "setup", "reverse", "sofixer", "--execute"],
					riskNote:
						"Builds native 32-bit and 64-bit SoFixer binaries from pinned upstream source (F8LEFT/SoFixer v2.1.7, BSD-3-Clause) using CMake and local compiler.",
				},
			],
			linux: [
				{
					manager: "build",
					command: "reverse setup reverse sofixer --execute",
					argv: ["reverse", "setup", "reverse", "sofixer", "--execute"],
					riskNote:
						"Builds native 32-bit and 64-bit SoFixer binaries from pinned upstream source (F8LEFT/SoFixer v2.1.7, BSD-3-Clause) using CMake and local compiler.",
				},
			],
			win32: [
				{
					manager: "build",
					command: "reverse setup reverse sofixer --execute",
					argv: ["reverse", "setup", "reverse", "sofixer", "--execute"],
					riskNote:
						"Builds native 32-bit and 64-bit SoFixer binaries from pinned upstream source (F8LEFT/SoFixer v2.1.7, BSD-3-Clause) using CMake and MSVC.",
				},
			],
		},
		usage: {
			canonical: 'elf_inspect(action: "repair", dump_path: "<dump.so>", base_address: "<base_addr>", arch: "64")',
			whenToUse:
				"Rebuilding sections, string tables and loadable headers of raw ELF shared objects dumped from Android process memory so they can be analyzed in IDA or Ghidra.",
			prerequisites: ["sofixer", "lief"],
			outputLimits:
				"Outputs candidate repaired ELF file with separate provenance; does not certify 100% restored relocations.",
			fallback:
				"readelf or binary_metadata_inspect for triage of raw dumped headers without section reconstruction.",
			examples: [
				{
					description: "Repair a 64-bit memory dumped .so with base address",
					command:
						'elf_inspect(action: "repair", dump_path: "artifacts/dump_libfoo.so", base_address: "0x7800000000", arch: "64")',
				},
				{
					description: "Repair a 32-bit ARM memory dumped .so",
					command:
						'elf_inspect(action: "repair", dump_path: "artifacts/dump_libfoo.so", base_address: "0xec000000", arch: "32")',
				},
			],
		},
	},
	"ghidra-findcrypt": {
		id: "ghidra-findcrypt",
		name: "Ghidra FindCrypt Analyzer",
		category: "decompiler",
		description:
			"Ghidra auto-analysis extension for locating cryptographic constants and algorithm signatures (AES, SHA, MD5, RSA, CRC).",
		optional: true,
		binaries: [],
		secondary: ["ghidra", "java"],
		probe: deps => {
			const res = resolveGhidraFindCrypt(deps);
			if (!res.available) {
				if (!res.ghidraFound) {
					return { path: "", secondaryMissing: ["ghidra"], adapterError: "Ghidra installation required" };
				}
				return null;
			}
			return { path: res.extensionDir ?? res.jarPath! };
		},
		installHints: {
			darwin: ["reverse setup reverse ghidra-findcrypt --execute"],
			linux: ["reverse setup reverse ghidra-findcrypt --execute"],
			win32: ["reverse setup reverse ghidra-findcrypt --execute"],
		},
		manualUrl: "https://github.com/TorgoTorgo/ghidra-findcrypt",
		manualInstructions: {
			darwin:
				"Build FindCrypt extension against your installed Ghidra version using 'gradle -PGHIDRA_INSTALL_DIR=<ghidra_dir> buildExtension', or run 'reverse setup reverse ghidra-findcrypt --execute'.",
			linux: "Build FindCrypt extension against your installed Ghidra version using 'gradle -PGHIDRA_INSTALL_DIR=<ghidra_dir> buildExtension', or run 'reverse setup reverse ghidra-findcrypt --execute'.",
			win32: "Build FindCrypt extension against your installed Ghidra version using 'gradle -PGHIDRA_INSTALL_DIR=<ghidra_dir> buildExtension', or run 'reverse setup reverse ghidra-findcrypt --execute'.",
		},
		installCommands: {
			darwin: [
				{
					manager: "build",
					command: "reverse setup reverse ghidra-findcrypt --execute",
					argv: ["reverse", "setup", "reverse", "ghidra-findcrypt", "--execute"],
					riskNote:
						"Compiles Ghidra FindCrypt extension from upstream source (TorgoTorgo/ghidra-findcrypt v2.1.4, GPL-3.0) against target Ghidra and installs it into Ghidra Extensions.",
				},
			],
			linux: [
				{
					manager: "build",
					command: "reverse setup reverse ghidra-findcrypt --execute",
					argv: ["reverse", "setup", "reverse", "ghidra-findcrypt", "--execute"],
					riskNote:
						"Compiles Ghidra FindCrypt extension from upstream source (TorgoTorgo/ghidra-findcrypt v2.1.4, GPL-3.0) against target Ghidra and installs it into Ghidra Extensions.",
				},
			],
			win32: [
				{
					manager: "build",
					command: "reverse setup reverse ghidra-findcrypt --execute",
					argv: ["reverse", "setup", "reverse", "ghidra-findcrypt", "--execute"],
					riskNote:
						"Compiles Ghidra FindCrypt extension from upstream source (TorgoTorgo/ghidra-findcrypt v2.1.4, GPL-3.0) against target Ghidra and installs it into Ghidra Extensions.",
				},
			],
		},
		usage: {
			canonical: 'ghidra_inspect(action: "findcrypt", path: "<target.so>")',
			whenToUse:
				"Scanning a native binary or shared library during Ghidra headless analysis to identify cryptographic constants, S-boxes, lookup tables, and candidate crypto algorithms.",
			prerequisites: ["ghidra", "ghidra-findcrypt", "java"],
			outputLimits:
				"Returns detected candidate constant matches, addresses and algorithm labels; does not certify cryptographic completeness.",
			fallback: "strings, readelf, or r2_inspect search for known constant byte patterns.",
			examples: [
				{
					description: "Run FindCrypt analysis on target binary via headless Ghidra",
					command: 'ghidra_inspect(action: "findcrypt", path: "libcrypto.so")',
				},
			],
		},
	},
};

/** All tools catalogued for the reverse engineering toolchain. */
export function getReverseTools(): readonly SkillToolDescriptor[] {
	return Object.values(SKILL_TOOL_CATALOG);
}

/** Lookup a single catalog tool by its canonical id (case-insensitive). */
export function getReverseTool(id: string): SkillToolDescriptor | undefined {
	return SKILL_TOOL_CATALOG[id.trim().toLowerCase()];
}

export interface ProbePythonOptions {
	env?: Record<string, string | undefined>;
	platform?: SkillToolPlatform;
	which?: SkillRequirementWhich;
	cwd?: string;
	candidates?: readonly string[];
}

/**
 * Synchronous probe function for Python 3.9+ runtime.
 *
 * Verifies that a candidate Python interpreter physically exists on disk and satisfies sys.version_info >= (3, 9).
 * Enumerates candidates via enumeratePythonRuntimes and PATH lookups (or takes explicit test candidates);
 * never returns nonexistent paths or assumes success without actual execution check.
 */
export function probePythonTool(deps?: ProbePythonOptions): string | null {
	const cwd = deps?.cwd ?? process.cwd();
	const env = deps?.env ?? process.env;
	const which = deps?.which ?? $which;

	const candidatePaths: string[] = [];
	if (deps?.candidates !== undefined) {
		candidatePaths.push(...deps.candidates);
	} else {
		if (deps?.which !== undefined) {
			for (const binName of ["python3", "python"]) {
				const candidate = which(binName);
				if (candidate && !candidatePaths.includes(candidate)) {
					candidatePaths.push(candidate);
				}
			}
		}

		try {
			const runtimes = enumeratePythonRuntimes(cwd, env);
			for (const r of runtimes) {
				if (!candidatePaths.includes(r.pythonPath)) {
					candidatePaths.push(r.pythonPath);
				}
			}
		} catch {}

		if (deps?.which === undefined) {
			for (const binName of ["python3", "python"]) {
				const candidate = which(binName);
				if (candidate && !candidatePaths.includes(candidate)) {
					candidatePaths.push(candidate);
				}
			}
		}
	}

	for (const candidate of candidatePaths) {
		try {
			if (!fs.existsSync(candidate) || fs.statSync(candidate).isDirectory()) {
				continue;
			}
		} catch {
			continue;
		}

		try {
			const res = child_process.spawnSync(
				candidate,
				["-c", "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"],
				{ timeout: 1500, windowsHide: true },
			);
			if (res.status === 0) {
				return candidate;
			}
		} catch {}
	}

	return null;
}
/**
 * Built-in catalog of canonical reverse engineering capabilities.
 *
 * Defines how high-level analysis scenarios map to recommended native tools,
 * optional external tools, fallbacks, setup commands, and post-installation dispatch.
 */
export const CAPABILITY_CATALOG: Readonly<Record<string, CapabilityDescriptor>> = {
	android_native_emulation: {
		id: "android_native_emulation",
		name: "Android Native Library Emulation (JNI / ARM)",
		category: "android",
		scenario:
			"Emulate ARM32/ARM64 Android .so native libraries headlessly and call JNI functions without a physical device or emulator.",
		description:
			"Simulates Dalvik/ART JVM runtime and Linux ARM CPU environment to execute exported or obfuscated JNI native methods (e.g. signature calculation, token generation, anti-tamper routines) directly from local .so binaries.",
		why: "Bypasses device environment detection, root checks, and emulator restrictions by executing JNI code directly inside a controlled CPU emulation harness.",
		recommendedNativeTool: "unidbg",
		optionalExternalTools: ["unidbg"],
		prerequisites: ["jdk8"],
		fallbacks: ["frida", "readelf", "radare2"],
		setupCommand: "reverse setup reverse unidbg",
		postInstallInvocation:
			"reverse unidbg scaffold <target> && reverse unidbg launch <harness> to run ARM32/ARM64 native JNI library emulation with automated McpToolkit & MCP debugger",
	},
	apk_unpacking: {
		id: "apk_unpacking",
		name: "APK / AAB Package Decompilation & Unpacking",
		category: "android",
		scenario:
			"Extract, decode, decompile, and inspect Android application packages (APK, AAB, APKS, XAPK), manifests, resources, and Dalvik bytecode.",
		description:
			"Decompiles binary AndroidManifest.xml, decodes resources.arsc, unpacks asset tables, and converts Dalvik DEX bytecode into readable smali assembly or Java high-level source code.",
		why: "Transforms opaque binary APK packages and optimized DEX files into structured project trees and intelligible source code for vulnerability and protocol analysis.",
		recommendedNativeTool: "android_package_inspect",
		optionalExternalTools: ["apktool", "jadx", "droidasc", "baksmali", "dexdump"],
		prerequisites: ["java"],
		fallbacks: ["file", "strings"],
		setupCommand: "reverse setup reverse apktool",
		postInstallInvocation: "apktool d -f -o <output_dir> <target.apk> or jadx -d <output_dir> <target.apk>",
	},
	dex_patching: {
		id: "dex_patching",
		name: "DEX Bytecode Inspection, Validation & Semantic Patching",
		category: "android",
		scenario:
			"Inspect Dalvik bytecode instruction sequences, validate DEX structures/headers, and apply deterministic byte-level opcode patches.",
		description:
			"Locates method instructions by class, method name, and signature; validates DEX headers, Adler32 checksums, SHA-1 signatures, and instruction boundaries; applies semantic bytecode patches (e.g. conditional branch inversion, return value overrides, nop padding) with automatic header recalculation.",
		why: "Direct bytecode editing avoids full smali disassembly/reassembly failures on obfuscated or anti-decompilation APKs, preserving layout, resources, and unaffected code without introducing assembly noise.",
		recommendedNativeTool: "dex_patch",
		optionalExternalTools: ["python", "jadx", "baksmali"],
		prerequisites: ["python"],
		fallbacks: ["droidasc", "dexdump", "strings"],
		setupCommand: "reverse setup reverse python",
		postInstallInvocation:
			'dex_patch(action: "inspect", path: "<target.apk_or_dex>", class: "<Lpkg/Class;>", method: "<method>") or dex_patch(action: "patch", path: "<target.dex>", out: "<out.dex>", dry_run: false, specs: [...])',
	},
	apk_artifact_generation: {
		id: "apk_artifact_generation",
		name: "APK Artifact Generation, Repackaging & Signing Pipeline",
		category: "android",
		scenario:
			"Diff container entries, assemble modified APK containers, align archives, apply v1-v3 APK signatures, and verify package integrity.",
		description:
			"Performs entry-level archive comparison, repacks modified DEX files into APK containers with uncompressed/aligned resources, executes 4-byte zipalign and 16KiB page alignment for native libraries, signs containers with apksigner (v1-v3 schemes), and validates signature blocks.",
		why: "Produces deployable, structurally valid Android packages while preventing corrupted resource alignments, invalid ZIP checksums, and broken signature blocks.",
		recommendedNativeTool: "apk_artifact",
		optionalExternalTools: ["python", "zipalign", "apksigner", "java", "adb"],
		prerequisites: ["python", "java"],
		fallbacks: ["apktool", "unzip", "file"],
		setupCommand: "reverse setup reverse apksigner",
		postInstallInvocation:
			'apk_artifact(action: "diff", original_path: "<orig.apk>", modified_path: "<mod.apk>") or apk_artifact(action: "repack", path: "<orig.apk>", output_path: "<out.apk>", dex_files: { "classes.dex": "<mod.dex>" }) or apk_artifact(action: "sign", path: "<in.apk>", output_path: "<out.apk>", keystore_path: "<ks>", key_alias: "<alias>")',
	},
	browser_debugger: {
		id: "browser_debugger",
		name: "Browser Debugger & CDP Dynamic Inspection",
		category: "web",
		scenario:
			"Dynamic Web application inspection, DOM inspection, script debugging, source-map recovery, and automated Chrome DevTools Protocol control.",
		description:
			"Connects to running Chromium/WebKit instances via Chrome DevTools Protocol (CDP) or Playwright to set breakpoints, evaluate expressions in page context, inspect call stacks, and intercept frontend execution flow.",
		why: "Enables runtime inspection of complex minified JavaScript code, single-page application state, and dynamic crypto/signature generation that cannot be resolved through static bundle analysis.",
		recommendedNativeTool: "browser_reverse_session",
		optionalExternalTools: ["jshookmcp", "playwright-mcp"],
		prerequisites: ["node"],
		fallbacks: ["mitmproxy", "curl", "file"],
		setupCommand: "reverse setup reverse jshookmcp --execute",
		postInstallInvocation:
			"jshook MCP search_tools -> describe_tool -> call_tool for browser/debugger tools; keep one browser controller per target",
	},
	websocket_capture: {
		id: "websocket_capture",
		name: "WebSocket & Network Protocol Capture",
		category: "network",
		scenario:
			"Intercept, monitor, record, decode, and analyze WebSocket frames and bidirectional network streaming protocols.",
		description:
			"Captures real-time full-duplex WebSocket frames (text, binary, protobuf), decrypts TLS/WSS traffic, and parses frame headers, payload opcodes, and sequence events for protocol reverse engineering.",
		why: "WebSocket connections bypass standard request-response HTTP inspection; frame-level capture is necessary to reconstruct streaming protocols, heartbeats, and push payloads.",
		recommendedNativeTool: "websocket_observe",
		optionalExternalTools: ["jshookmcp", "mitmproxy", "tshark"],
		prerequisites: [],
		fallbacks: ["pcap_inspect", "strings", "curl"],
		setupCommand: "reverse setup reverse mitmproxy",
		postInstallInvocation:
			"mitmweb --web-port 8081 or tshark -Y websocket -i any (or inspect existing captures with websocket_observe)",
	},
	native_debugger: {
		id: "native_debugger",
		name: "Native Binary Debugger & Dynamic Tracing",
		category: "binary",
		scenario:
			"Dynamic runtime debugging, breakpoint inspection, register state analysis, memory mapping, and execution trace of native ELF, PE, and Mach-O binaries.",
		description:
			"Attaches to or spawns native binary processes under debugger control to inspect register state, single-step assembly instructions, analyze memory heaps/stacks, and monitor dynamic system library calls.",
		why: "Analyzes packing routines, anti-debugging mechanisms, runtime decryption keys, and dynamically generated control flow that cannot be understood statically.",
		recommendedNativeTool: "triage",
		optionalExternalTools: ["radare2", "r2mcp", "frida", "ghidra", "ida"],
		prerequisites: [],
		fallbacks: ["binary_metadata_inspect", "readelf", "strings", "file"],
		setupCommand: "reverse setup reverse radare2",
		postInstallInvocation:
			'debug(action: "launch", program: "<binary_path>") or r2 -d <binary_path> or frida -f <binary_path>',
	},
	js_deobfuscation: {
		id: "js_deobfuscation",
		name: "JavaScript & Bytecode De-obfuscation",
		category: "web",
		scenario:
			"De-obfuscate minified or packed JavaScript, reconstruct AST structure, recover source maps, and disassemble React Native Hermes bytecode.",
		description:
			"Applies syntax transforms, control flow unscrambling, string decryptor execution, and Hermes bytecode disassembling to turn obfuscated client bundles into intelligible logic.",
		why: "Removes control flow flattening, dead code, and string encryption layers from frontend and mobile bundles.",
		recommendedNativeTool: "sourcemap_inspect",
		optionalExternalTools: ["jshookmcp", "hbctool"],
		prerequisites: ["node"],
		fallbacks: ["strings", "file"],
		setupCommand: "reverse setup reverse jshookmcp --execute",
		postInstallInvocation:
			"jshook MCP search_tools -> describe_tool -> call_tool for webcrack_unpack/AST transformations; hbctool remains the Hermes-specific option",
	},
	traffic_interception: {
		id: "traffic_interception",
		name: "HTTP/HTTPS & Protocol Traffic Interception",
		category: "network",
		scenario:
			"Transparent network proxying, SSL/TLS decryption, request/response tampering, and API endpoint mapping.",
		description:
			"Routes client network traffic through an inspecting proxy to capture headers, query parameters, multipart bodies, and cryptographic signatures in transit.",
		why: "Uncovers client-server API contracts, authentication token flows, and cryptographic request signing algorithms.",
		recommendedNativeTool: "pcap_inspect",
		optionalExternalTools: ["jshookmcp", "mitmproxy", "tshark"],
		prerequisites: [],
		fallbacks: ["curl", "strings"],
		setupCommand: "reverse setup reverse mitmproxy",
		postInstallInvocation: "mitmproxy -p 8080 or mitmdump -s filter.py",
	},
	symbolic_trace_analysis: {
		id: "symbolic_trace_analysis",
		name: "Symbolic Trace Analysis",
		category: "binary",
		scenario: "Recover symbolic input/output relations from captured x86 or x64 execution traces.",
		description:
			"Replays bounded instruction and state evidence with Triton, simplifies expressions and emits LLVM IR when the installed engine supports it.",
		why: "Separates target semantics from obfuscation along observed paths without running target machine code on the host.",
		recommendedNativeTool: "triton_analyze",
		optionalExternalTools: ["triton"],
		fallbacks: ["triage", "binary_metadata_inspect"],
		setupCommand: "reverse setup reverse triton --execute",
		postInstallInvocation:
			'triton_analyze(action: "status"), then bounded replay with explicit symbolic inputs and requested output',
	},
	vmp_dump_repair: {
		id: "vmp_dump_repair",
		name: "VMProtect Dump and Import Repair",
		category: "binary",
		scenario: "Dump an already unpacked VMProtect x64 module and rebuild protected imports on Windows.",
		description:
			"Runs VMPDump against an explicitly selected process after observed OEP and preserves the repaired PE as an artifact.",
		why: "Produces the unpacked input needed for static analysis while retaining original module and image-base evidence.",
		recommendedNativeTool: "vmp_dump",
		optionalExternalTools: ["vmpdump"],
		fallbacks: ["binary_metadata_inspect", "triage"],
		setupCommand: "reverse setup reverse vmpdump --execute",
		postInstallInvocation:
			'vmp_dump(action: "status"), then explicitly approved dump with PID, module path and observed OEP evidence',
	},
	native_function_lifting: {
		id: "native_function_lifting",
		name: "Native Function LLVM Lifting",
		category: "binary",
		scenario: "Recover LLVM IR for an individual obfuscated x64 PE function.",
		description:
			"Runs Mergen against a staged copy and retains actual LLVM IR and diagnostics. Self-modifying code and whole-binary recovery are unsupported.",
		why: "Uses compiler optimization to make protected function semantics and control flow easier to analyze.",
		recommendedNativeTool: "native_devirtualize",
		optionalExternalTools: ["mergen"],
		fallbacks: ["binary_metadata_inspect", "triage"],
		setupCommand: "reverse setup reverse mergen --execute",
		postInstallInvocation:
			'native_devirtualize(action: "status", backend: "mergen"), then lift one x64 PE function at its virtual address',
	},
	vmp_legacy_devirtualization: {
		id: "vmp_legacy_devirtualization",
		name: "Legacy VMProtect VTIL Devirtualization",
		category: "binary",
		scenario: "Analyze unpacked VMProtect 3.0–3.5 x64 virtualized routines.",
		description:
			"Runs NoVmp with selected VM-entry RVAs and optional original image base; retains genuine VTIL artifacts in a separate output directory.",
		why: "Adds a static legacy backend without treating experimental recompilation as verified executable recovery.",
		recommendedNativeTool: "native_devirtualize",
		optionalExternalTools: ["novmp"],
		fallbacks: ["binary_metadata_inspect", "triage"],
		setupCommand: "reverse setup reverse novmp --execute",
		postInstallInvocation:
			'native_devirtualize(action: "status", backend: "novmp"), then lift selected VM-entry RVAs from an unpacked x64 PE',
	},
	native_elf_analysis: {
		id: "native_elf_analysis",
		name: "Native ELF Deep Inspection & Constructor Analysis",
		category: "binary",
		scenario: "Inspect ELF headers, segments, dynamic entries, relocations, init/fini arrays, and address mappings.",
		description:
			"Performs deep structural analysis of Linux and Android native ELF binaries using LIEF, extracting dynamic symbols, relocation tables, and constructor/destructor functions.",
		why: "Reveals early initialization logic, anti-debugging code in .init_array, and dynamic symbol bindings without running the binary.",
		recommendedNativeTool: "elf_inspect",
		optionalExternalTools: ["lief", "readelf"],
		prerequisites: ["python"],
		fallbacks: ["binary_metadata_inspect", "readelf", "r2_inspect"],
		setupCommand: "reverse setup reverse lief",
		postInstallInvocation:
			'elf_inspect(action: "query", path: "<sample.so>", query_type: "all") or elf_inspect(action: "query", path: "<sample.so>", query_type: "constructors")',
	},
	native_elf_repair: {
		id: "native_elf_repair",
		name: "Native ELF Memory Dump Reconstruction & Repair",
		category: "binary",
		scenario: "Reconstruct and repair corrupted ELF section headers from memory dumps using SoFixer.",
		description:
			"Rebuilds corrupted section headers, string tables, and dynamic segments of raw memory-dumped ELF binaries using SoFixer (32-bit or 64-bit), producing analyzable candidate binaries for Ghidra or IDA.",
		why: "Memory dumps often lack section headers and segment alignments, causing disassemblers and decompilers to fail; reconstruction restores loadable layout.",
		recommendedNativeTool: "elf_inspect",
		optionalExternalTools: ["sofixer"],
		prerequisites: ["sofixer", "lief"],
		fallbacks: ["readelf", "binary_metadata_inspect"],
		setupCommand: "reverse setup reverse sofixer",
		postInstallInvocation: 'elf_inspect(action: "repair", dump_path: "<dump.so>", base_address: "0x...", arch: "64")',
	},
	native_crypto_constant_analysis: {
		id: "native_crypto_constant_analysis",
		name: "Native Cryptographic Constant & Algorithm Detection",
		category: "decompiler",
		scenario:
			"Identify cryptographic constants and known algorithm signatures inside native binaries using Ghidra FindCrypt.",
		description:
			"Runs Ghidra's FindCrypt auto-analyzer during headless inspection to locate cryptographic constants (AES S-box, SHA-256 round constants, MD5 initial states, CRC tables) and annotate functions.",
		why: "Quickly pinpoints encryption, hashing, and signature routines in stripped native binaries without manual constant cross-referencing.",
		recommendedNativeTool: "ghidra_inspect",
		optionalExternalTools: ["ghidra-findcrypt", "ghidra"],
		prerequisites: ["ghidra"],
		fallbacks: ["ghidra_inspect", "strings", "r2_inspect"],
		setupCommand: "reverse setup reverse ghidra-findcrypt",
		postInstallInvocation: 'ghidra_inspect(action: "findcrypt", path: "<target.so>")',
	},
};

/** All capabilities defined for the reverse engineering catalog. */
export function getReverseCapabilities(): readonly CapabilityDescriptor[] {
	return Object.values(CAPABILITY_CATALOG);
}

/** Lookup a single capability by its canonical id (case-insensitive). */
export function getReverseCapability(id: string): CapabilityDescriptor | undefined {
	return CAPABILITY_CATALOG[id.trim().toLowerCase()];
}

/**
 * Resolve availability status of all reverse capabilities for the host system.
 *
 * Evaluates whether each capability is fully ready (all or primary external tools installed),
 * available with fallbacks (native inspection tools or command-line substitutes present),
 * or missing, providing model-actionable setup commands and post-install routing.
 */
const COMMON_FALLBACK_TOOLS: Record<string, true> = {
	file: true,
	strings: true,
	curl: true,
	unzip: true,
	pcap_inspect: true,
	binary_metadata_inspect: true,
	readelf: true,
	elf_inspect: true,
};

const NATIVE_DAP_ADAPTER_IDS: Record<string, true> = {
	"lldb-dap": true,
	gdb: true,
	codelldb: true,
};
const NATIVE_DAP_LANGUAGES: Record<string, true> = {
	c: true,
	cpp: true,
	rust: true,
	zig: true,
	objc: true,
	swift: true,
};

/**
 * Read-only probe for native binary debugger DAP adapters on the host system.
 * Probes configured DAP adapter executables via which/resolveCommand without executing subprocesses or debug targets.
 */
export function probeNativeDapAdapters(options?: {
	cwd?: string;
	which?: SkillRequirementWhich;
	dapAdapters?: readonly string[];
}): string[] {
	if (options?.dapAdapters !== undefined) {
		return [...options.dapAdapters];
	}
	try {
		const cwd = options?.cwd ?? process.cwd();
		const configs = getAdapterConfigs(cwd);
		const found: string[] = [];
		for (const [name, config] of Object.entries(configs)) {
			const lower = name.toLowerCase();
			const isNativeName = Boolean(NATIVE_DAP_ADAPTER_IDS[lower]);
			const isNativeLang =
				config.languages?.some(lang => Boolean(NATIVE_DAP_LANGUAGES[lang.toLowerCase()])) ?? false;
			if (!isNativeName && !isNativeLang) continue;
			if (options?.which !== undefined) {
				const cmd = config.command || name;
				if (options.which(cmd) || options.which(name)) {
					found.push(name);
				}
			} else {
				const adapter = resolveAdapter(name, cwd);
				if (adapter) {
					found.push(adapter.name);
				}
			}
		}
		return found;
	} catch {
		return [];
	}
}

export function resolveReverseCapabilities(options: ResolveCapabilitiesOptions = {}): ReverseCapabilityStatus[] {
	const platform =
		options.platform ?? (process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux");
	const toolMap: Record<
		string,
		{
			id: string;
			name?: string;
			status: "installed" | "missing";
			packageManager?: string | null;
			installCommand?: string | null;
		}
	> = {};
	if (options.toolStatuses) {
		for (const t of options.toolStatuses) {
			toolMap[t.id.toLowerCase()] = t;
		}
	}
	const serviceMap: Record<
		string,
		{
			id: string;
			name?: string;
			ready?: boolean;
			prerequisitesReady?: boolean;
			installed?: boolean;
			configured?: boolean;
			enabled?: boolean | null;
			connection?: "unknown" | string;
			packageManager?: string | null;
			installCommand?: string | null;
		}
	> = {};
	if (options.serviceStatuses) {
		for (const s of options.serviceStatuses) {
			serviceMap[s.id.toLowerCase()] = s;
		}
	}

	const results: ReverseCapabilityStatus[] = [];

	let candidateCaps = Object.values(CAPABILITY_CATALOG);
	if (options.filterCapability) {
		const filterId = options.filterCapability.toLowerCase();
		candidateCaps = candidateCaps.filter(c => c.id.toLowerCase() === filterId);
	}
	if (options.filterCategory) {
		const filterCat = options.filterCategory.toLowerCase();
		candidateCaps = candidateCaps.filter(c => c.category.toLowerCase() === filterCat);
	}
	if (options.filterTool) {
		const filterT = options.filterTool.toLowerCase();
		candidateCaps = candidateCaps.filter(
			c =>
				c.optionalExternalTools.some(t => t.toLowerCase() === filterT) ||
				c.recommendedNativeTool?.toLowerCase() === filterT,
		);
	}

	for (const cap of candidateCaps) {
		const toolRefs: CapabilityToolRef[] = [];
		for (const toolId of cap.optionalExternalTools) {
			const lowerId = toolId.toLowerCase();
			const fromTool = toolMap[lowerId];
			const fromService = serviceMap[lowerId];
			if (fromTool) {
				toolRefs.push({
					id: fromTool.id,
					name: fromTool.name ?? fromTool.id,
					status: fromTool.status,
					packageManager: fromTool.packageManager,
					installCommand: fromTool.installCommand,
				});
			} else if (fromService) {
				const prereqsReady = fromService.prerequisitesReady ?? fromService.ready ?? false;
				const isConfigured = fromService.configured === true;
				const isEnabled = fromService.enabled !== false;
				const isConnected = fromService.connection === "connected";
				const isReady = prereqsReady && fromService.installed !== false && isConfigured && isEnabled && isConnected;

				const toolStatus: "ready" | "configured" | "unconfigured" | "missing" = isReady
					? "ready"
					: !prereqsReady || fromService.installed === false
						? "missing"
						: isConfigured
							? "configured"
							: "unconfigured";

				toolRefs.push({
					id: fromService.id,
					name: fromService.name ?? fromService.id,
					status: toolStatus,
					packageManager: fromService.packageManager,
					installCommand: fromService.installCommand,
					prerequisitesReady: prereqsReady,
					configured: isConfigured,
					enabled: fromService.enabled ?? null,
					connection: fromService.connection ?? "unknown",
				});
			} else {
				const toolDesc = SKILL_TOOL_CATALOG[lowerId];
				if (toolDesc) {
					toolRefs.push({
						id: toolDesc.id,
						name: toolDesc.name ?? toolDesc.id,
						status: "missing",
						installCommand: toolDesc.installCommands?.[platform]?.[0]?.command ?? null,
						packageManager: toolDesc.installCommands?.[platform]?.[0]?.manager ?? null,
					});
				} else {
					toolRefs.push({
						id: toolId,
						name: toolId,
						status: "missing",
					});
				}
			}
		}

		const hasInstalledTool = toolRefs.some(t => t.status === "installed" || t.status === "ready");
		const availableFallbacks: string[] = [];
		for (const fb of cap.fallbacks) {
			const lowerFb = fb.toLowerCase();
			const toolStatus = toolMap[lowerFb];
			if (toolStatus && toolStatus.status === "installed") {
				availableFallbacks.push(fb);
			} else if (lowerFb in COMMON_FALLBACK_TOOLS) {
				if (!toolStatus || toolStatus.status === "installed") {
					availableFallbacks.push(fb);
				}
			}
		}
		let canStart: boolean | undefined;
		let runtimeReady: boolean | undefined;
		let compatible: boolean | undefined;
		let targetMatched: ReverseCapabilityStatus["targetMatched"];
		let executedVerified: ReverseCapabilityStatus["executedVerified"];
		let unpackingStages: ReverseCapabilityStatus["unpackingStages"];
		let emulationStages: ReverseCapabilityStatus["emulationStages"];
		let status: "ready" | "available_with_fallbacks" | "missing";
		let isReady: boolean;
		let setupCommand = cap.setupCommand;
		let blockedRequirements: string[] | undefined;
		let pipelineStages: ReverseCapabilityStatus["pipelineStages"];
		let elfRepairStages: ReverseCapabilityStatus["elfRepairStages"];
		let resolvedRecommendedNativeTool = cap.recommendedNativeTool;
		let resolvedPostInstallInvocation = cap.postInstallInvocation;

		if (cap.id === "android_native_emulation") {
			const unidbgReadiness = evaluateUnidbgReadiness({
				cwd: options.cwd,
				session: options.session,
				env: options.env,
				target: options.target,
			});
			canStart = unidbgReadiness.canStart;
			compatible = unidbgReadiness.compatible;
			runtimeReady = unidbgReadiness.runtimeReady;
			targetMatched = unidbgReadiness.targetMatched;
			executedVerified = unidbgReadiness.executedVerified;
			const missingLaunchRequirements = !unidbgReadiness.installed
				? ["unidbg"]
				: !compatible
					? ["jdk8"]
					: !canStart
						? ["unidbg-classpath"]
						: [];
			const jniH = unidbgReadiness.connectedHarness;

			emulationStages = {
				launchPrerequisites: {
					ready: canStart,
					canStart,
					installed: unidbgReadiness.installed,
					compatible,
					missingRequirements: missingLaunchRequirements,
					error: unidbgReadiness.error,
					remedy: unidbgReadiness.remedy,
				},
				runtimeSession: {
					connected: runtimeReady,
					activeHarnessCount: unidbgReadiness.activeHarnessCount,
					serverName: jniH?.serverName,
					port: jniH?.port,
				},
			};

			if (runtimeReady) {
				isReady = true;
				status = "ready";
				resolvedPostInstallInvocation = `Active Unidbg SSE MCP server running on port ${jniH?.port ?? "unknown"} (PID ${jniH?.pid ?? "unknown"}) with target ${jniH?.targetPath || "loaded binary"}. Server: ${jniH?.serverName ?? "unidbg"}`;
			} else if (canStart) {
				isReady = false;
				status = "available_with_fallbacks";
				resolvedPostInstallInvocation =
					"Run 'reverse unidbg scaffold' and 'reverse unidbg launch' to start an active emulation session.";
			} else if (unidbgReadiness.installed && !compatible) {
				isReady = false;
				status = "available_with_fallbacks";
				blockedRequirements = ["jdk8"];
				setupCommand = "reverse setup reverse unidbg";
				resolvedPostInstallInvocation = `${unidbgReadiness.error} ${unidbgReadiness.remedy}`;
			} else {
				isReady = false;
				status = availableFallbacks.length > 0 ? "available_with_fallbacks" : "missing";
				blockedRequirements = unidbgReadiness.installed ? ["unidbg-classpath"] : ["unidbg"];
				setupCommand = "reverse setup reverse unidbg";
				resolvedPostInstallInvocation = `${unidbgReadiness.error ?? ""} ${unidbgReadiness.remedy ?? ""}`.trim();
			}
		} else if (cap.id === "apk_unpacking") {
			const unpackReadiness = evaluateApkUnpackingReadiness({ toolStatuses: options.toolStatuses });
			unpackingStages = unpackReadiness.stages;
			canStart = true;
			const decompileReady = unpackReadiness.ready;

			if (decompileReady) {
				isReady = true;
				status = "ready";
			} else {
				isReady = false;
				status = "available_with_fallbacks";
				const missingTools: string[] = [];
				for (const m of unpackReadiness.stages.javaDecompile.missingTools) {
					if (!missingTools.includes(m)) missingTools.push(m);
				}
				for (const m of unpackReadiness.stages.smali.missingTools) {
					if (!missingTools.includes(m)) missingTools.push(m);
				}
				blockedRequirements = missingTools;
				setupCommand =
					toolMap["apktool"]?.status !== "installed"
						? "reverse setup reverse apktool"
						: "reverse setup reverse jadx";
			}
		} else if (cap.id === "apk_artifact_generation") {
			const pythonReady = toolMap["python"]?.status === "installed";
			const zipalignReady = toolMap["zipalign"]?.status === "installed";
			const javaReady = toolMap["java"]?.status === "installed";
			const apksignerInstalled = toolMap["apksigner"]?.status === "installed";
			const apksignerReady = apksignerInstalled && javaReady;
			const signingReady = pythonReady && zipalignReady && apksignerReady;
			const adbReady = toolMap["adb"]?.status === "installed";
			const deviceHostReady = pythonReady && adbReady;

			const missingOffline = pythonReady ? [] : ["python"];
			const missingSigning: string[] = [];
			if (!pythonReady) missingSigning.push("python");
			if (!zipalignReady) missingSigning.push("zipalign");
			if (!apksignerInstalled) missingSigning.push("apksigner");
			if (!javaReady) missingSigning.push("java");

			const missingDevice: string[] = [];
			if (!pythonReady) missingDevice.push("python");
			if (!adbReady) missingDevice.push("adb");

			pipelineStages = {
				offline: {
					ready: pythonReady,
					requiredTools: ["python"],
					missingTools: missingOffline,
				},
				signing: {
					ready: signingReady,
					requiredTools: ["python", "zipalign", "apksigner", "java"],
					missingTools: missingSigning,
				},
				device: {
					ready: false,
					hostPrerequisitesReady: deviceHostReady,
					requiredTools: ["python", "adb"],
					missingTools: missingDevice,
					deviceConnected: false,
				},
			};

			const unionMissing = Array.from(new Set([...missingOffline, ...missingSigning]));
			if (unionMissing.length > 0) {
				blockedRequirements = unionMissing;
				if (!pythonReady) {
					setupCommand = "reverse setup reverse python";
				} else if (!apksignerInstalled) {
					setupCommand = "reverse setup reverse apksigner";
				} else if (!zipalignReady) {
					setupCommand = "reverse setup reverse zipalign";
				} else if (!javaReady) {
					setupCommand = "reverse setup reverse java";
				}
			}

			// apk_artifact_generation is only fully ready when both offline engine and complete signing pipeline are ready
			isReady = pythonReady && signingReady;
			if (isReady) {
				status = "ready";
			} else if (pythonReady || availableFallbacks.length > 0 || hasInstalledTool) {
				status = "available_with_fallbacks";
			} else {
				status = "missing";
			}
		} else if (cap.id === "dex_patching") {
			const pythonReady = toolMap["python"]?.status === "installed";
			const missingOffline = pythonReady ? [] : ["python"];
			pipelineStages = {
				offline: {
					ready: pythonReady,
					requiredTools: ["python"],
					missingTools: missingOffline,
				},
				signing: {
					ready: true,
					requiredTools: [],
					missingTools: [],
				},
				device: {
					ready: true,
					hostPrerequisitesReady: true,
					requiredTools: [],
					missingTools: [],
				},
			};
			if (!pythonReady) {
				blockedRequirements = ["python"];
				setupCommand = "reverse setup reverse python";
			}
			isReady = pythonReady;
			if (isReady) {
				status = "ready";
			} else if (availableFallbacks.length > 0 || hasInstalledTool) {
				status = "available_with_fallbacks";
			} else {
				status = "missing";
			}
		} else if (cap.id === "native_debugger") {
			// Probes configured native binary DAP debuggers (lldb-dap, gdb, codelldb) via read-only which/config check without subprocess execution
			let dapAdapters: string[];
			if (options.dapAdapters !== undefined) {
				dapAdapters = [...options.dapAdapters];
			} else if (options.which !== undefined) {
				dapAdapters = probeNativeDapAdapters({ which: options.which });
			} else if (options.toolStatuses !== undefined) {
				// Synthetic test or caller passing toolStatuses: isolate from ambient host DAP
				dapAdapters = Object.keys(NATIVE_DAP_ADAPTER_IDS).filter(id => toolMap[id]?.status === "installed");
			} else {
				dapAdapters = probeNativeDapAdapters({ cwd: options.cwd });
			}

			const hasDapDebugger = dapAdapters.length > 0;
			const radareInstalled = toolMap["radare2"]?.status === "installed";
			const fridaInstalled = toolMap["frida"]?.status === "installed";
			const ghidraInstalled = toolMap["ghidra"]?.status === "installed";
			const idaInstalled = toolMap["ida"]?.status === "installed";
			const debugToolEnabled = options.debugToolEnabled !== false;
			const dapRouteReady = hasDapDebugger && debugToolEnabled;
			const hasRealDebuggerRoute = dapRouteReady || radareInstalled;

			isReady = hasRealDebuggerRoute;
			if (isReady) {
				status = "ready";
			} else if (
				fridaInstalled ||
				ghidraInstalled ||
				idaInstalled ||
				availableFallbacks.length > 0 ||
				hasInstalledTool
			) {
				status = "available_with_fallbacks";
			} else {
				status = "missing";
			}

			// Recommendation points to a usable tool for this capability:
			// - When DAP debugger backend is discovered and enabled in session: native DAP 'debug' tool
			// - Otherwise: zero-dependency built-in partial fallback 'triage' (avoiding advertising debug or r2_inspect when backends are missing)
			if (dapRouteReady) {
				resolvedRecommendedNativeTool = "debug";
				resolvedPostInstallInvocation = `debug(action: "launch", program: "<binary_path>", adapter: "${dapAdapters[0]}")`;
			} else if (radareInstalled) {
				resolvedRecommendedNativeTool = "triage";
				resolvedPostInstallInvocation =
					'r2 -d <binary_path> (radare2 CLI debugging) or r2_inspect(action: "disasm", path: "<binary_path>")';
			} else if (idaInstalled) {
				resolvedRecommendedNativeTool = "triage";
				resolvedPostInstallInvocation =
					'read(path: "<binary_path>:overview") (with idalib) or launch IDA Pro GUI for interactive analysis';
			} else if (fridaInstalled) {
				resolvedRecommendedNativeTool = "triage";
				resolvedPostInstallInvocation =
					'frida_session(action: "create", mode: "live", spawn: "<binary_path>") or frida(action: "exec", spawn: "<binary_path>", script: "<inline_hook>")';
			} else {
				resolvedRecommendedNativeTool = "triage";
				resolvedPostInstallInvocation =
					"r2 -d <binary_path> (after 'reverse setup reverse radare2') or configure a native DAP adapter (lldb-dap/gdb)";
			}
		} else if (cap.id === "native_elf_analysis") {
			const liefReady = toolMap["lief"]?.status === "installed";
			isReady = liefReady;
			if (!liefReady) {
				blockedRequirements = ["lief"];
				setupCommand = "reverse setup reverse lief";
			}
			if (isReady) {
				status = "ready";
			} else if (availableFallbacks.length > 0 || toolMap["readelf"]?.status === "installed") {
				status = "available_with_fallbacks";
			} else {
				status = "missing";
			}
		} else if (cap.id === "native_crypto_constant_analysis") {
			const ghidraReady = toolMap["ghidra"]?.status === "installed";
			const findcryptReady = toolMap["ghidra-findcrypt"]?.status === "installed";
			isReady = ghidraReady && findcryptReady;
			if (!ghidraReady || !findcryptReady) {
				const missing: string[] = [];
				if (!ghidraReady) missing.push("ghidra");
				if (!findcryptReady) missing.push("ghidra-findcrypt");
				blockedRequirements = missing;
				setupCommand = !ghidraReady ? "reverse setup reverse ghidra" : "reverse setup reverse ghidra-findcrypt";
			}
			if (isReady) {
				status = "ready";
			} else if (ghidraReady || availableFallbacks.length > 0) {
				status = "available_with_fallbacks";
			} else {
				status = "missing";
			}
		} else if (cap.id === "native_elf_repair") {
			const sofixerReady = toolMap["sofixer"]?.status === "installed";
			const liefReady = toolMap["lief"]?.status === "installed";
			const fridaReady = toolMap["frida"]?.status === "installed";
			const offlineReady = sofixerReady && liefReady;
			isReady = offlineReady;

			const missingOffline: string[] = [];
			if (!sofixerReady) missingOffline.push("sofixer");
			if (!liefReady) missingOffline.push("lief");
			const missingDump: string[] = fridaReady ? [] : ["frida"];

			elfRepairStages = {
				offline: {
					ready: offlineReady,
					requiredTools: ["sofixer", "lief"],
					missingTools: missingOffline,
				},
				dump: {
					ready: fridaReady,
					requiredTools: ["frida"],
					missingTools: missingDump,
				},
			};

			if (!offlineReady) {
				blockedRequirements = missingOffline;
				setupCommand = !sofixerReady ? "reverse setup reverse sofixer" : "reverse setup reverse lief";
			}

			if (isReady) {
				status = "ready";
			} else if (sofixerReady || liefReady || fridaReady || availableFallbacks.length > 0) {
				status = "available_with_fallbacks";
			} else {
				status = "missing";
			}
		} else {
			isReady = hasInstalledTool;
			if (isReady) {
				status = "ready";
			} else if (availableFallbacks.length > 0 || cap.recommendedNativeTool || hasInstalledTool) {
				status = "available_with_fallbacks";
			} else {
				status = "missing";
			}
		}

		results.push({
			id: cap.id,
			name: cap.name,
			category: cap.category,
			scenario: cap.scenario,
			description: cap.description,
			why: cap.why,
			status,
			ready: isReady,
			...(canStart !== undefined ? { canStart } : {}),
			...(runtimeReady !== undefined ? { runtimeReady } : {}),
			...(compatible !== undefined ? { compatible } : {}),
			...(targetMatched !== undefined ? { targetMatched } : {}),
			...(executedVerified !== undefined ? { executedVerified } : {}),
			recommendedNativeTool: resolvedRecommendedNativeTool,
			optionalExternalTools: toolRefs,
			prerequisites: cap.prerequisites,
			fallbacks: cap.fallbacks,
			availableFallbacks,
			setupCommand,
			postInstallInvocation: resolvedPostInstallInvocation,
			...(blockedRequirements ? { blockedRequirements } : {}),
			...(pipelineStages ? { pipelineStages } : {}),
			...(elfRepairStages ? { elfRepairStages } : {}),
			...(unpackingStages ? { unpackingStages } : {}),
			...(emulationStages ? { emulationStages } : {}),
		});
	}

	return results;
}

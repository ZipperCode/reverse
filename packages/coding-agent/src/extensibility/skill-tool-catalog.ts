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
import { locateIdaInstall } from "../ida/install";

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
	probe?: () => string | null;
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
}

/** Options for resolving capability availability on the host system. */
export interface ResolveCapabilitiesOptions {
	platform?: SkillToolPlatform;
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
		configured?: boolean;
		enabled?: boolean | null;
		connection?: "unknown" | string;
		packageManager?: string | null;
		installCommand?: string | null;
	}[];
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
		"~/Library/Android/sdk/build-tools/35.0.0",
		"~/Library/Android/sdk/build-tools/34.0.0",
		"~/Library/Android/sdk/build-tools/33.0.0",
	],
	linux: [
		"/usr/bin",
		"/usr/local/bin",
		"~/Android/Sdk/build-tools/35.0.0",
		"~/Android/Sdk/build-tools/34.0.0",
		"~/Android/Sdk/build-tools/33.0.0",
	],
	win32: [
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
			linux: [
				"/opt/ghidra/support",
				"/usr/share/ghidra/support",
				...UNIX_SEARCH_PATHS,
			],
			win32: [
				"C:/ghidra/support",
				"${LOCALAPPDATA}/Programs/ghidra/support",
				"~/ghidra/support",
			],
		},
		secondary: ["java"],
		installHints: {
			darwin: ["brew install --cask ghidra"],
			linux: ["apt install ghidra", "snap install ghidra --classic"],
			win32: ["choco install ghidra", "winget install NationalSecurityAgency.Ghidra"],
		},
		manualUrl: "https://ghidra-sre.org/",
		manualInstructions: {
			darwin: "Install via 'brew install --cask ghidra' or extract release zip and set GHIDRA_INSTALL_DIR (requires JDK 17+).",
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
			outputLimits: "Query specific functions or bounded export regions; avoid dumping entire binary listings into context.",
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
			win32: ["${LOCALAPPDATA}/Programs/wabt/bin", "~/wabt/bin"],
		},
		installHints: {
			darwin: ["brew install wabt"],
			linux: ["apt install wabt"],
			win32: ["choco install wabt"],
		},
		manualUrl: "https://github.com/WebAssembly/wabt/releases",
		manualInstructions: {
			darwin: "Install via 'brew install wabt' or download prebuilt tarball from GitHub releases.",
			linux: "Install via 'apt install wabt' or download prebuilt release from GitHub releases.",
			win32: "Install via 'choco install wabt' or download Windows release zip from GitHub releases.",
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
					manager: "choco",
					command: "choco install -y wabt",
					argv: ["choco", "install", "-y", "wabt"],
					riskNote: "Installs wabt via Chocolatey.",
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
		installCommands: {},
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
		installCommands: {},
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
		installCommands: {},
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
		installCommands: {},
	},

	unidbg: {
		id: "unidbg",
		name: "Unidbg (ARM32/ARM64 Android Native Library Emulator)",
		category: "android",
		description:
			"Emulate Android ARM32 and ARM64 native JNI libraries (.so) on the host JVM via Maven Java test harness (manual integration required)",
		optional: true,
		binaries: ["unidbg"],
		envPaths: [
			{ env: "UNIDBG_HOME", suffix: "/bin" },
			{ env: "UNIDBG_HOME" },
			{ env: "UNIDBG_ROOT" },
		],
		searchPaths: {
			darwin: ["~/.unidbg", "/usr/local/share/unidbg", "~/unidbg", ...UNIX_SEARCH_PATHS],
			linux: ["~/.unidbg", "/opt/unidbg", "~/unidbg", ...UNIX_SEARCH_PATHS],
			win32: ["${USERPROFILE}/unidbg", "${ProgramFiles}/unidbg"],
		},
		secondary: ["java"],
		installHints: {
			darwin: [
				"brew install openjdk maven && git clone https://github.com/zhkl0228/unidbg.git && cd unidbg && mvn package -DskipTests",
			],
			linux: [
				"sudo apt install -y default-jdk maven && git clone https://github.com/zhkl0228/unidbg.git && cd unidbg && mvn package -DskipTests",
			],
			win32: ["winget install Microsoft.OpenJDK.17 && git clone https://github.com/zhkl0228/unidbg.git"],
		},
		manualUrl: "https://github.com/zhkl0228/unidbg",
		manualInstructions: {
			darwin:
				"Clone https://github.com/zhkl0228/unidbg, compile with 'mvn package -DskipTests', and run tests or implement custom McpToolkit harness in Java.",
			linux: "Clone https://github.com/zhkl0228/unidbg, compile with 'mvn package -DskipTests', and run tests or implement custom McpToolkit harness in Java.",
			win32: "Clone https://github.com/zhkl0228/unidbg, compile with Maven, and run tests or implement custom McpToolkit harness in Java.",
		},
		installCommands: {},
		usage: {
			canonical: "mvn test -Dtest=<HarnessTest> (unidbg Java harness) or McpToolkit",
			whenToUse:
				"Emulating Android JNI native cryptographic algorithms, token generators, or anti-debug routines on host JVM without an Android device or emulator.",
			prerequisites: ["java"],
			outputLimits:
				"Capture bounded execution traces and returned buffers; avoid full memory block dumps in conversation context.",
			fallback: "Native ELF triage via readelf/r2_inspect or dynamic device instrumentation via frida_session.",
			examples: [
				{
					description: "Execute native emulation harness via Maven",
					command: "mvn test -Dtest=MyNativeHarnessTest",
				},
			],
		},
	},

	bundletool: {
		id: "bundletool",
		name: "bundletool (Android App Bundle tool)",
		category: "android",
		description: "Inspect Android App Bundles (.aab), extract APKs, and convert AAB containers to standalone APK sets",
		optional: true,
		binaries: ["bundletool", "bundletool.jar"],
		envPaths: [
			{ env: "BUNDLETOOL_HOME", suffix: "/bin" },
			{ env: "BUNDLETOOL_HOME" },
		],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${LOCALAPPDATA}/Programs/bundletool", "~/AppData/Local/Programs/bundletool"],
		},
		secondary: ["java"],
		installHints: {
			darwin: ["brew install bundletool"],
			linux: ["Download bundletool jar from https://github.com/google/bundletool/releases and wrap in shell script"],
			win32: ["winget install Google.Bundletool", "choco install bundletool"],
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
					manager: "winget",
					command: "winget install -e --id Google.Bundletool",
					argv: ["winget", "install", "-e", "--id", "Google.Bundletool"],
					riskNote: "Installs bundletool via Windows Package Manager.",
				},
				{
					manager: "choco",
					command: "choco install -y bundletool",
					argv: ["choco", "install", "-y", "bundletool"],
					riskNote: "Installs bundletool via Chocolatey.",
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
		envPaths: [
			{ env: "DEX2JAR_HOME", suffix: "/bin" },
			{ env: "DEX2JAR_HOME" },
		],
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
		description:
			"Disassemble Android Dalvik Executable (DEX) bytecode into precise human-readable smali assembly",
		optional: true,
		binaries: ["baksmali", "smali"],
		envPaths: [
			{ env: "SMALI_HOME", suffix: "/bin" },
			{ env: "SMALI_HOME" },
		],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${LOCALAPPDATA}/smali", "~/AppData/Local/smali"],
		},
		secondary: ["java"],
		installHints: {
			darwin: ["brew install smali"],
			linux: ["apt install -y smali"],
			win32: ["choco install smali"],
		},
		manualUrl: "https://github.com/google/smali/releases",
		manualInstructions: {
			darwin:
				"Download baksmali.jar from GitHub releases and wrap it in an executable script in /usr/local/bin.",
			linux: "Download baksmali.jar from GitHub releases and wrap it in an executable script in /usr/local/bin.",
			win32: "Download baksmali.jar from GitHub releases and wrap it in a baksmali.bat script in PATH.",
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
					manager: "choco",
					command: "choco install -y smali",
					argv: ["choco", "install", "-y", "smali"],
					riskNote: "Installs smali/baksmali via Chocolatey.",
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
		description:
			"Low-latency display and control of physical Android devices over USB or TCP/IP without root",
		optional: true,
		binaries: ["scrcpy"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: [
				"${LOCALAPPDATA}/Programs/scrcpy",
				"~/AppData/Local/Programs/scrcpy",
				"${ProgramFiles}/scrcpy",
			],
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
		name: "hermes-dec / hbctool",
		category: "web",
		description: "Disassembler and decompiler for Facebook Hermes JavaScript bytecode",
		optional: true,
		binaries: ["hermes-dec", "hbctool"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${APPDATA}/Python/Scripts", "${LOCALAPPDATA}/Programs/Python/Python312/Scripts"],
		},
		installHints: {
			darwin: ["git clone https://github.com/P1sec/hermes-dec or install hbctool"],
			linux: ["git clone https://github.com/P1sec/hermes-dec or install hbctool"],
			win32: ["git clone https://github.com/P1sec/hermes-dec or install hbctool"],
		},
		manualUrl: "https://github.com/P1sec/hermes-dec",
		manualInstructions: {
			darwin: "Clone https://github.com/P1sec/hermes-dec and build with CMake, or install hbctool via pipx.",
			linux: "Clone https://github.com/P1sec/hermes-dec and build with CMake, or install hbctool via pipx.",
			win32: "Clone https://github.com/P1sec/hermes-dec and build with CMake, or install hbctool via pipx.",
		},
		installCommands: {},
	},

	hbctool: {
		id: "hbctool",
		name: "hbctool",
		category: "web",
		description: "Hermes Bytecode disassembler and assembler tool",
		optional: true,
		binaries: ["hbctool", "hermes-dec"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${APPDATA}/Python/Scripts"],
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
		binaries: ["Il2CppDumper", "il2cppdumper"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${LOCALAPPDATA}/Programs/Il2CppDumper", "~/Il2CppDumper"],
		},
		installHints: {
			darwin: ["Download release from https://github.com/Perfare/Il2CppDumper/releases"],
			linux: ["Download release from https://github.com/Perfare/Il2CppDumper/releases"],
			win32: ["choco install il2cppdumper or download GitHub release"],
		},
		manualUrl: "https://github.com/Perfare/Il2CppDumper/releases",
		manualInstructions: {
			darwin: "Download the cross-platform release from GitHub releases and run with dotnet.",
			linux: "Download the release from GitHub releases and run with dotnet.",
			win32: "Install via 'choco install il2cppdumper' or extract release zip from GitHub releases.",
		},
		installCommands: {
			win32: [
				{
					manager: "choco",
					command: "choco install -y il2cppdumper",
					argv: ["choco", "install", "-y", "il2cppdumper"],
					riskNote: "Installs Il2CppDumper via Chocolatey.",
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
		name: "readelf / objdump",
		category: "binary",
		description: "Display information about ELF object files, section headers, and symbols",
		optional: true,
		binaries: ["readelf", "greadelf", "llvm-readelf", "objdump", "gobjdump", "llvm-objdump"],
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
			darwin: "Install GNU binutils via 'brew install binutils' (provides greadelf and gobjdump).",
			linux: "Install binutils via system package manager (e.g. sudo apt install binutils).",
			win32: "Install binutils via Chocolatey or MSYS2.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install binutils",
					argv: ["brew", "install", "binutils"],
					riskNote: "Installs GNU binutils via Homebrew (provides greadelf/gobjdump).",
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
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["${LOCALAPPDATA}/Programs/binwalk", "C:/binwalk"],
		},
		installHints: {
			darwin: ["brew install binwalk"],
			linux: ["apt install binwalk"],
			win32: ["pip install binwalk"],
		},
		manualUrl: "https://github.com/ReFirmLabs/binwalk",
		manualInstructions: {
			darwin: "Install via Homebrew: brew install binwalk.",
			linux: "Install via system package manager (e.g. sudo apt install binwalk).",
			win32: "Install via pip: pip install binwalk.",
		},
		installCommands: {
			darwin: [
				{
					manager: "brew",
					command: "brew install binwalk",
					argv: ["brew", "install", "binwalk"],
					riskNote: "Installs binwalk via Homebrew.",
				},
			],
			linux: [
				{
					manager: "apt",
					command: "apt install -y binwalk",
					argv: ["apt", "install", "-y", "binwalk"],
					riskNote: "Installs binwalk package via apt. May require root/sudo.",
				},
			],
			win32: [
				{
					manager: "pip",
					command: "pip install binwalk",
					argv: ["pip", "install", "binwalk"],
					riskNote: "Installs binwalk via pip.",
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
		binaries: ["vbindiff", "radiff2"],
		searchPaths: {
			darwin: UNIX_SEARCH_PATHS,
			linux: UNIX_SEARCH_PATHS,
			win32: ["C:/vbindiff"],
		},
		installHints: {
			darwin: ["brew install vbindiff"],
			linux: ["apt install vbindiff"],
			win32: ["choco install vbindiff"],
		},
		manualUrl: "https://www.cjmweb.net/vbindiff/",
		manualInstructions: {
			darwin: "Install via Homebrew: brew install vbindiff.",
			linux: "Install via package manager: apt install vbindiff.",
			win32: "Download from https://www.cjmweb.net/vbindiff/ or install via choco.",
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
					manager: "choco",
					command: "choco install -y vbindiff",
					argv: ["choco", "install", "-y", "vbindiff"],
					riskNote: "Installs vbindiff via Chocolatey.",
				},
			],
		},
		usage: {
			canonical: "binary_diff(path_a: 'v1.bin', path_b: 'v2.bin')",
			whenToUse:
				"Use native binary_diff for offline deterministic hashes, similarity score, and block/byte diffs; use vbindiff or radiff2 CLI for visual interactive side-by-side terminal hex inspection.",
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
		binaries: ["cargo-auditable", "rustc"],
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
		name: "tshark / tcpdump",
		category: "network",
		description: "Terminal network packet analyzer and capture utility",
		optional: true,
		binaries: ["tshark", "tcpdump"],
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
			darwin: "Install via 'brew install sqlite' or download precompiled binaries from https://www.sqlite.org/download.html.",
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
		envPaths: [
			{ env: "JAVA_HOME", suffix: "/bin" },
			{ env: "JAVA_HOME" },
		],
		searchPaths: {
			darwin: ["/Library/Java/JavaVirtualMachines/*/Contents/Home/bin", ...UNIX_SEARCH_PATHS],
			linux: ["/usr/lib/jvm/*/bin", ...UNIX_SEARCH_PATHS],
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

	ida: {
		id: "ida",
		name: "IDA Pro",
		category: "decompiler",
		description: "Interactive Disassembler and decompiler with idalib integration",
		optional: true,
		binaries: [],
		// IDA is an application bundle: reuse the one existing install detector
		// instead of teaching the generic resolver another platform matrix.
		probe: () => locateIdaInstall(undefined) ?? null,
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
};

/** All tools catalogued for the reverse engineering toolchain. */
export function getReverseTools(): readonly SkillToolDescriptor[] {
	return Object.values(SKILL_TOOL_CATALOG);
}

/** Lookup a single catalog tool by its canonical id (case-insensitive). */
export function getReverseTool(id: string): SkillToolDescriptor | undefined {
	return SKILL_TOOL_CATALOG[id.trim().toLowerCase()];
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
		recommendedNativeTool: "android_package_inspect",
		optionalExternalTools: ["unidbg"],
		prerequisites: ["java"],
		fallbacks: ["frida", "readelf", "radare2"],
		setupCommand: "rea setup reverse unidbg",
		postInstallInvocation: "Manual Maven Java harness integration required (git clone https://github.com/zhkl0228/unidbg, implement McpToolkit or test harness with JavaVM/DalvikModule, run with Maven)",
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
		optionalExternalTools: ["apktool", "jadx", "baksmali", "dexdump"],
		prerequisites: ["java"],
		fallbacks: ["file", "strings"],
		setupCommand: "rea setup reverse apktool",
		postInstallInvocation: "apktool d -f -o <output_dir> <target.apk> or jadx -d <output_dir> <target.apk>",
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
		optionalExternalTools: ["playwright-mcp"],
		prerequisites: ["node"],
		fallbacks: ["mitmproxy", "curl", "file"],
		setupCommand: "rea setup reverse playwright-mcp",
		postInstallInvocation:
			"Configure .rva/mcp.json playwright entry or launch browser_reverse_session with target URL",
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
		optionalExternalTools: ["mitmproxy", "tshark"],
		prerequisites: [],
		fallbacks: ["pcap_inspect", "strings", "curl"],
		setupCommand: "rea setup reverse mitmproxy",
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
		recommendedNativeTool: "r2_inspect",
		optionalExternalTools: ["radare2", "r2mcp", "frida", "ghidra"],
		prerequisites: [],
		fallbacks: ["binary_metadata_inspect", "readelf", "strings", "file"],
		setupCommand: "rea setup reverse radare2",
		postInstallInvocation: "r2 -d <binary_path> or frida -f <binary_path> (or query via r2_inspect)",
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
		optionalExternalTools: ["hbctool"],
		prerequisites: ["node"],
		fallbacks: ["strings", "file"],
		setupCommand: "rea setup reverse hbctool",
		postInstallInvocation: "hbctool disasm <index.android.bundle> <out_dir> or node deobfuscate.js",
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
		optionalExternalTools: ["mitmproxy", "tshark"],
		prerequisites: [],
		fallbacks: ["curl", "strings"],
		setupCommand: "rea setup reverse mitmproxy",
		postInstallInvocation: "mitmproxy -p 8080 or mitmdump -s filter.py",
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
};

export function resolveReverseCapabilities(options: ResolveCapabilitiesOptions = {}): ReverseCapabilityStatus[] {
	const platform =
		options.platform ??
		(process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux");
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

	for (const cap of Object.values(CAPABILITY_CATALOG)) {
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
				const isReady = prereqsReady && isConfigured && isEnabled && isConnected;

				const toolStatus: "ready" | "configured" | "unconfigured" | "missing" =
					isReady
						? "ready"
						: !prereqsReady
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

		let status: "ready" | "available_with_fallbacks" | "missing";
		if (hasInstalledTool) {
			status = "ready";
		} else if (availableFallbacks.length > 0 || cap.recommendedNativeTool) {
			status = "available_with_fallbacks";
		} else {
			status = "missing";
		}

		results.push({
			id: cap.id,
			name: cap.name,
			category: cap.category,
			scenario: cap.scenario,
			description: cap.description,
			why: cap.why,
			status,
			ready: hasInstalledTool,
			recommendedNativeTool: cap.recommendedNativeTool,
			optionalExternalTools: toolRefs,
			prerequisites: cap.prerequisites,
			fallbacks: cap.fallbacks,
			availableFallbacks,
			setupCommand: cap.setupCommand,
			postInstallInvocation: cap.postInstallInvocation,
		});
	}

	return results;
}

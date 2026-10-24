/**
 * Local IDA Pro install detection. IDA features (`read` views, the `ida` tool) are only
 * exposed when {@link cfgIdaAvailable} finds an install shipping idalib.
 *
 * Detection is synchronous because tool gating and prompt rendering are synchronous; it runs
 * once per settings input change (memoized by the registry), never per call.
 */
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { $env, $which, getMCPConfigPath, getProjectDir, logger, type WhichOptions } from "@reverse/utils";
import { combine } from "../config/registry";
import type { Settings } from "../config/settings";
import { cfgIdaEnabled, cfgIdaInstallDir } from "./settings";

export interface LocateIdaOptions {
	env?: Record<string, string | undefined>;
	platform?: NodeJS.Platform;
	which?: (cmd: string, options?: WhichOptions) => string | null;
	requireIdalib?: boolean;
	settings?: Settings;
	installDir?: string;
}
const IDA_BINARIES: Record<string, readonly string[]> = {
	win32: ["ida.exe", "idat.exe", "ida64.exe", "idat64.exe", "idaq.exe", "idaq64.exe", "idalib.dll"],
	darwin: ["ida", "ida64", "idat", "idat64", "libidalib.dylib"],
	linux: ["ida", "ida64", "idat", "idat64", "libidalib.so"],
};

const IDA_GUI_BINARIES: Record<string, readonly string[]> = {
	win32: ["ida.exe", "idat.exe", "ida64.exe", "idat64.exe", "idaq.exe", "idaq64.exe"],
	darwin: ["ida", "ida64", "idat", "idat64"],
	linux: ["ida", "ida64", "idat", "idat64"],
};

export function hasIdaGuiBinary(dir: string, platform: NodeJS.Platform = process.platform): boolean {
	const bins = IDA_GUI_BINARIES[platform] ?? IDA_GUI_BINARIES.linux;
	for (const b of bins) {
		try {
			const candidate = path.join(dir, b);
			if (fs.existsSync(candidate) && !fs.statSync(candidate).isDirectory()) {
				return true;
			}
		} catch {}
	}
	return false;
}
export function hasIdalib(dir: string, platform: NodeJS.Platform = process.platform): boolean {
	const idalib = platform === "darwin" ? "libidalib.dylib" : platform === "win32" ? "idalib.dll" : "libidalib.so";
	return fs.existsSync(path.join(dir, idalib));
}

export function hasIdaBinary(dir: string, platform: NodeJS.Platform = process.platform): boolean {
	const bins = IDA_BINARIES[platform] ?? IDA_BINARIES.linux;
	for (const b of bins) {
		try {
			const candidate = path.join(dir, b);
			if (fs.existsSync(candidate) && !fs.statSync(candidate).isDirectory()) {
				return true;
			}
		} catch {}
	}
	return false;
}

let memoizedRegistryDirs: string[] | null = null;

export function readRegistryIdaDirs(): string[] {
	if (process.platform !== "win32") return [];
	if (memoizedRegistryDirs !== null) return memoizedRegistryDirs;
	const dirs: string[] = [];
	const regQueries = [
		["query", "HKCU\\Software\\Hex-Rays\\IDA Pro", "/v", "InstallDir"],
		["query", "HKLM\\Software\\Hex-Rays\\IDA Pro", "/v", "InstallDir"],
		["query", "HKLM\\Software\\WOW6432Node\\Hex-Rays\\IDA Pro", "/v", "InstallDir"],
		["query", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\ida.exe"],
		["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\ida.exe"],
		["query", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IDA Pro_is1", "/v", "InstallLocation"],
		["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IDA Pro_is1", "/v", "InstallLocation"],
	];
	for (const args of regQueries) {
		try {
			const res = execFileSync("reg.exe", args, {
				encoding: "utf8",
				timeout: 1000,
				stdio: ["ignore", "pipe", "ignore"],
			});
			for (const line of res.split(/\r?\n/)) {
				const match = line.match(/(?:InstallDir|InstallLocation|Path|\(Default\))\s+REG_\w+\s+([^\r\n]+)/i);
				if (match && match[1]) {
					let candidate = match[1].trim().replace(/^["']+|["']+$/g, "");
					if (candidate.toLowerCase().endsWith(".exe") || candidate.toLowerCase().endsWith(".bat")) {
						candidate = path.dirname(candidate);
					}
					if (candidate && !dirs.includes(candidate)) {
						dirs.push(candidate);
					}
				}
			}
		} catch {}
	}
	memoizedRegistryDirs = dirs;
	return dirs;
}

/** `Paths.ida-install-dir` from each `ida-config.json` idalib itself would consult, in order. */
function configuredInstallDirs(
	env: Record<string, string | undefined> = process.env,
	platform: NodeJS.Platform = process.platform,
): string[] {
	const idausr = env.IDAUSR ?? $env.IDAUSR ?? "";
	const userDirs = idausr.split(path.delimiter).filter(Boolean);
	const homedir = env.HOME ?? env.USERPROFILE ?? os.homedir();
	userDirs.push(
		platform === "win32"
			? path.join(env.APPDATA ?? path.join(homedir, "AppData", "Roaming"), "Hex-Rays", "IDA Pro")
			: path.join(homedir, ".idapro"),
	);
	const dirs: string[] = [];
	for (const userDir of userDirs) {
		try {
			const config: { Paths?: { "ida-install-dir"?: unknown } } = JSON.parse(
				fs.readFileSync(path.join(userDir, "ida-config.json"), "utf8"),
			);
			const dir = config.Paths?.["ida-install-dir"];
			if (typeof dir === "string" && dir) dirs.push(dir);
		} catch {
			// Missing or malformed config: idalib ignores it too.
		}
	}
	return dirs;
}

/** Children of `parent` whose names start with `prefix` (case-insensitive), newest version first. */
function childDirs(parent: string, prefix: string, suffix = ""): string[] {
	let names: string[];
	try {
		names = fs.readdirSync(parent);
	} catch {
		return [];
	}
	return names
		.filter(name => name.toLowerCase().startsWith(prefix))
		.sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
		.map(name => path.join(parent, name, suffix));
}

/** Standard install locations per platform across drives. */
function defaultInstallDirs(
	platform: NodeJS.Platform = process.platform,
	env: Record<string, string | undefined> = process.env,
): string[] {
	switch (platform) {
		case "darwin":
			return [
				...childDirs("/Applications", "ida", "Contents/MacOS"),
				...childDirs(path.join(os.homedir(), "Applications"), "ida", "Contents/MacOS"),
			];
		case "win32": {
			const dirs: string[] = [];
			const progFiles = [
				env.ProgramFiles ?? "C:\\Program Files",
				env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)",
				env.ProgramW6432,
				"D:\\Program Files",
				"D:\\Program Files (x86)",
				"E:\\Program Files",
				"E:\\Program Files (x86)",
			].filter((d): d is string => typeof d === "string" && Boolean(d));

			for (const pf of progFiles) {
				dirs.push(...childDirs(pf, "ida"));
			}
			for (const drive of ["C:\\", "D:\\", "E:\\"]) {
				dirs.push(...childDirs(drive, "ida"));
			}
			if (env.LOCALAPPDATA) {
				dirs.push(...childDirs(path.join(env.LOCALAPPDATA, "Programs"), "ida"));
			}
			return dirs;
		}
		default:
			return [...childDirs(os.homedir(), "ida"), ...childDirs("/opt", "ida")];
	}
}

/**
 * Directory of a local IDA install that ships idalib, or undefined when none exists.
 * An explicit `configured` directory is authoritative: when it lacks idalib, nothing else is tried.
 * Otherwise checks `$IDADIR`, `ida-config.json`, then standard install locations.
 */
export function locateIdaInstall(configured?: string, options: LocateIdaOptions = {}): string | undefined {
	const targetPlatform = options.platform ?? process.platform;
	const env = options.env ?? process.env;
	const requireIdalib = options.requireIdalib ?? false;

	let effectiveConfigured = configured?.trim() || undefined;
	if (!effectiveConfigured && options.settings) {
		effectiveConfigured = cfgIdaInstallDir.get(options.settings)?.trim() || undefined;
	}

	if (effectiveConfigured) {
		if (hasIdalib(effectiveConfigured, targetPlatform)) {
			return effectiveConfigured;
		}
		if (!requireIdalib && hasIdaBinary(effectiveConfigured, targetPlatform)) {
			return effectiveConfigured;
		}
		logger.warn("ida.installDir has no idalib; IDA features stay hidden", {
			installDir: effectiveConfigured,
		});
		return undefined;
	}

	const whichFn = options.which ?? $which;
	const pathDirs: string[] = [];
	const bins =
		targetPlatform === "win32"
			? ["ida.exe", "ida", "ida64.exe", "ida64", "idat.exe", "idat"]
			: ["ida", "ida64", "idat"];
	for (const b of bins) {
		try {
			const found = whichFn(b);
			if (found && fs.existsSync(found)) {
				pathDirs.push(path.dirname(found));
				if (found.endsWith(".bat") || found.endsWith(".cmd")) {
					try {
						const content = fs.readFileSync(found, "utf8");
						const match =
							content.match(/"([^"]*ida(?:64|t|t64|q|q64)?\.exe)"/i) ||
							content.match(/([A-Za-z]:\\[^"'\r\n;]*ida(?:64|t|t64|q|q64)?\.exe)/i);
						if (match && match[1]) {
							const targetDir = path.dirname(match[1].trim());
							if (!pathDirs.includes(targetDir)) pathDirs.push(targetDir);
						}
					} catch {}
				}
				try {
					const real = fs.realpathSync(found);
					const realDir = path.dirname(real);
					if (!pathDirs.includes(realDir)) pathDirs.push(realDir);
				} catch {}
			}
		} catch {}
	}

	const registryDirs = targetPlatform === "win32" ? readRegistryIdaDirs() : [];
	const candidates = [
		options.env?.IDADIR ?? $env.IDADIR,
		...configuredInstallDirs(env, targetPlatform),
		...registryDirs,
		...pathDirs,
		...defaultInstallDirs(targetPlatform, env),
	].filter((dir): dir is string => typeof dir === "string" && dir.length > 0 && fs.existsSync(dir));

	const withIdalib = candidates.find(dir => hasIdalib(dir, targetPlatform));
	if (withIdalib) return withIdalib;

	if (requireIdalib) return undefined;

	return candidates.find(dir => hasIdaBinary(dir, targetPlatform));
}

/**
 * Probe IDA tool presence for the skill tool catalog (setup reverse / CLI).
 * First checks for an idalib-enabled installation via {@link locateIdaInstall}.
 * If absent, checks whether IDA GUI/CLI executables exist in candidate install paths
 * or on PATH via launcher scripts (e.g. ida.bat / ida.exe).
 */
export function probeIdaTool(options: LocateIdaOptions = {}): string | null {
	const idalibInstall = locateIdaInstall(undefined, options);
	if (idalibInstall) return idalibInstall;

	const targetPlatform = options.platform ?? process.platform;
	const env = options.env ?? process.env;

	if (options.which) {
		const bins =
			targetPlatform === "win32"
				? ["ida.exe", "ida", "ida64.exe", "ida64", "idat.exe", "idat"]
				: ["ida", "ida64", "idat"];
		for (const b of bins) {
			const found = options.which(b);
			if (found && fs.existsSync(found)) {
				return found;
			}
		}
	}

	const registryDirs = targetPlatform === "win32" ? readRegistryIdaDirs() : [];
	const candidates = [
		options.env?.IDADIR ?? $env.IDADIR,
		...configuredInstallDirs(env, targetPlatform),
		...registryDirs,
		...defaultInstallDirs(targetPlatform, env),
	].filter((dir): dir is string => typeof dir === "string" && dir.length > 0 && fs.existsSync(dir));

	return candidates.find(dir => hasIdaBinary(dir, targetPlatform)) ?? null;
}

/** IDA install directory when `ida.enabled` is on and an install is found; undefined otherwise. */
export const cfgIdaInstall = combine(
	{ enabled: cfgIdaEnabled, installDir: cfgIdaInstallDir },
	({ enabled, installDir }) =>
		enabled ? locateIdaInstall(installDir?.trim() || undefined, { requireIdalib: true }) : undefined,
);

/** Whether IDA features (`read` views, the `ida` tool) are exposed. */
export const cfgIdaAvailable = cfgIdaInstall.map(dir => dir !== undefined);

export interface IdaBackendStatus {
	guiAvailable: boolean;
	guiPath?: string;
	idalibAvailable: boolean;
	idalibPath?: string;
	localDatabaseRecognized: boolean;
	localDatabaseBackendAvailable: boolean;
	localDatabaseSupported: boolean;
	mcpBridgeConfigured: boolean;
	mcpBridgeConnected: boolean;
	bridgeAbsentReason?: string;
}

export function getIdaBackendStatus(
	options: LocateIdaOptions & {
		mcpManager?: {
			getConnectionStatus(name: string): string;
			getAllServerNames(): string[];
		};
		cwd?: string;
		agentDir?: string;
		readMcpConfig?: (path: string) => unknown;
	} = {},
): IdaBackendStatus {
	const targetPlatform = options.platform ?? process.platform;
	const idalibPath = locateIdaInstall(options.installDir, { ...options, requireIdalib: true });
	const idalibAvailable = Boolean(idalibPath);

	const rawGuiCandidate =
		locateIdaInstall(options.installDir, { ...options, requireIdalib: false }) ??
		(options.installDir ? undefined : probeIdaTool(options));
	const guiPath = rawGuiCandidate && hasIdaGuiBinary(rawGuiCandidate, targetPlatform) ? rawGuiCandidate : undefined;
	const guiAvailable = Boolean(guiPath);

	const localDatabaseRecognized = true;
	const localDatabaseBackendAvailable = idalibAvailable;
	const localDatabaseSupported = idalibAvailable;

	let mcpBridgeConfigured = false;
	let mcpBridgeConnected = false;

	if (options.mcpManager) {
		const allNames = options.mcpManager.getAllServerNames();
		const matchedName = allNames.find(n => n.toLowerCase() === "ida-mcp" || n.toLowerCase() === "ida");
		if (matchedName) {
			mcpBridgeConfigured = true;
			mcpBridgeConnected = options.mcpManager.getConnectionStatus(matchedName) === "connected";
		}
	}

	if (!mcpBridgeConfigured) {
		try {
			const cwd = options.cwd ?? getProjectDir();
			const userConfigPath = options.agentDir
				? path.join(options.agentDir, "mcp.json")
				: getMCPConfigPath("user", cwd);
			const configPaths = [getMCPConfigPath("project", cwd), userConfigPath];
			const readFn =
				options.readMcpConfig ??
				(p => {
					try {
						return JSON.parse(fs.readFileSync(p, "utf8"));
					} catch {
						return null;
					}
				});
			for (const p of configPaths) {
				const cfg = readFn(p) as { mcpServers?: Record<string, unknown> } | null;
				if (cfg?.mcpServers && (cfg.mcpServers["ida-mcp"] || cfg.mcpServers["ida"])) {
					mcpBridgeConfigured = true;
					break;
				}
			}
		} catch {}
	}

	let bridgeAbsentReason: string | undefined;
	if (!mcpBridgeConfigured) {
		bridgeAbsentReason =
			"Direct MCP bridge 'ida-mcp' is not configured in mcp.json; IDA GUI and idalib operate independently when installed.";
	} else if (!mcpBridgeConnected) {
		bridgeAbsentReason = "Direct MCP bridge 'ida-mcp' is configured but not connected to an active IDA session.";
	}

	return {
		guiAvailable,
		guiPath,
		idalibAvailable,
		idalibPath: idalibPath ?? undefined,
		localDatabaseRecognized,
		localDatabaseBackendAvailable,
		localDatabaseSupported,
		mcpBridgeConfigured,
		mcpBridgeConnected,
		...(bridgeAbsentReason ? { bridgeAbsentReason } : {}),
	};
}

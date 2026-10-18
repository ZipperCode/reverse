import * as fs from "node:fs/promises";
import type { Dirent, Stats } from "node:fs";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@rva/agent";
import { type } from "@rva/omptype";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { isReadableUrlPath } from "@rva/tui/tools/read";
import { archiveFormatFromPath, openArchive, sniffArchiveFormat, type ArchiveReader } from "@rva/utils/ar";
import { formatBytes, prompt } from "@rva/utils";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import javascriptApplicationDescription from "../prompts/tools/javascript-application.md" with { type: "text" };

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 500;
const DEFAULT_MAX_FILES = 200;
const MAX_FILES_LIMIT = 2000;
const MAX_DIRECTORY_DEPTH = 15;
const MAX_FILE_SCAN_BYTES = 5 * 1024 * 1024;

const javascriptApplicationSchema = type({
	"path?": type("string").describe("Path to target JavaScript / Electron directory, .asar archive, or .zip container"),
	"target?": type("string").describe("Target path (alias for path)"),
	"limit?": type("number.integer >= 1").describe(
		"Maximum items per list to display (modules, IPC channels, native addons) (default 50, max 500)",
	),
	"max_files?": type("number.integer >= 1").describe(
		"Maximum JavaScript/TypeScript files to analyze (default 200, max 2000)",
	),
	"include_node_modules?": type("boolean").describe(
		"Whether to include node_modules in module inventory and static analysis (default false)",
	),
	"channel_filter?": type("string").describe("Optional substring filter for IPC channel names"),
});

export type JavascriptApplicationParams = typeof javascriptApplicationSchema.infer;

export interface PackageJsonSummary {
	filePath: string;
	name?: string;
	version?: string;
	description?: string;
	main?: string;
	module?: string;
	type?: string;
	electronVersion?: string;
	scripts?: Record<string, string>;
	dependencies?: Record<string, string>;
	devDependencies?: Record<string, string>;
	build?: Record<string, unknown>;
}

export interface ElectronRoleClassification {
	mainProcessFiles: string[];
	preloadFiles: string[];
	rendererFiles: string[];
}

export interface IpcChannelOccurrence {
	channel: string;
	direction: "send" | "sendSync" | "invoke" | "postMessage" | "on" | "once" | "handle" | "handleOnce" | "other";
	api: string;
	file: string;
	line: number;
}

export interface NativeAddonInfo {
	name: string;
	path: string;
	kind: "binary" | "reference";
	size?: number;
}

export interface SecurityIndicator {
	rule: string;
	description: string;
	file: string;
	line: number;
	snippet?: string;
}

export interface JavascriptApplicationDetails {
	path: string;
	targetType: "directory" | "asar" | "zip" | "archive";
	fileCount: number;
	totalSizeBytes: number;
	packageJson?: PackageJsonSummary;
	electronVersion?: string;
	roles: ElectronRoleClassification;
	modules: {
		totalJsFiles: number;
		analyzedJsFiles: number;
		entrypoints: string[];
		topImports: Array<{ module: string; count: number }>;
	};
	ipcChannels: IpcChannelOccurrence[];
	totalIpcChannels: number;
	nativeAddons: NativeAddonInfo[];
	securityIndicators: SecurityIndicator[];
	truncated?: boolean;
}

interface DiscoveredFile {
	path: string;
	size: number;
	readText: () => Promise<string>;
}

function isUrlLike(value: string): boolean {
	return (
		/^https?:\/\//i.test(value) ||
		/^www\./i.test(value) ||
		/^(?:ftp|file|ws|wss):\/\//i.test(value) ||
		isReadableUrlPath(value)
	);
}

function getLineNumber(text: string, index: number): number {
	let line = 1;
	for (let i = 0; i < index; i++) {
		if (text.charCodeAt(i) === 10) line++;
	}
	return line;
}

async function collectDirectoryFiles(
	baseDir: string,
	includeNodeModules: boolean,
	maxDepth: number,
	signal?: AbortSignal,
): Promise<{ files: DiscoveredFile[]; totalFiles: number; totalSizeBytes: number }> {
	const files: DiscoveredFile[] = [];
	let totalFiles = 0;
	let totalSizeBytes = 0;

	async function walk(currentDir: string, relPrefix: string, depth: number) {
		throwIfAborted(signal);
		if (depth > maxDepth) return;

		let entries: Dirent[];
		try {
			entries = await fs.readdir(currentDir, { withFileTypes: true });
		} catch {
			return;
		}

		for (const entry of entries) {
			throwIfAborted(signal);
			const relPath = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
			const fullPath = path.join(currentDir, entry.name);

			if (entry.isDirectory()) {
				if (!includeNodeModules && entry.name === "node_modules") continue;
				if (entry.name === ".git" || entry.name === ".svn" || entry.name === ".hg") continue;
				await walk(fullPath, relPath, depth + 1);
			} else if (entry.isFile() || entry.isSymbolicLink()) {
				let size = 0;
				try {
					const s = await fs.stat(fullPath);
					if (!s.isFile()) continue;
					size = s.size;
				} catch {
					continue;
				}
				totalFiles++;
				totalSizeBytes += size;
				files.push({
					path: relPath,
					size,
					readText: async () => {
						const content = await fs.readFile(fullPath);
						return new TextDecoder("utf-8", { fatal: false }).decode(content);
					},
				});
			}
		}
	}

	await walk(baseDir, "", 0);
	return { files, totalFiles, totalSizeBytes };
}

async function collectArchiveFiles(
	reader: ArchiveReader,
	includeNodeModules: boolean,
	signal?: AbortSignal,
): Promise<{ files: DiscoveredFile[]; totalFiles: number; totalSizeBytes: number }> {
	const files: DiscoveredFile[] = [];
	let totalFiles = 0;
	let totalSizeBytes = 0;

	for (const entry of reader.indexEntries()) {
		throwIfAborted(signal);
		if (entry.isDirectory) continue;
		const normPath = entry.path.replace(/\\/g, "/");
		const segments = normPath.split("/");
		if (!includeNodeModules && segments.includes("node_modules")) {
			totalFiles++;
			totalSizeBytes += entry.size;
			continue;
		}
		totalFiles++;
		totalSizeBytes += entry.size;
		files.push({
			path: normPath,
			size: entry.size,
			readText: async () => {
				const extracted = await reader.readFile(entry.path);
				return new TextDecoder("utf-8", { fatal: false }).decode(extracted.bytes);
			},
		});
	}

	return { files, totalFiles, totalSizeBytes };
}

const IPC_CALL_REGEX =
	/\b(ipcRenderer|ipcMain|webContents|event\.sender|event)\s*\.\s*(send|sendSync|sendTo|sendToHost|invoke|postMessage|on|once|handle|handleOnce|reply)\s*\(\s*(['"`])([^'"`\r\n\t]+)\3/g;

const CONTEXT_BRIDGE_REGEX =
	/\bcontextBridge\s*\.\s*exposeInMainWorld\s*\(\s*(['"`])([^'"`\r\n\t]+)\1/g;

const NODE_ADDON_REQUIRE_REGEX =
	/(?:require\s*\(\s*|import\s*(?:[^{}]*?from\s+)?)(['"])([^'"]+?\.node)\1/g;

const BINDINGS_REGEX = /\b(?:bindings|node-gyp-build)\s*\(\s*(['"])([^'"]+)\1\s*\)/g;
const REQUIRE_BINDINGS_REGEX = /\brequire\s*\(\s*(['"])bindings\1\s*\)\s*\(\s*(['"])([^'"]+)\2\s*\)/g;

const IMPORT_REQUIRE_REGEX =
	/\b(?:require\s*\(\s*|import\s*(?:[^{}]*?from\s+)?|export\s*(?:[^{}]*?from\s+)?)(['"])([@\w\d_./-]+)\1/g;

interface SecurityRule {
	name: string;
	regex: RegExp;
	description: string;
}

const SECURITY_RULES: SecurityRule[] = [
	{
		name: "nodeIntegration",
		regex: /\bnodeIntegration\s*:\s*true\b/g,
		description: "Node.js integration enabled in renderer process",
	},
	{
		name: "contextIsolationDisabled",
		regex: /\bcontextIsolation\s*:\s*false\b/g,
		description: "Context isolation explicitly disabled in BrowserWindow",
	},
	{
		name: "enableRemoteModule",
		regex: /\benableRemoteModule\s*:\s*true\b/g,
		description: "Deprecated remote module enabled in webPreferences",
	},
	{
		name: "webSecurityDisabled",
		regex: /\bwebSecurity\s*:\s*false\b/g,
		description: "Same-origin policy disabled via webSecurity: false",
	},
	{
		name: "allowRunningInsecureContent",
		regex: /\ballowRunningInsecureContent\s*:\s*true\b/g,
		description: "Insecure mixed content allowed in HTTPS context",
	},
	{
		name: "shellOpenExternal",
		regex: /\b(?:shell\s*\.\s*)?openExternal\s*\(/g,
		description: "shell.openExternal call (auditable for arbitrary protocol/URL injection)",
	},
];

const JS_EXTENSIONS: Record<string, true> = {
	".js": true,
	".mjs": true,
	".cjs": true,
	".jsx": true,
	".ts": true,
	".mts": true,
	".cts": true,
	".tsx": true,
};

function getPriorityScore(filePath: string, mainPath?: string): number {
	const norm = filePath.toLowerCase();
	if (mainPath && (filePath === mainPath || filePath.endsWith(`/${mainPath}`))) return 0;
	if (norm.includes("main")) return 1;
	if (norm.includes("preload")) return 2;
	if (norm.includes("renderer")) return 3;
	if (norm.includes("index.")) return 4;
	return 5;
}

function renderApplicationReport(
	details: JavascriptApplicationDetails,
	requestedPath: string,
	limit: number,
): string {
	const lines: string[] = [];
	const sizeStr = formatBytes(details.totalSizeBytes);
	lines.push(
		`JavaScript Application: ${requestedPath} (${details.targetType}, ${details.fileCount} file${details.fileCount === 1 ? "" : "s"}, ${sizeStr})`,
	);

	if (details.packageJson) {
		const pkg = details.packageJson;
		const namePart = pkg.name ? `${pkg.name}${pkg.version ? ` v${pkg.version}` : ""}` : "Unnamed package";
		const electronPart = details.electronVersion ? ` [Electron: ${details.electronVersion}]` : "";
		lines.push(`Package: ${namePart}${electronPart}`);
		if (pkg.description) {
			lines.push(`Description: ${pkg.description}`);
		}
		if (pkg.main) {
			lines.push(`Main Entrypoint: ${pkg.main}`);
		}
	} else {
		lines.push("Package: No package.json found");
	}

	lines.push("\nElectron Roles:");
	const mainList =
		details.roles.mainProcessFiles.length > 0
			? details.roles.mainProcessFiles.slice(0, 5).join(", ") +
				(details.roles.mainProcessFiles.length > 5 ? ` (+${details.roles.mainProcessFiles.length - 5} more)` : "")
			: "None identified";
	const preloadList =
		details.roles.preloadFiles.length > 0
			? details.roles.preloadFiles.slice(0, 5).join(", ") +
				(details.roles.preloadFiles.length > 5 ? ` (+${details.roles.preloadFiles.length - 5} more)` : "")
			: "None identified";
	const rendererList =
		details.roles.rendererFiles.length > 0
			? details.roles.rendererFiles.slice(0, 5).join(", ") +
				(details.roles.rendererFiles.length > 5 ? ` (+${details.roles.rendererFiles.length - 5} more)` : "")
			: "None identified";

	lines.push(`  Main Process: ${mainList}`);
	lines.push(`  Preload:      ${preloadList}`);
	lines.push(`  Renderer:     ${rendererList}`);

	lines.push(`\nIPC Channels (${details.totalIpcChannels} found):`);
	if (details.ipcChannels.length === 0) {
		lines.push("  None detected");
	} else {
		for (const item of details.ipcChannels.slice(0, limit)) {
			lines.push(`  - "${item.channel}" (${item.api} @ ${item.file}:${item.line})`);
		}
		if (details.totalIpcChannels > limit) {
			lines.push(`  … ${details.totalIpcChannels - limit} more IPC channel calls; raise limit to view more.`);
		}
	}

	const totalAddons = details.nativeAddons.length;
	lines.push(`\nNative Addons (${totalAddons} found):`);
	if (totalAddons === 0) {
		lines.push("  None detected");
	} else {
		for (const addon of details.nativeAddons.slice(0, limit)) {
			const sizePart = addon.size !== undefined ? ` (${formatBytes(addon.size)})` : "";
			lines.push(`  - ${addon.name}: ${addon.path}${sizePart} [${addon.kind}]`);
		}
		if (totalAddons > limit) {
			lines.push(`  … ${totalAddons - limit} more native addon references; raise limit to view more.`);
		}
	}

	if (details.modules.topImports.length > 0) {
		lines.push("\nTop External Imports:");
		const top = details.modules.topImports
			.slice(0, 10)
			.map(t => `${t.module} (${t.count})`)
			.join(", ");
		lines.push(`  ${top}`);
	}

	if (details.securityIndicators.length > 0) {
		lines.push(`\nSecurity Indicators (${details.securityIndicators.length} detected):`);
		for (const sec of details.securityIndicators.slice(0, limit)) {
			lines.push(`  - [${sec.rule}] ${sec.file}:${sec.line} — ${sec.description}`);
			if (sec.snippet) {
				lines.push(`    \`${sec.snippet}\``);
			}
		}
		if (details.securityIndicators.length > limit) {
			lines.push(`  … ${details.securityIndicators.length - limit} more security indicators.`);
		}
	}

	return lines.join("\n");
}

export class JavascriptApplicationTool
	implements AgentTool<typeof javascriptApplicationSchema, JavascriptApplicationDetails>
{
	readonly name = "javascript_application";
	readonly approval: ToolTier = "read";
	readonly label = "JavaScript Application";
	readonly summary =
		"Static inspection of JavaScript, Electron, and ASAR applications (package metadata, IPC channels, roles, native addons)";
	readonly description: string;
	readonly parameters = javascriptApplicationSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(javascriptApplicationDescription);
	}

	async execute(
		_toolCallId: string,
		params: JavascriptApplicationParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<JavascriptApplicationDetails>> {
		throwIfAborted(signal);
		const requestedPath = params.path?.trim() || params.target?.trim() || "";
		if (!requestedPath) {
			throw new ToolError("path or target is required");
		}

		if (isUrlLike(requestedPath)) {
			throw new ToolError(
				`URL targets are not supported; provide a local directory, .asar, or .zip archive path: ${requestedPath}`,
			);
		}

		const absolutePath = resolveReadPath(requestedPath, this.session.cwd);

		let fileStat: Stats;
		try {
			fileStat = await fs.stat(absolutePath);
		} catch {
			throw new ToolError(`Target not found: ${requestedPath}`);
		}

		if (!fileStat.isDirectory() && !fileStat.isFile()) {
			throw new ToolError(`Target is neither a regular file nor a directory: ${requestedPath}`);
		}

		const limit = Math.min(MAX_LIST_LIMIT, Math.max(1, Math.floor(params.limit ?? DEFAULT_LIST_LIMIT)));
		const maxFiles = Math.min(
			MAX_FILES_LIMIT,
			Math.max(1, Math.floor(params.max_files ?? DEFAULT_MAX_FILES)),
		);
		const includeNodeModules = params.include_node_modules === true;
		const channelFilter = params.channel_filter?.trim() || undefined;

		let targetType: "directory" | "asar" | "zip" | "archive" = "archive";
		let collected: { files: DiscoveredFile[]; totalFiles: number; totalSizeBytes: number };

		if (fileStat.isDirectory()) {
			targetType = "directory";
			collected = await collectDirectoryFiles(absolutePath, includeNodeModules, MAX_DIRECTORY_DEPTH, signal);
		} else {
			const format = archiveFormatFromPath(absolutePath);
			let reader: ArchiveReader;
			if (format === "asar" || format === "zip") {
				targetType = format;
				try {
					reader = await openArchive(absolutePath);
				} catch (err) {
					throw new ToolError(
						`Failed to open archive ${requestedPath}: ${err instanceof Error ? err.message : String(err)}`,
					);
				}
			} else {
				let head = Buffer.alloc(512);
				let bytesRead = 0;
				try {
					const fh = await fs.open(absolutePath, "r");
					try {
						const res = await fh.read(head, 0, 512, 0);
						bytesRead = res.bytesRead;
					} finally {
						await fh.close();
					}
				} catch (err) {
					throw new ToolError(
						`Failed to read file ${requestedPath}: ${err instanceof Error ? err.message : String(err)}`,
					);
				}
				const sniffed = sniffArchiveFormat(head.subarray(0, bytesRead));
				if (sniffed === "asar" || sniffed === "zip") {
					targetType = sniffed;
					try {
						reader = await openArchive({ path: absolutePath, format: sniffed });
					} catch (err) {
						throw new ToolError(
							`Failed to open archive ${requestedPath}: ${err instanceof Error ? err.message : String(err)}`,
						);
					}
				} else {
					throw new ToolError(
						`Target file is not a supported JavaScript application archive (.asar, .zip): ${requestedPath}`,
					);
				}
			}
			collected = await collectArchiveFiles(reader, includeNodeModules, signal);
		}

		throwIfAborted(signal);

		const { files, totalFiles, totalSizeBytes } = collected;

		const packageJsonFiles = files.filter(f => f.path === "package.json" || f.path.endsWith("/package.json"));
		packageJsonFiles.sort((a, b) => a.path.split("/").length - b.path.split("/").length);

		let packageJsonSummary: PackageJsonSummary | undefined;
		let electronVersion: string | undefined;

		if (packageJsonFiles.length > 0) {
			try {
				const raw = await packageJsonFiles[0].readText();
				const parsed = JSON.parse(raw);
				if (typeof parsed === "object" && parsed !== null) {
					electronVersion =
						(typeof parsed.dependencies?.electron === "string" ? parsed.dependencies.electron : undefined) ??
						(typeof parsed.devDependencies?.electron === "string" ? parsed.devDependencies.electron : undefined) ??
						(typeof parsed.build?.electronVersion === "string" ? parsed.build.electronVersion : undefined);

					packageJsonSummary = {
						filePath: packageJsonFiles[0].path,
						name: typeof parsed.name === "string" ? parsed.name : undefined,
						version: typeof parsed.version === "string" ? parsed.version : undefined,
						description: typeof parsed.description === "string" ? parsed.description : undefined,
						main: typeof parsed.main === "string" ? parsed.main : undefined,
						module: typeof parsed.module === "string" ? parsed.module : undefined,
						type: typeof parsed.type === "string" ? parsed.type : undefined,
						electronVersion,
						scripts:
							typeof parsed.scripts === "object" && parsed.scripts !== null ? parsed.scripts : undefined,
						dependencies:
							typeof parsed.dependencies === "object" && parsed.dependencies !== null
								? parsed.dependencies
								: undefined,
						devDependencies:
							typeof parsed.devDependencies === "object" && parsed.devDependencies !== null
								? parsed.devDependencies
								: undefined,
						build:
							typeof parsed.build === "object" && parsed.build !== null ? parsed.build : undefined,
					};
				}
			} catch {
				// Malformed package.json ignored gracefully
			}
		}

		const nativeAddons: NativeAddonInfo[] = [];
		for (const file of files) {
			if (file.path.toLowerCase().endsWith(".node")) {
				const name = path.posix.basename(file.path);
				nativeAddons.push({
					name,
					path: file.path,
					kind: "binary",
					size: file.size,
				});
			}
		}

		const allJsFiles = files.filter(f => {
			const ext = path.posix.extname(f.path).toLowerCase();
			return ext in JS_EXTENSIONS;
		});
		const htmlFiles = files.filter(f => f.path.toLowerCase().endsWith(".html"));

		const prioritizedJsFiles = [...allJsFiles].sort((a, b) => {
			const scoreA = getPriorityScore(a.path, packageJsonSummary?.main);
			const scoreB = getPriorityScore(b.path, packageJsonSummary?.main);
			if (scoreA !== scoreB) return scoreA - scoreB;
			return a.path.localeCompare(b.path);
		});

		const filesToAnalyze = prioritizedJsFiles.slice(0, maxFiles);

		const roles: ElectronRoleClassification = {
			mainProcessFiles: [],
			preloadFiles: [],
			rendererFiles: [],
		};

		for (const html of htmlFiles) {
			roles.rendererFiles.push(html.path);
		}

		const ipcOccurrences: IpcChannelOccurrence[] = [];
		const externalImportCounts = new Map<string, number>();
		const securityIndicators: SecurityIndicator[] = [];

		for (const file of filesToAnalyze) {
			throwIfAborted(signal);
			if (file.size > MAX_FILE_SCAN_BYTES) continue;
			let text = "";
			try {
				text = await file.readText();
			} catch {
				continue;
			}

			// Roles
			const isMainByPkg =
				packageJsonSummary?.main &&
				(file.path === packageJsonSummary.main || file.path.endsWith(`/${packageJsonSummary.main}`));
			const hasElectronMainApis =
				/\b(?:app|BrowserWindow|ipcMain|autoUpdater|powerMonitor|Tray|Menu)\b/.test(text) &&
				/\b(?:electron|@electron\/remote\/main)\b/.test(text);

			if (isMainByPkg || hasElectronMainApis) {
				if (!roles.mainProcessFiles.includes(file.path)) {
					roles.mainProcessFiles.push(file.path);
				}
			}

			const isPreloadByPath = file.path.toLowerCase().includes("preload");
			const hasContextBridge = /\bcontextBridge\b/.test(text);
			if (isPreloadByPath || hasContextBridge) {
				if (!roles.preloadFiles.includes(file.path)) {
					roles.preloadFiles.push(file.path);
				}
			}

			const isRendererByPath = file.path.toLowerCase().includes("renderer");
			const hasRendererDom = /\b(?:document\.getElementById|window\.addEventListener|ReactDOM|createRoot)\b/.test(
				text,
			);
			const hasIpcRendererWithoutBridge = /\bipcRenderer\b/.test(text) && !hasContextBridge;

			if (isRendererByPath || hasRendererDom || hasIpcRendererWithoutBridge) {
				if (!roles.rendererFiles.includes(file.path)) {
					roles.rendererFiles.push(file.path);
				}
			}

			// IPC calls
			IPC_CALL_REGEX.lastIndex = 0;
			let match: RegExpExecArray | null;
			while ((match = IPC_CALL_REGEX.exec(text)) !== null) {
				const target = match[1];
				const method = match[2];
				const channel = match[4];

				if (channelFilter && !channel.toLowerCase().includes(channelFilter.toLowerCase())) {
					continue;
				}

				let direction: IpcChannelOccurrence["direction"] = "other";
				if (method === "send" || method === "sendTo" || method === "sendToHost") direction = "send";
				else if (method === "sendSync") direction = "sendSync";
				else if (method === "invoke") direction = "invoke";
				else if (method === "postMessage") direction = "postMessage";
				else if (method === "on") direction = "on";
				else if (method === "once") direction = "once";
				else if (method === "handle") direction = "handle";
				else if (method === "handleOnce") direction = "handleOnce";

				const line = getLineNumber(text, match.index);
				ipcOccurrences.push({
					channel,
					direction,
					api: `${target}.${method}`,
					file: file.path,
					line,
				});
			}

			// contextBridge
			CONTEXT_BRIDGE_REGEX.lastIndex = 0;
			while ((match = CONTEXT_BRIDGE_REGEX.exec(text)) !== null) {
				const exposedName = match[2];
				const line = getLineNumber(text, match.index);
				if (!channelFilter || exposedName.toLowerCase().includes(channelFilter.toLowerCase())) {
					ipcOccurrences.push({
						channel: exposedName,
						direction: "other",
						api: "contextBridge.exposeInMainWorld",
						file: file.path,
						line,
					});
				}
			}

			// Native Addons in code
			NODE_ADDON_REQUIRE_REGEX.lastIndex = 0;
			while ((match = NODE_ADDON_REQUIRE_REGEX.exec(text)) !== null) {
				const addonRef = match[2];
				const name = path.posix.basename(addonRef);
				const line = getLineNumber(text, match.index);
				nativeAddons.push({
					name,
					path: `${file.path}:${line} (${addonRef})`,
					kind: "reference",
				});
			}

			BINDINGS_REGEX.lastIndex = 0;
			while ((match = BINDINGS_REGEX.exec(text)) !== null) {
				const addonName = match[2];
				const line = getLineNumber(text, match.index);
				nativeAddons.push({
					name: addonName,
					path: `${file.path}:${line}`,
					kind: "reference",
				});
			}

			REQUIRE_BINDINGS_REGEX.lastIndex = 0;
			while ((match = REQUIRE_BINDINGS_REGEX.exec(text)) !== null) {
				const addonName = match[3];
				const line = getLineNumber(text, match.index);
				nativeAddons.push({ name: addonName, path: `${file.path}:${line}`, kind: "reference" });
			}

			// External Imports
			IMPORT_REQUIRE_REGEX.lastIndex = 0;
			while ((match = IMPORT_REQUIRE_REGEX.exec(text)) !== null) {
				const spec = match[2];
				if (spec.startsWith(".") || spec.startsWith("/")) continue;
				let pkgName = spec;
				if (spec.startsWith("@")) {
					const parts = spec.split("/");
					if (parts.length >= 2) {
						pkgName = `${parts[0]}/${parts[1]}`;
					}
				} else {
					pkgName = spec.split("/")[0];
				}
				if (pkgName) {
					externalImportCounts.set(pkgName, (externalImportCounts.get(pkgName) ?? 0) + 1);
				}
			}

			// Security Indicators
			for (const rule of SECURITY_RULES) {
				rule.regex.lastIndex = 0;
				while ((match = rule.regex.exec(text)) !== null) {
					const line = getLineNumber(text, match.index);
					const snippet = text
						.slice(Math.max(0, match.index - 20), Math.min(text.length, match.index + 40))
						.trim();
					securityIndicators.push({
						rule: rule.name,
						description: rule.description,
						file: file.path,
						line,
						snippet,
					});
				}
			}
		}

		const topImports = [...externalImportCounts.entries()]
			.map(([module, count]) => ({ module, count }))
			.sort((a, b) => b.count - a.count)
			.slice(0, 20);

		const totalIpcChannels = ipcOccurrences.length;
		const truncated =
			totalIpcChannels > limit ||
			nativeAddons.length > limit ||
			prioritizedJsFiles.length > maxFiles ||
			securityIndicators.length > limit;

		const entrypoints: string[] = [];
		if (packageJsonSummary?.main) {
			entrypoints.push(packageJsonSummary.main);
		}

		const details: JavascriptApplicationDetails = {
			path: requestedPath,
			targetType,
			fileCount: totalFiles,
			totalSizeBytes,
			packageJson: packageJsonSummary,
			electronVersion,
			roles,
			modules: {
				totalJsFiles: allJsFiles.length,
				analyzedJsFiles: filesToAnalyze.length,
				entrypoints,
				topImports,
			},
			ipcChannels: ipcOccurrences.slice(0, limit),
			totalIpcChannels,
			nativeAddons: nativeAddons.slice(0, limit),
			securityIndicators: securityIndicators.slice(0, limit),
			truncated,
		};

		const reportText = renderApplicationReport(details, requestedPath, limit);

		return {
			content: [{ type: "text", text: reportText }],
			details,
		};
	}
}

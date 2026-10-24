/**
 * Real Portable Tool Installer for Windows (and cross-platform testing).
 *
 * Downloads vetted binary releases from primary upstream sources:
 * - WABT: GitHub release tar.gz (wasm2wat, wat2wasm)
 * - Bundletool: GitHub release fat JAR (bundletool-all.jar) + wrapper scripts
 * - Smali / Baksmali: Bitbucket fat JARs (baksmali.jar, smali.jar) + wrapper scripts
 * - VBinDiff: cjmweb.net release ZIP (VBinDiff.exe)
 * - Il2CppDumper: GitHub release ZIP (Il2CppDumper.exe)
 *
 * All operations are staged in sibling temporary directories and validated
 * using @reverse/utils/ar before atomic publication with rollback protection.
 */
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { getAgentDir } from "@reverse/utils";
import { extractArchive, openArchive } from "@reverse/utils/ar";

export interface PortableToolFile {
	url: string;
	/** Target filename on disk (e.g. bundletool-all.jar). */
	targetFilename?: string;
	/** Optional pinned SHA-256 digest for asset verification. */
	sha256?: string;
}

export interface PortableToolRecipe {
	id: string;
	name: string;
	version: string;
	files: PortableToolFile[];
	format: "tar.gz" | "zip" | "jar" | "exe";
	targetSubdir: string;
	/** Required distinct command groups: every group must have at least one regular binary file resolved. */
	requiredCommandGroups: string[][];
	shims?: Array<{ name: string; targetJar: string }>;
	supportedPlatforms?: readonly NodeJS.Platform[];
	license?: string;
	upstreamUrl?: string;
}

export interface PortableInstallOptions {
	agentDir?: string;
	targetDir?: string;
	onChunk?: (chunk: string) => void;
	signal?: AbortSignal;
	fetch?: (
		input: Parameters<typeof globalThis.fetch>[0],
		init?: Parameters<typeof globalThis.fetch>[1],
	) => Promise<Response>;
	platform?: NodeJS.Platform;
}

export interface PortableInstallResult {
	success: boolean;
	id: string;
	installDir: string;
	binDirs: string[];
	binaries: string[];
	message?: string;
}

export const PORTABLE_TOOL_RECIPES: Readonly<Record<string, PortableToolRecipe>> = {
	wabt: {
		id: "wabt",
		name: "WABT",
		version: "1.0.42",
		files: [{ url: "https://github.com/WebAssembly/wabt/releases/download/1.0.42/wabt-1.0.42-windows-x64.tar.gz" }],
		format: "tar.gz",
		targetSubdir: "wabt",
		requiredCommandGroups: [
			["wasm2wat.exe", "wasm2wat"],
			["wat2wasm.exe", "wat2wasm"],
		],
	},
	bundletool: {
		id: "bundletool",
		name: "bundletool",
		version: "1.18.3",
		files: [
			{
				url: "https://github.com/google/bundletool/releases/download/1.18.3/bundletool-all-1.18.3.jar",
				targetFilename: "bundletool-all.jar",
			},
		],
		format: "jar",
		targetSubdir: "bundletool",
		requiredCommandGroups: [["bundletool.bat", "bundletool"], ["bundletool-all.jar"]],
		shims: [{ name: "bundletool", targetJar: "bundletool-all.jar" }],
	},
	baksmali: {
		id: "baksmali",
		name: "baksmali",
		version: "2.5.2",
		files: [
			{
				url: "https://bitbucket.org/JesusFreke/smali/downloads/baksmali-2.5.2.jar",
				targetFilename: "baksmali.jar",
			},
			{
				url: "https://bitbucket.org/JesusFreke/smali/downloads/smali-2.5.2.jar",
				targetFilename: "smali.jar",
			},
		],
		format: "jar",
		targetSubdir: "smali",
		requiredCommandGroups: [["baksmali.bat", "baksmali"], ["smali.bat", "smali"], ["baksmali.jar"], ["smali.jar"]],
		shims: [
			{ name: "baksmali", targetJar: "baksmali.jar" },
			{ name: "smali", targetJar: "smali.jar" },
		],
	},
	vbindiff: {
		id: "vbindiff",
		name: "VBinDiff",
		version: "3.0_beta5",
		files: [{ url: "https://www.cjmweb.net/vbindiff/VBinDiff-3.0_beta5.zip" }],
		format: "zip",
		targetSubdir: "vbindiff",
		requiredCommandGroups: [["VBinDiff.exe", "vbindiff.exe", "vbindiff"]],
	},
	il2cppdumper: {
		id: "il2cppdumper",
		name: "Il2CppDumper",
		version: "6.7.46",
		files: [
			{ url: "https://github.com/Perfare/Il2CppDumper/releases/download/v6.7.46/Il2CppDumper-win-v6.7.46.zip" },
		],
		format: "zip",
		targetSubdir: "Il2CppDumper",
		requiredCommandGroups: [["Il2CppDumper.exe", "il2cppdumper.exe", "il2cppdumper"]],
	},
	vmpdump: {
		id: "vmpdump",
		name: "VMPDump",
		version: "1.2",
		files: [
			{
				url: "https://github.com/0xnobody/vmpdump/releases/download/v1.2/VMPDump.zip",
				sha256: "3232aa702f2af8b0cc6a967defc525537317fab9dc2512418911326e50551097",
			},
		],
		format: "zip",
		targetSubdir: "vmpdump",
		requiredCommandGroups: [["VMPDump.exe", "vmpdump.exe", "vmpdump"]],
		supportedPlatforms: ["win32"],
		license: "GPL-3.0",
		upstreamUrl: "https://github.com/0xnobody/vmpdump",
	},
	mergen: {
		id: "mergen",
		name: "Mergen",
		version: "0.7",
		files: [
			{
				url: "https://github.com/NaC-L/Mergen/releases/download/v0.7/lifter-windows-iced.exe",
				targetFilename: "lifter-windows-iced.exe",
				sha256: "6dc014b100d0ce2f8d5c6156c2a3786783a8014f8bf4cc20faafad5ce9d366b6",
			},
		],
		format: "exe",
		targetSubdir: "mergen",
		requiredCommandGroups: [["lifter-windows-iced.exe", "mergen.exe", "mergen"]],
		supportedPlatforms: ["win32"],
		license: "GPL-3.0",
		upstreamUrl: "https://github.com/NaC-L/Mergen",
	},
	novmp: {
		id: "novmp",
		name: "NoVmp",
		version: "1.0.6",
		files: [
			{
				url: "https://github.com/can1357/NoVmp/releases/download/v1.0.6/NoVmp.exe",
				targetFilename: "NoVmp.exe",
				sha256: "545788e150e9fab8f16fc157669ee42fe7c636b2a7cb0b8b8e0622af3455401c",
			},
		],
		format: "exe",
		targetSubdir: "novmp",
		requiredCommandGroups: [["NoVmp.exe", "novmp.exe", "novmp"]],
		supportedPlatforms: ["win32"],
		license: "GPL-3.0",
		upstreamUrl: "https://github.com/can1357/NoVmp",
	},
};

export function getPortableToolRecipe(id: string): PortableToolRecipe | undefined {
	const normalized = id.trim().toLowerCase();
	if (normalized === "smali") return PORTABLE_TOOL_RECIPES.baksmali;
	return PORTABLE_TOOL_RECIPES[normalized];
}

/** Validate JAR file structure, manifest Main-Class header, and readable class payload. */
export async function isValidJar(buf: Buffer): Promise<boolean> {
	try {
		if (buf.length < 22) return false;
		const archive = await openArchive({ bytes: buf, format: "zip" });
		let hasManifest = false;
		let hasClass = false;

		for (const entry of archive.indexEntries()) {
			if (entry.path === "META-INF/MANIFEST.MF") hasManifest = true;
			if (entry.path.endsWith(".class")) hasClass = true;
		}
		if (!hasManifest || !hasClass) return false;

		const manifestFile = await archive.readFile("META-INF/MANIFEST.MF").catch(() => null);
		if (!manifestFile) return false;

		const text = new TextDecoder().decode(manifestFile.bytes);
		const match = text.match(/Main-Class:\s*([^\r\n]+)/i);
		if (!match || !match[1]) return false;

		const mainClass = match[1].trim();
		const classPath = mainClass.replace(/\./g, "/") + ".class";
		const classFile = await archive.readFile(classPath).catch(() => null);
		return classFile !== null && classFile.bytes.byteLength > 0;
	} catch {
		return false;
	}
}

function writeShims(targetDir: string, shims: Array<{ name: string; targetJar: string }>): string[] {
	const created: string[] = [];
	for (const shim of shims) {
		const batPath = path.join(targetDir, `${shim.name}.bat`);
		const batContent = `@echo off\r\njava -jar "%~dp0${shim.targetJar}" %*\r\n`;
		fs.writeFileSync(batPath, batContent, { mode: 0o755 });
		created.push(batPath);

		const shPath = path.join(targetDir, shim.name);
		const shContent = `#!/bin/sh\nexec java -jar "$(dirname "$0")/${shim.targetJar}" "$@"\n`;
		fs.writeFileSync(shPath, shContent, { mode: 0o755 });
		created.push(shPath);
	}
	return created;
}

function findBinaryInStage(stageDir: string, binaryName: string): string | null {
	const targetLower = binaryName.toLowerCase();
	const checkEntries = (dir: string): string | null => {
		try {
			if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) return null;
			for (const entry of fs.readdirSync(dir)) {
				if (entry.toLowerCase() === targetLower) {
					const full = path.join(dir, entry);
					if (fs.existsSync(full) && fs.statSync(full).isFile()) {
						return full;
					}
				}
			}
		} catch {}
		return null;
	};

	// 1. Direct or bin/ candidate
	const direct = checkEntries(stageDir);
	if (direct) return direct;

	const bin = checkEntries(path.join(stageDir, "bin"));
	if (bin) return bin;

	// 2. Subdirectories (e.g. wabt-1.0.42/bin/wasm2wat.exe)
	try {
		for (const entry of fs.readdirSync(stageDir, { withFileTypes: true })) {
			if (entry.isDirectory()) {
				const nestedDirect = checkEntries(path.join(stageDir, entry.name));
				if (nestedDirect) return nestedDirect;
				const nestedBin = checkEntries(path.join(stageDir, entry.name, "bin"));
				if (nestedBin) return nestedBin;
			}
		}
	} catch {}

	return null;
}

export async function installPortableTool(
	id: string,
	options: PortableInstallOptions = {},
): Promise<PortableInstallResult> {
	const recipe = getPortableToolRecipe(id);
	if (!recipe) {
		return {
			success: false,
			id,
			installDir: "",
			binDirs: [],
			binaries: [],
			message: `No portable install recipe found for tool "${id}".`,
		};
	}
	const targetPlatform = options.platform ?? process.platform;
	if (recipe.supportedPlatforms && !recipe.supportedPlatforms.includes(targetPlatform)) {
		return {
			success: false,
			id: recipe.id,
			installDir: "",
			binDirs: [],
			binaries: [],
			message: `${recipe.name} is only supported on [${recipe.supportedPlatforms.join(", ")}]; current platform is ${targetPlatform}.`,
		};
	}

	const baseToolsDir = options.targetDir ?? path.join(options.agentDir ?? getAgentDir(), "tools");
	const installDir = path.join(baseToolsDir, recipe.targetSubdir);

	// 1. Stage installation in sibling temporary directory on the same filesystem
	fs.mkdirSync(baseToolsDir, { recursive: true });
	const stageDir = fs.mkdtempSync(path.join(baseToolsDir, `.stage-${recipe.id}-`));

	try {
		const fetchFn = options.fetch ?? globalThis.fetch;
		options.onChunk?.(`[portable] Staging ${recipe.name} v${recipe.version} from primary upstream...\n`);

		for (const file of recipe.files) {
			options.signal?.throwIfAborted();
			const filename = file.targetFilename ?? path.basename(new URL(file.url).pathname);
			options.onChunk?.(`[portable] Fetching ${filename}...\n`);

			const res = await fetchFn(file.url, { signal: options.signal });
			if (!res.ok) {
				return {
					success: false,
					id: recipe.id,
					installDir,
					binDirs: [],
					binaries: [],
					message: `Failed to download ${file.url}: HTTP ${res.status} ${res.statusText}`,
				};
			}

			const arrayBuf = await res.arrayBuffer();
			const buf = Buffer.from(arrayBuf);

			if (file.sha256) {
				const digest = crypto.createHash("sha256").update(buf).digest("hex");
				if (digest.toLowerCase() !== file.sha256.toLowerCase()) {
					return {
						success: false,
						id: recipe.id,
						installDir,
						binDirs: [],
						binaries: [],
						message: `Checksum verification failed for ${filename}: expected ${file.sha256}, got ${digest}`,
					};
				}
			}

			if (recipe.format === "jar") {
				const valid = await isValidJar(buf);
				if (!valid) {
					return {
						success: false,
						id: recipe.id,
						installDir,
						binDirs: [],
						binaries: [],
						message: `Downloaded file from ${file.url} is not a valid executable JAR archive.`,
					};
				}
				const jarDest = path.join(stageDir, filename);
				fs.writeFileSync(jarDest, buf);
			} else if (recipe.format === "exe") {
				const exeDest = path.join(stageDir, filename);
				fs.writeFileSync(exeDest, buf, { mode: 0o755 });
			} else {
				// Use repo native extractArchive with full path traversal and symlink guards
				await extractArchive({ bytes: buf, format: recipe.format }, stageDir);
			}
		}

		// 2. Generate shims if specified
		if (recipe.shims && recipe.shims.length > 0) {
			writeShims(stageDir, recipe.shims);
		}
		if (recipe.license || recipe.upstreamUrl) {
			const receiptPayload = {
				id: recipe.id,
				name: recipe.name,
				version: recipe.version,
				license: recipe.license ?? "Unknown",
				upstreamUrl: recipe.upstreamUrl,
				installedAt: new Date().toISOString(),
			};
			fs.writeFileSync(path.join(stageDir, "receipt.json"), JSON.stringify(receiptPayload, null, 2));
			if (recipe.license) {
				fs.writeFileSync(
					path.join(stageDir, "LICENSE-NOTICE.txt"),
					`Tool: ${recipe.name} v${recipe.version}\nLicense: ${recipe.license}\nUpstream: ${recipe.upstreamUrl ?? ""}\n`,
				);
			}
		}

		// 3. Relocate nested archive directory up if tool extracted to subfolder (e.g. wabt-1.0.42)
		const topDirs = fs.readdirSync(stageDir, { withFileTypes: true }).filter(e => e.isDirectory());
		if (topDirs.length === 1 && !fs.existsSync(path.join(stageDir, "bin"))) {
			const nestedDir = path.join(stageDir, topDirs[0].name);
			if (fs.existsSync(path.join(nestedDir, "bin"))) {
				for (const item of fs.readdirSync(nestedDir)) {
					fs.renameSync(path.join(nestedDir, item), path.join(stageDir, item));
				}
				try {
					fs.rmdirSync(nestedDir);
				} catch {}
			}
		}

		// 4. Verify all required command groups resolve regular files
		const foundBinaries: string[] = [];

		for (const group of recipe.requiredCommandGroups) {
			const matched = group
				.map(name => findBinaryInStage(stageDir, name))
				.find(p => p !== null && fs.existsSync(p) && fs.statSync(p).isFile());

			if (!matched) {
				return {
					success: false,
					id: recipe.id,
					installDir,
					binDirs: [],
					binaries: [],
					message: `Extracted archive is missing required binary command from group: [${group.join(", ")}]`,
				};
			}
			if (!foundBinaries.includes(matched)) {
				foundBinaries.push(matched);
			}
		}

		// 5. Atomically publish to installDir with rollback protection
		let backupDir: string | null = null;
		if (fs.existsSync(installDir)) {
			backupDir = path.join(baseToolsDir, `.backup-${recipe.targetSubdir}-${process.pid}-${Date.now()}`);
			try {
				fs.renameSync(installDir, backupDir);
			} catch (backupErr) {
				return {
					success: false,
					id: recipe.id,
					installDir,
					binDirs: [],
					binaries: [],
					message: `Cannot safely back up existing installation before upgrade: ${(backupErr as Error).message}`,
				};
			}
		}

		try {
			fs.mkdirSync(path.dirname(installDir), { recursive: true });
			fs.renameSync(stageDir, installDir);
			// Success! Safely remove backup now
			if (backupDir && fs.existsSync(backupDir)) {
				try {
					fs.rmSync(backupDir, { recursive: true, force: true });
				} catch {}
			}
		} catch (swapErr) {
			// Rollback: restore backup to preserve existing install
			if (backupDir && fs.existsSync(backupDir)) {
				try {
					fs.renameSync(backupDir, installDir);
				} catch {}
			}
			throw swapErr;
		}

		// Resolve final published binary paths and directories
		const publishedBinaries: string[] = [];
		for (const group of recipe.requiredCommandGroups) {
			const candidate = group
				.map(name => findBinaryInStage(installDir, name))
				.find(p => p !== null && fs.existsSync(p) && fs.statSync(p).isFile());
			if (candidate && !publishedBinaries.includes(candidate)) {
				publishedBinaries.push(candidate);
			}
		}

		const binDirs = Array.from(new Set(publishedBinaries.map(b => path.dirname(b))));

		options.onChunk?.(`[portable] Successfully installed ${recipe.name} to ${installDir}\n`);

		return {
			success: true,
			id: recipe.id,
			installDir,
			binDirs,
			binaries: publishedBinaries,
		};
	} finally {
		try {
			fs.rmSync(stageDir, { recursive: true, force: true });
		} catch {}
	}
}

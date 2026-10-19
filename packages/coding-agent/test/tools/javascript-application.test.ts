import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import { createTools, JavascriptApplicationTool, type ToolSession } from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

interface AsarFixtureFile {
	size: number;
	offset?: string;
	unpacked?: boolean;
}

interface AsarFixtureDirectory {
	files: Record<string, AsarFixtureDirectory | AsarFixtureFile>;
}

function createAsarArchive(entries: Array<{ path: string; content: string; unpacked?: boolean }>): Buffer {
	const root: AsarFixtureDirectory = { files: {} };
	const packed: Buffer[] = [];
	let offset = 0;

	for (const entry of entries) {
		const segments = entry.path.replace(/\\/g, "/").split("/");
		const fileName = segments.pop()!;
		let directory = root;
		for (const segment of segments) {
			let child = directory.files[segment];
			if (!child || !("files" in child)) {
				child = { files: {} };
				directory.files[segment] = child;
			}
			directory = child as AsarFixtureDirectory;
		}

		const content = Buffer.from(entry.content, "utf-8");
		if (entry.unpacked) {
			directory.files[fileName] = { size: content.length, unpacked: true };
		} else {
			directory.files[fileName] = { size: content.length, offset: String(offset) };
			packed.push(content);
			offset += content.length;
		}
	}

	const json = Buffer.from(JSON.stringify(root), "utf-8");
	const alignedJsonSize = json.length + ((4 - (json.length % 4)) % 4);
	const header = Buffer.alloc(8 + alignedJsonSize);
	header.writeUInt32LE(4 + alignedJsonSize, 0);
	header.writeUInt32LE(json.length, 4);
	json.copy(header, 8);

	const sizePickle = Buffer.alloc(8);
	sizePickle.writeUInt32LE(4, 0);
	sizePickle.writeUInt32LE(header.length, 4);
	return Buffer.concat([sizePickle, header, ...packed]);
}

describe("javascript_application discovery and registration", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes canonical/alias names", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("javascript_application");
		expect(normalizeToolName("javascript_application")).toBe("javascript_application");
		expect(normalizeToolName("analyze_javascript_application")).toBe("javascript_application");
	});

	it("creates tool instance with discoverable loadMode and read approval", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-app-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["javascript_application"]);
			const tool = tools.find(t => t.name === "javascript_application");
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("javascript_application");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("javascript_application directory analysis", () => {
	it("analyzes package metadata, Electron roles, IPC channels, and security indicators", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-app-dir-"));
		try {
			const appDir = path.join(tempDir, "my-electron-app");
			await fs.mkdir(path.join(appDir, "src", "main"), { recursive: true });
			await fs.mkdir(path.join(appDir, "src", "preload"), { recursive: true });
			await fs.mkdir(path.join(appDir, "src", "renderer"), { recursive: true });

			const packageJson = {
				name: "sample-desktop-app",
				version: "1.2.3",
				description: "A desktop reconnaissance sample",
				main: "src/main/index.js",
				dependencies: {
					electron: "^29.1.0",
					"better-sqlite3": "^9.4.0",
				},
			};
			await fs.writeFile(path.join(appDir, "package.json"), JSON.stringify(packageJson, null, 2));

			const mainCode = `
const { app, BrowserWindow, ipcMain } = require('electron');
const sqlite3 = require('better-sqlite3');
const keytar = require('bindings')('keytar');

function createWindow() {
	const win = new BrowserWindow({
		width: 800,
		height: 600,
		webPreferences: {
			preload: 'src/preload/index.js',
			nodeIntegration: true,
			contextIsolation: false,
		},
	});

	ipcMain.handle('auth:login', async (event, credentials) => {
		return { success: true };
	});

	ipcMain.on('window:minimize', () => {
		win.minimize();
	});
}

app.whenReady().then(createWindow);
`;
			await fs.writeFile(path.join(appDir, "src", "main", "index.js"), mainCode);

			const preloadCode = `
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('desktopAPI', {
	login: (creds) => ipcRenderer.invoke('auth:login', creds),
	minimize: () => ipcRenderer.send('window:minimize'),
});
`;
			await fs.writeFile(path.join(appDir, "src", "preload", "index.js"), preloadCode);

			const rendererHtml = `<!DOCTYPE html><html><body><h1>Desktop App</h1></body></html>`;
			await fs.writeFile(path.join(appDir, "src", "renderer", "index.html"), rendererHtml);

			const rendererCode = `
document.getElementById('login-btn')?.addEventListener('click', () => {
	window.desktopAPI.login({ user: 'admin' });
});
`;
			await fs.writeFile(path.join(appDir, "src", "renderer", "app.js"), rendererCode);

			const session = createTestSession(tempDir);
			const tool = new JavascriptApplicationTool(session);
			const result = await tool.execute("call-1", { path: "my-electron-app" });

			const text = textOf(result);
			const details = result.details;

			expect(details.targetType).toBe("directory");
			expect(details.packageJson?.name).toBe("sample-desktop-app");
			expect(details.packageJson?.version).toBe("1.2.3");
			expect(details.electronVersion).toBe("^29.1.0");
			expect(details.packageJson?.main).toBe("src/main/index.js");

			// Roles
			expect(details.roles.mainProcessFiles).toContain("src/main/index.js");
			expect(details.roles.preloadFiles).toContain("src/preload/index.js");
			expect(details.roles.rendererFiles).toContain("src/renderer/index.html");

			// IPC channels
			const channels = details.ipcChannels.map(c => c.channel);
			expect(channels).toContain("auth:login");
			expect(channels).toContain("window:minimize");
			expect(channels).toContain("desktopAPI");

			// Native addon references
			expect(details.nativeAddons.some(a => a.name === "keytar")).toBe(true);

			// Security indicators
			expect(details.securityIndicators.some(s => s.rule === "nodeIntegration")).toBe(true);
			expect(details.securityIndicators.some(s => s.rule === "contextIsolationDisabled")).toBe(true);

			// Text output formatting
			expect(text).toContain("sample-desktop-app");
			expect(text).toContain("auth:login");
			expect(text).toContain("keytar");
			expect(text).toContain("nodeIntegration");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("javascript_application ASAR archive analysis", () => {
	it("inspects .asar archives and extracts package metadata, IPC, and binary addons", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-app-asar-"));
		try {
			const asarPath = path.join(tempDir, "app.asar");
			const packageJson = JSON.stringify({
				name: "packaged-asar-app",
				version: "3.0.0",
				main: "bundle/main.js",
				devDependencies: { electron: "31.0.0" },
			});
			const mainJs = `
const { app, ipcMain } = require('electron');
ipcMain.handle('vault:unlock', async () => 'secret');
`;
			const preloadJs = `
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('vaultApi', {});
ipcRenderer.send('app:ready');
`;
			const nativeAddonContent = "/* dummy native ELF/Mach-O/PE addon */";

			const asarBuffer = createAsarArchive([
				{ path: "package.json", content: packageJson },
				{ path: "bundle/main.js", content: mainJs },
				{ path: "bundle/preload.js", content: preloadJs },
				{ path: "native/keytar.node", content: nativeAddonContent },
			]);
			await fs.writeFile(asarPath, asarBuffer);

			const session = createTestSession(tempDir);
			const tool = new JavascriptApplicationTool(session);
			const result = await tool.execute("call-2", { path: "app.asar" });

			const details = result.details;
			expect(details.targetType).toBe("asar");
			expect(details.packageJson?.name).toBe("packaged-asar-app");
			expect(details.electronVersion).toBe("31.0.0");
			expect(details.roles.mainProcessFiles).toContain("bundle/main.js");
			expect(details.roles.preloadFiles).toContain("bundle/preload.js");

			// Binary native addon
			const binaryAddon = details.nativeAddons.find(a => a.name === "keytar.node");
			expect(binaryAddon).toBeDefined();
			expect(binaryAddon?.kind).toBe("binary");

			// IPC channels
			const channels = details.ipcChannels.map(c => c.channel);
			expect(channels).toContain("vault:unlock");
			expect(channels).toContain("app:ready");
			expect(channels).toContain("vaultApi");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("filters IPC channels with channel_filter", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-app-filter-"));
		try {
			const asarPath = path.join(tempDir, "filtered.asar");
			const mainJs = `
const { ipcMain } = require('electron');
ipcMain.handle('auth:secret-token', () => {});
ipcMain.handle('window:close', () => {});
ipcMain.handle('system:reboot', () => {});
`;
			const asarBuffer = createAsarArchive([
				{ path: "package.json", content: JSON.stringify({ name: "filter-test", main: "index.js" }) },
				{ path: "index.js", content: mainJs },
			]);
			await fs.writeFile(asarPath, asarBuffer);

			const session = createTestSession(tempDir);
			const tool = new JavascriptApplicationTool(session);
			const result = await tool.execute("call-3", { path: "filtered.asar", channel_filter: "secret" });

			const details = result.details;
			expect(details.ipcChannels.length).toBe(1);
			expect(details.ipcChannels[0].channel).toBe("auth:secret-token");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("javascript_application path validation & error handling", () => {
	it("rejects empty path parameter", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-app-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JavascriptApplicationTool(session);
			expect(tool.execute("call-err-1", { path: "  " })).rejects.toThrow("path or target is required");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects URL targets safely", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-app-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JavascriptApplicationTool(session);
			expect(tool.execute("call-err-2", { path: "https://example.com/app.asar" })).rejects.toThrow(
				"URL targets are not supported",
			);
			expect(tool.execute("call-err-3", { path: "http://localhost:3000/electron" })).rejects.toThrow(
				"URL targets are not supported",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects nonexistent paths safely", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-app-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JavascriptApplicationTool(session);
			expect(tool.execute("call-err-4", { path: "does-not-exist.asar" })).rejects.toThrow("Target not found");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects non-archive regular files safely", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-app-err-"));
		try {
			const textFile = path.join(tempDir, "plain.txt");
			await fs.writeFile(textFile, "This is not an asar or zip archive.");
			const session = createTestSession(tempDir);
			const tool = new JavascriptApplicationTool(session);
			expect(tool.execute("call-err-5", { path: "plain.txt" })).rejects.toThrow(
				"Target file is not a supported JavaScript application archive",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

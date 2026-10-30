import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { createContext, runInContext, runInNewContext } from "node:vm";
import { HTMLElement, parseHTML } from "@reverse/utils/dom";
import { TempDir } from "@reverse/utils/temp";
import { buildExportViewer, type ExportViewerMetadata } from "../scripts/build-export-viewer";

const temp = TempDir.createSync("@reverse-export-viewer-build-");
const outDir = temp.path();
const staleName = `export-viewer-${"0".repeat(64)}.js`;
const unrelatedName = "another-build.js";
let metadata: ExportViewerMetadata;
let bytes: Buffer<ArrayBuffer>;

beforeAll(async () => {
	await Bun.write(path.join(outDir, staleName), "obsolete viewer");
	await Bun.write(path.join(outDir, unrelatedName), "unrelated output");
	await fs.mkdir(path.join(outDir, `export-viewer-${"1".repeat(64)}.js`));
	metadata = await buildExportViewer({ outDir });
	bytes = await fs.readFile(path.join(outDir, metadata.file));
}, 30_000);

afterAll(() => temp[Symbol.dispose]());

describe("hosted export viewer build", () => {
	it("hashes the exact uploaded bytes and removes only obsolete viewer files", async () => {
		const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
		expect(metadata).toEqual({
			file: `export-viewer-${digest.toHex()}.js`,
			integrity: `sha256-${digest.toBase64()}`,
			size: bytes.length,
		});
		expect(await Bun.file(path.join(outDir, "viewer.generated.json")).json()).toEqual(metadata);
		expect(await Bun.file(path.join(outDir, staleName)).exists()).toBe(false);
		expect(await Bun.file(path.join(outDir, unrelatedName)).text()).toBe("unrelated output");
		expect((await fs.stat(path.join(outDir, `export-viewer-${"1".repeat(64)}.js`))).isDirectory()).toBe(true);
	});

	it("reproduces the asset while checking, rather than rewriting, its manifest", async () => {
		const metadataPath = path.join(outDir, "checked.json");
		const original = JSON.stringify(metadata);
		await Bun.write(metadataPath, original);
		expect(await buildExportViewer({ outDir, metadataPath, check: true })).toEqual(metadata);
		expect(await Bun.file(metadataPath).text()).toBe(original);
		expect(await fs.readFile(path.join(outDir, metadata.file))).toEqual(bytes);
	}, 30_000);

	for (const field of ["file", "integrity", "size"]) {
		it(`rejects a stale ${field} pin without changing the manifest or asset`, async () => {
			const metadataPath = path.join(outDir, `stale-${field}.json`);
			const original = JSON.stringify({ ...metadata, [field]: field === "size" ? metadata.size + 1 : "stale" });
			await Bun.write(metadataPath, original);
			await expect(buildExportViewer({ outDir, metadataPath, check: true })).rejects.toThrow("metadata is stale");
			expect(await Bun.file(metadataPath).text()).toBe(original);
			expect(await fs.readFile(path.join(outDir, metadata.file))).toEqual(bytes);
		}, 30_000);
	}

	it("catches synchronous initialization failures and renders them as status text", () => {
		const status = { textContent: "Loading viewer…" };
		runInNewContext(bytes.toString("utf8"), {
			document: {
				createElement() {
					throw new Error("<img src=x onerror=alert(1)>");
				},
				getElementById(id: string) {
					return id === "viewer-status" ? status : null;
				},
			},
		});
		expect(status.textContent).toContain("Failed to load viewer:");
	});

	it("renders transcript and tool Markdown with their independent parser settings", () => {
		const { document, window } = parseHTML(
			'<html><head><style id="custom-theme">:root { --accent: red; }</style></head><body><p id="viewer-status">Loading viewer…</p><script id="session-data"></script></body></html>',
		);
		const sessionData = document.getElementById("session-data");
		if (!sessionData) throw new Error("Missing test session data");
		sessionData.textContent = Buffer.from(
			JSON.stringify({
				header: {
					type: "session",
					version: 3,
					id: "shared-runtime",
					timestamp: "2026-01-01T00:00:00Z",
					cwd: "/tmp",
				},
				leafId: "assistant-1",
				entries: [
					{
						type: "message",
						id: "assistant-1",
						parentId: null,
						timestamp: "2026-01-01T00:00:01Z",
						message: {
							role: "assistant",
							content: [{ type: "text", text: "$x^2$\n\n```js\nconst transcriptCode = 1;\n```" }],
							stopReason: "stop",
							timestamp: 1,
						},
					},
				],
			}),
		).toBase64();
		Object.defineProperty(window, "location", { value: new URL("https://example.test/export.html") });
		const matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
		Object.defineProperty(window, "matchMedia", { value: matchMedia });

		const elements = new Map<string, typeof HTMLElement>();
		const scheduled: Array<() => void> = [];
		const flushWork = () => {
			while (scheduled.length > 0) scheduled.shift()?.();
		};
		const context = createContext({
			window,
			document,
			HTMLElement: class extends HTMLElement {
				constructor() {
					super("reverse-tool-view", document);
				}
			},
			customElements: {
				get: (name: string) => elements.get(name),
				define: (name: string, element: typeof HTMLElement) => elements.set(name, element),
			},
			URL,
			URLSearchParams,
			TextDecoder,
			Uint8Array,
			atob,
			navigator: window.navigator,
			localStorage: { getItem: () => null, setItem() {} },
			matchMedia,
			getComputedStyle: (element: HTMLElement) => element.style,
			// Drive React's scheduled work explicitly; ignore transcript layout-only scroll timers.
			setImmediate: (callback: () => void) => scheduled.push(callback),
			setTimeout: () => 0,
			clearTimeout() {},
			queueMicrotask: (callback: () => void) => scheduled.push(callback),
			performance,
			console,
		});
		runInContext(bytes.toString("utf8"), context);
		expect(
			document.getElementById("viewer-status"),
			document.getElementById("viewer-status")?.textContent ?? "",
		).toBeNull();
		expect(document.head.firstElementChild?.getAttribute("data-reverse-export-viewer")).toBe("");
		expect(document.getElementById("custom-theme")?.previousElementSibling).toBe(document.head.firstElementChild);
		const assistant = document.querySelector(".assistant-message");
		expect(assistant?.textContent).toContain("$x^2$");
		expect(assistant?.querySelector("math")).toBeNull();
		expect(assistant?.querySelector("code")?.textContent).toContain("const transcriptCode = 1;");

		const payload = {
			name: "eval",
			args: { language: "js", code: "const toolCode = 2;" },
			defaultOpen: true,
			result: {
				content: [],
				details: {
					cells: [
						{
							index: 0,
							output: "**tool output**",
							views: [{ text: "**tool output**", view: { kind: "markdown", text: "**tool output**" } }],
						},
					],
				},
			},
		};
		// The lightweight DOM does not auto-upgrade custom elements. Instantiate the
		// actual registered React wrapper and deliver its normal connection callback.
		runInContext(
			`
			const tool = new (customElements.get("reverse-tool-view"))();
			tool.setAttribute("payload", ${JSON.stringify(JSON.stringify(payload))});
			document.body.appendChild(tool);
			tool.connectedCallback();
		`,
			context,
		);
		try {
			flushWork();
			expect(document.querySelector("reverse-tool-view .tv-md strong")?.textContent).toBe("tool output");
		} finally {
			runInContext("tool.remove(); tool.disconnectedCallback();", context);
			flushWork();
		}
	});
});

/**
 * Interactive startup binds startup-safe extensions after the composer accepts
 * input (`deferredExtensionPaths`) and gates the first request on them. These
 * tests pin the two halves of that contract: which sources may defer, and that
 * a deferred source ends up as live as an eagerly loaded one.
 */
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { loadExtensions } from "@reverse/coding-agent/extensibility/extensions";
import {
	partitionStartupExtensions,
	recordStartupVerdicts,
} from "@reverse/coding-agent/extensibility/extensions/startup-deferral";
import { createAgentSession } from "@reverse/coding-agent/sdk";
import { AgentStorage } from "@reverse/coding-agent/session/agent-storage";
import type { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { EventBus } from "@reverse/coding-agent/utils/event-bus";
import { TempDir } from "@reverse/utils";
import { createInMemoryAuthStorage } from "./helpers/agent-session-setup";

const DEFERRED_TOOL_EXTENSION = (logPath: string) => `
	import * as fs from "node:fs";
	export default function(pi) {
		const { Type } = pi.typebox;
		pi.registerTool({
			name: "deferred_probe",
			label: "Deferred probe",
			description: "Registered by a startup-deferred extension.",
			parameters: Type.Object({}),
			execute: async () => ({ content: [{ type: "text", text: "ok" }], details: {} }),
		});
		pi.on("session_start", () => { fs.appendFileSync(${JSON.stringify(logPath)}, "deferred\\n"); });
	}
`;

describe("startup-deferred extensions", () => {
	let tempDir: TempDir;
	let authStorage: AuthStorage;

	beforeEach(() => {
		tempDir = TempDir.createSync("@reverse-deferred-ext-");
		authStorage = createInMemoryAuthStorage();
	});

	afterEach(() => {
		AgentStorage.close();
		authStorage.close();
		tempDir.removeSync();
	});

	it("defers only sources whose recorded verdict matches their current file", async () => {
		const storage = await AgentStorage.open(path.join(tempDir.path(), "agent.db"));
		const toolOnly = path.join(tempDir.path(), "tool-only.ts");
		const withShortcut = path.join(tempDir.path(), "with-shortcut.ts");
		const neverLoaded = path.join(tempDir.path(), "never-loaded.ts");
		fs.writeFileSync(toolOnly, DEFERRED_TOOL_EXTENSION(path.join(tempDir.path(), "unused.log")));
		fs.writeFileSync(
			withShortcut,
			`export default function(pi) { pi.registerShortcut("ctrl+shift+y", { handler: () => {} }); }`,
		);
		fs.writeFileSync(neverLoaded, `export default function() {}`);

		const loaded = await loadExtensions([toolOnly, withShortcut], tempDir.path());
		await recordStartupVerdicts(storage, loaded.extensions);

		const paths = [toolOnly, withShortcut, neverLoaded];
		expect(await partitionStartupExtensions(storage, paths, tempDir.path())).toEqual({
			eager: [withShortcut, neverLoaded],
			deferred: [toolOnly],
		});

		// An edited source may now register something startup needs: load it eagerly again.
		fs.appendFileSync(toolOnly, "\n// edited\n");
		expect(await partitionStartupExtensions(storage, paths, tempDir.path())).toEqual({
			eager: [toolOnly, withShortcut, neverLoaded],
			deferred: [],
		});
	});

	it("binds a deferred extension into the live session and replays session_start to it alone", async () => {
		const logPath = path.join(tempDir.path(), "session-start.log");
		const eagerPath = path.join(tempDir.path(), "eager.ts");
		const deferredPath = path.join(tempDir.path(), "deferred.ts");
		fs.writeFileSync(
			eagerPath,
			`import * as fs from "node:fs";
			export default function(pi) {
				pi.on("session_start", () => { fs.appendFileSync(${JSON.stringify(logPath)}, "eager\\n"); });
			}`,
		);
		fs.writeFileSync(deferredPath, DEFERRED_TOOL_EXTENSION(logPath));

		const eventBus = new EventBus();
		const preloaded = await loadExtensions([eagerPath], tempDir.path(), eventBus);
		const { session } = await createAgentSession({
			cwd: tempDir.path(),
			agentDir: tempDir.path(),
			sessionManager: SessionManager.inMemory(),
			modelRegistry: new ModelRegistry(authStorage, path.join(tempDir.path(), "models.yml")),
			settings: Settings.isolated(),
			eventBus,
			preloadedExtensions: preloaded,
			deferredExtensionPaths: [deferredPath],
			enableLsp: false,
			enableMCP: false,
			skipPythonPreflight: true,
			skills: [],
			rules: [],
			preloadedCustomToolPaths: [],
			contextFiles: [],
			promptTemplates: [],
			slashCommands: [],
			toolNames: ["read"],
		});

		try {
			const runner = session.extensionRunner;
			if (!runner) throw new Error("expected an extension runner");
			await runner.emit({ type: "session_start" });
			expect(session.getAllToolNames()).not.toContain("deferred_probe");

			await session.loadDeferredExtensions();

			expect(session.getAllToolNames()).toContain("deferred_probe");
			expect(session.getEnabledToolNames()).toContain("deferred_probe");
			expect(fs.readFileSync(logPath, "utf8")).toBe("eager\ndeferred\n");
			// Subagents and forks inherit the deferred source like an eager one.
			expect(session.extensionPaths).toContain(deferredPath);
		} finally {
			await session.dispose();
		}
	});
});

import { afterEach, beforeEach, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { RpcClient } from "@reverse/coding-agent/modes/rpc/rpc-client";
import type { TodoPhase } from "@reverse/tui/tools/todo";
import { removeWithRetries } from "@reverse/utils";

let client: RpcClient;
let directory: string;

beforeEach(async () => {
	directory = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-rpc-todos-"));
	client = new RpcClient({
		command: [process.execPath, path.join(import.meta.dir, "..", "fixtures", "fork-rpc-agent.ts"), directory],
		cwd: directory,
		env: { REVERSE_CODING_AGENT_DIR: directory, REVERSE_NO_TITLE: "1" },
	});
});

afterEach(async () => {
	const ownClient = client;
	const ownDirectory = directory;
	await ownClient?.stop();
	await removeWithRetries(ownDirectory);
});

it("restores RPC todo edits and explicit clears after reloading the session", async () => {
	await client.start();
	await client.promptAndWait("seed");
	const { sessionFile } = await client.getState();
	if (!sessionFile) throw new Error("expected a persisted session file");
	const phases: TodoPhase[] = [{ name: "Plan", tasks: [{ content: "Review changes", status: "pending" }] }];

	await client.setTodos(phases);
	await client.switchSession(sessionFile);
	expect((await client.getState()).todoPhases).toEqual(phases);

	await client.setTodos([]);
	await client.switchSession(sessionFile);
	expect((await client.getState()).todoPhases).toEqual([]);
}, 30_000);

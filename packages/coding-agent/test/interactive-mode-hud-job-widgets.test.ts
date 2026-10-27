import { afterAll, afterEach, beforeAll, describe, expect, it, spyOn, vi } from "bun:test";
import * as path from "node:path";
import { Agent } from "@reverse/agent";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { resetSettingsForTest, Settings } from "@reverse/coding-agent/config/settings";
import { InteractiveMode } from "@reverse/coding-agent/modes/interactive-mode";
import { AgentSession } from "@reverse/coding-agent/session/agent-session";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import type { TspPropNode } from "@reverse/wire";
import type { NativeChild, NativeNode } from "@reverse/tui/native/node";
import { initTheme } from "@reverse/tui/theme";
import type { JobWidgetEntry, JobWidgetView } from "@reverse/tui/tools/job-widget";
import { TempDir } from "@reverse/utils";

function nodes(root: NativeNode): NativeNode[] {
	const out: NativeNode[] = [root];
	for (const child of root.c ?? []) if ("k" in child) out.push(...nodes(child));
	return out;
}

function prop(node: NativeNode | TspPropNode | NativeChild | undefined, name: string): unknown {
	return node && "p" in node && node.p ? Reflect.get(node.p, name) : undefined;
}

const decode: JobWidgetView = {
	title: "verb-bench · decode",
	headline: { text: "186 tok/s", label: "decode", trend: { text: "▲ 15%", tone: "success" } },
	blocks: [
		{
			kind: "spark",
			label: "tok/s",
			values: Array.from({ length: 24 }, (_, i) => 150 + i),
			min: 0,
			max: 220,
			marks: [{ value: 200, label: "target 200 tok/s" }],
			last: "186 tok/s",
		},
		{ kind: "stat", items: [{ label: "p99", text: "212 ms" }] },
	],
	state: "live",
	updatedAt: 2_000,
};
const evalRun: JobWidgetView = {
	title: "eval · per model",
	blocks: [{ kind: "meter", label: "trials", value: 7 / 9, text: "7/9 trials" }],
	state: "live",
	updatedAt: 1_000,
};

describe("InteractiveMode HUD jobs segment with job widgets", () => {
	let tempDir: TempDir;
	let authStorage: AuthStorage;
	let session: AgentSession;
	let mode: InteractiveMode;

	beforeAll(async () => {
		await initTheme();
		resetSettingsForTest();
		tempDir = TempDir.createSync("@pi-hud-job-widgets-");
		await Settings.init({ inMemory: true, cwd: tempDir.path() });
		authStorage = await AuthStorage.create(path.join(tempDir.path(), "testauth.db"));
		const modelRegistry = new ModelRegistry(authStorage);
		const model = modelRegistry.find("anthropic", "claude-sonnet-4-5");
		if (!model) throw new Error("Expected claude-sonnet-4-5 to exist in registry");
		session = new AgentSession({
			agent: new Agent({ initialState: { model, systemPrompt: ["Test"], tools: [], messages: [] } }),
			sessionManager: SessionManager.create(tempDir.path(), tempDir.path()),
			settings: Settings.isolated(),
			modelRegistry,
		});
		mode = new InteractiveMode(session, "test");
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	afterAll(async () => {
		mode?.stop();
		await session?.dispose();
		authStorage?.close();
		tempDir?.removeSync();
		resetSettingsForTest();
	});

	const jobsSegment = (): NativeNode | undefined =>
		nodes(mode.describeHudPills()).find(node => node.key === "jobs" && prop(node, "role") === "reverse.hud.seg");

	it("shows the freshest headline and a mini spark, lists every widget in the title and stacks them in a hover card", () => {
		let entries: JobWidgetEntry[] = [
			{ id: "bg_1", type: "bash", view: evalRun },
			{ id: "bg_2", type: "bash", view: decode },
		];
		spyOn(mode.statusLine, "runningBackgroundJobCount").mockReturnValue(2);
		spyOn(session, "getRunningJobWidgets").mockImplementation(() => entries);

		const segment = jobsSegment()!;
		const glance = nodes(segment).find(node => prop(node, "role") === "reverse.hud.glance");
		expect(prop(glance, "spans")).toEqual([
			{ t: "186 tok/s", s: "num strong" },
			{ t: " ▲ 15%", s: "success" },
		]);
		const spark = nodes(segment).find(node => node.k === "chart");
		expect(spark?.p).toMatchObject({ kind: "spark", min: 0, max: 220 });
		expect(prop(spark, "series")).toHaveLength(16);
		expect(prop(segment, "title")).toBe(
			"2 jobs running  /jobs\nbg_1  eval · per model — trials 7/9 trials\nbg_2  verb-bench · decode — decode 186 tok/s ▲ 15%",
		);
		const card = prop(segment, "hovercard") as TspPropNode;
		expect(card).toMatchObject({ k: "col", p: { role: "reverse.jobs.hovercard" } });
		expect(card.c?.map(child => prop(child, "role"))).toEqual(["reverse.job.tiles"]);
		expect(card.c?.[0]?.c?.map(child => prop(child, "role"))).toEqual(["reverse.job.tile", "reverse.job.tile"]);

		// Unchanged widget data keeps the described node; moved data re-describes it.
		expect(jobsSegment()).toBe(segment);
		entries = [
			entries[0]!,
			{ id: "bg_2", type: "bash", view: { ...decode, updatedAt: 3_000, headline: { text: "191 tok/s" } } },
		];
		const next = jobsSegment()!;
		expect(next).not.toBe(segment);
		expect(JSON.stringify(next)).toContain("191 tok/s");
	});

	it("keeps the bare count segment while no running job draws a widget", () => {
		spyOn(mode.statusLine, "runningBackgroundJobCount").mockReturnValue(1);
		spyOn(session, "getRunningJobWidgets").mockReturnValue([]);
		const segment = jobsSegment()!;
		expect(prop(segment, "hovercard")).toBeUndefined();
		expect(prop(segment, "title")).toBe("1 job running  /jobs");
	});
});

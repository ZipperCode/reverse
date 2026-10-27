import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

const SCRIPT = path.join(import.meta.dir, "session-output-metrics.ts");
const WORKSPACE_ROOT = path.join(import.meta.dir, "..");
const tempDirs: string[] = [];

const HANDOFF_DOCUMENT = [
	"## Goal",
	"Verify that compaction output stays within artifact and handoff budgets.",
	"## Constraints & Preferences",
	"- Deterministic analysis; no network access during replay.",
	"- Keep the anchor `ANCHOR_SHA = abcdef` unchanged across runs.",
	"## Progress",
	"### Done",
	"- [x] Captured the baseline session and artifact directories.",
	"- [x] Re-ran the candidate workload with the new budget settings.",
	"## Key Decisions",
	"- Keep per-call capture logs under the configured 4 MiB budget.",
	"## Critical Context",
	"- `ANCHOR_SHA = abcdef` identifies the retained capture log region.",
	"## Next Steps",
	"1. Re-run the replay and compare all five acceptance axes.",
].join("\n");

/** Committed compaction summary: the generated document plus the appended file-operations tag. */
const HANDOFF_SUMMARY = `${HANDOFF_DOCUMENT}\n\n<modified-files>\n- src/a.ts (Write)\n</modified-files>`;
const INVARIANTS_JSON = JSON.stringify([{ name: "anchor_sha", pattern: "ANCHOR_SHA = abcdef" }]);

afterEach(async () => {
	while (tempDirs.length > 0) {
		const dir = tempDirs.pop()!;
		await fs.rm(dir, { recursive: true, force: true });
	}
});

async function makeTempDir(): Promise<string> {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-output-metrics-cli-"));
	tempDirs.push(dir);
	return dir;
}

async function runCli(args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> {
	const proc = Bun.spawn([process.execPath, SCRIPT, ...args], {
		cwd: WORKSPACE_ROOT,
		stdout: "pipe",
		stderr: "pipe",
	});
	const [stdout, stderr, exitCode] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	return { exitCode, stdout, stderr };
}

async function writeSessionFixture(options: {
	root: string;
	name: string;
	compactions: number;
	shaken: boolean;
	captureBytes: number;
	saveHandoff: boolean;
}): Promise<string> {
	const file = path.join(options.root, `${options.name}.jsonl`);
	const artifactsDir = path.join(options.root, options.name);
	await fs.mkdir(artifactsDir, { recursive: true });
	const entries: unknown[] = [
		{ type: "session", version: 3, id: options.name, timestamp: "2026-10-25T00:00:00.000Z", cwd: "/workspace" },
	];
	for (let index = 0; index < options.compactions; index++) {
		entries.push({
			type: "compaction",
			id: `c${index + 1}`,
			parentId: index === 0 ? null : `c${index}`,
			timestamp: `2026-10-25T00:${String(15 * (index + 1)).padStart(2, "0")}:00.000Z`,
			method: "handoff",
			firstKeptEntryId: `c${index + 1}`,
			tokensBefore: 120_000,
			tokensAfter: 50_000,
			summary: HANDOFF_SUMMARY,
		});
	}
	entries.push({
		type: "message",
		id: "m1",
		parentId: `c${options.compactions}`,
		timestamp: "2026-10-25T00:46:00.000Z",
		message: {
			role: "toolResult",
			toolCallId: "t1",
			toolName: "bash",
			isError: false,
			content: [
				{
					type: "text",
					text: options.shaken
						? "[shaken ~500 tokens — recover: artifact://1 (region 1)]"
						: "bounded inline output",
				},
			],
			timestamp: 1,
		},
	});
	await fs.writeFile(file, `${entries.map(entry => JSON.stringify(entry)).join("\n")}\n`, "utf8");
	if (options.saveHandoff) {
		await fs.writeFile(path.join(artifactsDir, "handoff-2026-10-25T00-15-00-000Z.md"), HANDOFF_DOCUMENT, "utf8");
	}
	if (options.captureBytes > 0) {
		await fs.writeFile(path.join(artifactsDir, "1.bash.log"), "A".repeat(options.captureBytes), "utf8");
	}
	return file;
}

describe("session-output-metrics CLI preconditions", () => {
	test("rejects --require-pass without --baseline instead of exiting 0", async () => {
		const root = await makeTempDir();
		const session = path.join(root, "solo.jsonl");
		await fs.writeFile(
			session,
			`${JSON.stringify({ type: "session", version: 3, id: "solo", timestamp: "2026-10-25T00:00:00.000Z", cwd: "/" })}\n`,
			"utf8",
		);

		const result = await runCli([session, "--require-pass", "--json"]);
		expect(result.exitCode).not.toBe(0);
		expect(result.stderr).toContain("--require-pass requires --baseline");
		expect(result.stdout.trim()).toBe("");
	}, 60_000);

	test("rejects extra positional arguments", async () => {
		const root = await makeTempDir();
		const session = await writeSessionFixture({
			root,
			name: "solo",
			compactions: 0,
			shaken: false,
			captureBytes: 0,
			saveHandoff: false,
		});

		const result = await runCli([session, path.join(root, "extra.jsonl")]);
		expect(result.exitCode).not.toBe(0);
		expect(result.stderr).toContain("Unexpected extra argument");
	}, 60_000);

	test("rejects malformed --handoff-invariants and unknown --handoff-provenance values", async () => {
		const root = await makeTempDir();
		const baseline = await writeSessionFixture({
			root,
			name: "base",
			compactions: 2,
			shaken: true,
			captureBytes: 0,
			saveHandoff: false,
		});
		const candidate = await writeSessionFixture({
			root,
			name: "cand",
			compactions: 1,
			shaken: false,
			captureBytes: 0,
			saveHandoff: false,
		});

		const badInvariants = await runCli([
			candidate,
			"--baseline",
			baseline,
			"--handoff-invariants",
			'{"name":"anchor_sha","pattern":"ANCHOR_SHA"}',
		]);
		expect(badInvariants.exitCode).not.toBe(0);
		expect(badInvariants.stderr).toContain("--handoff-invariants");

		const badProvenance = await runCli([candidate, "--baseline", baseline, "--handoff-provenance", "trust_me"]);
		expect(badProvenance.exitCode).not.toBe(0);
		expect(badProvenance.stderr).toContain("--handoff-provenance");

		// A flag must never assert live-model origin; that is what the matched-document inference is for.
		const assertedLive = await runCli([candidate, "--baseline", baseline, "--handoff-provenance", "live_model"]);
		expect(assertedLive.exitCode).not.toBe(0);
		expect(assertedLive.stderr).toContain("never asserted by a flag");
	}, 60_000);
});

describe("session-output-metrics CLI acceptance gate", () => {
	test("fails --require-pass when handoff provenance and invariants are unproven", async () => {
		const root = await makeTempDir();
		const baseline = await writeSessionFixture({
			root,
			name: "base",
			compactions: 2,
			shaken: true,
			captureBytes: 0,
			saveHandoff: false,
		});
		const candidate = await writeSessionFixture({
			root,
			name: "cand",
			compactions: 1,
			shaken: false,
			captureBytes: 0,
			saveHandoff: false,
		});

		const result = await runCli([candidate, "--baseline", baseline, "--require-pass", "--json"]);
		expect(result.exitCode).toBe(1);
		const payload = JSON.parse(result.stdout) as {
			comparison: { passed: boolean; axes: Record<string, { status: string }> };
		};
		expect(payload.comparison.passed).toBe(false);
		expect(payload.comparison.axes.compactionPace?.status).toBe("pass");
		expect(payload.comparison.axes.handoffStructuralCoverage?.status).toBe("unknown");
	}, 60_000);

	test("passes --require-pass for matched live-model handoffs with shared invariants", async () => {
		const root = await makeTempDir();
		const baseline = await writeSessionFixture({
			root,
			name: "base",
			compactions: 2,
			shaken: true,
			captureBytes: 2_048,
			saveHandoff: true,
		});
		const candidate = await writeSessionFixture({
			root,
			name: "cand",
			compactions: 1,
			shaken: false,
			captureBytes: 1_024,
			saveHandoff: true,
		});

		const result = await runCli([
			candidate,
			"--baseline",
			baseline,
			"--handoff-invariants",
			INVARIANTS_JSON,
			"--require-pass",
			"--json",
		]);
		expect(result.exitCode).toBe(0);
		const payload = JSON.parse(result.stdout) as {
			metrics: { artifacts: { handoffQuality: { provenance: string; invariantMatchedCount: number } } };
			baseline: { artifacts: { handoffQuality: { provenance: string; invariantMatchedCount: number } } };
			comparison: { passed: boolean };
		};
		expect(payload.comparison.passed).toBe(true);
		expect(payload.metrics.artifacts.handoffQuality.provenance).toBe("live_model");
		expect(payload.baseline.artifacts.handoffQuality.provenance).toBe("live_model");
		expect(payload.metrics.artifacts.handoffQuality.invariantMatchedCount).toBe(1);

		// An explicit caller assertion can only weaken a proven handoff, never strengthen it.
		const assertedFixture = await runCli([
			candidate,
			"--baseline",
			baseline,
			"--handoff-invariants",
			INVARIANTS_JSON,
			"--handoff-provenance",
			"fixture",
			"--require-pass",
			"--json",
		]);
		expect(assertedFixture.exitCode).toBe(1);
		const assertedPayload = JSON.parse(assertedFixture.stdout) as {
			metrics: { artifacts: { handoffQuality: { provenance: string } } };
			comparison: { passed: boolean };
		};
		expect(assertedPayload.metrics.artifacts.handoffQuality.provenance).toBe("fixture");
		expect(assertedPayload.comparison.passed).toBe(false);
	}, 60_000);
});

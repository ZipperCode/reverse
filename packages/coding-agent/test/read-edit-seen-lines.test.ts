import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolResult } from "@reverse/agent";
import { Settings } from "@reverse/coding-agent/config/settings";
import { classifyEditRejection, EditTool, extractEditErrorKind } from "@reverse/coding-agent/edit";
import type { ToolSession } from "@reverse/coding-agent/tools";
import { ReadTool } from "@reverse/coding-agent/tools/read";
import { removeWithRetries } from "@reverse/utils";

// A call whose arguments span several lines, so a structural read elides the
// inner rows (3-4) and displays the rest.
const SOURCE = [
	"def draw(sheet, anchor, alpha, beta):",
	"    add_native_hole_callout(sheet=sheet,",
	"        nested=nested(alpha,",
	"            beta),",
	"        point=model_point_in_view(",
	"            anchor),",
	"        callout_xy=(0.230, 0.258))",
	"",
].join("\n");

function textOutput(result: AgentToolResult<unknown>): string {
	return result.content
		.filter(c => c.type === "text")
		.map(c => c.text)
		.join("\n");
}

function createSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: false,
		getSessionFile: () => path.join(cwd, "session.jsonl"),
		getSessionSpawns: () => "*",
		getArtifactsDir: () => path.join(cwd, "artifacts"),
		settings: Settings.isolated(),
	} as unknown as ToolSession;
}

// Regression: the hashline prompt promises that hunks anchored on lines a read
// never displayed are rejected, but the seen-line guard shipped opt-in. With
// the guard off, a hunk whose range fell inside an elided region was instead
// "auto-repaired" — the syntax probe kept the row the range had selected and
// spliced the body into the neighbouring call, silently and with valid syntax.
describe("read → edit seen-line guard under default settings", () => {
	let cwd: string;
	let file: string;

	beforeEach(async () => {
		cwd = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-seen-lines-"));
		file = path.join(cwd, "draw.py");
		await Bun.write(file, SOURCE);
	});

	afterEach(async () => {
		await removeWithRetries(cwd);
	});

	it("rejects unseen-line and cross-file-tag edits without mutating the file, then applies once the range is displayed", async () => {
		const session = createSession(cwd);
		const otherFile = path.join(cwd, "other.py");
		const otherSource = "def other():\n    return 1\n";
		await Bun.write(otherFile, otherSource);

		const readDraw = textOutput(await new ReadTool(session).execute("read", { path: "draw.py:7-7" }));
		const drawHeader = readDraw.split("\n")[0]!;
		expect(drawHeader).toMatch(/^\[draw\.py#[0-9A-F]{4}\]$/);
		expect(readDraw).toContain("…");
		expect(readDraw).not.toContain("beta),");

		const readOther = textOutput(await new ReadTool(session).execute("read", { path: "other.py:1-2" }));
		const otherTag = readOther.split("\n")[0]!.match(/#([0-9A-F]{4})\]$/)?.[1];
		expect(otherTag).toBeDefined();

		// 1. Unseen line anchor is rejected; file content and hash remain untouched.
		const unseenResult = await new EditTool(session, "hashline").execute("edit-unseen", {
			input: `${drawHeader}\nPUT 4.=4:\n+            beta, gamma),\n`,
		});
		expect(unseenResult.isError).toBe(true);
		expect(extractEditErrorKind(unseenResult)).toBe("unseen_lines");
		expect(classifyEditRejection(unseenResult)).toBe("anchor_reject");
		expect(await Bun.file(file).text()).toBe(SOURCE);

		// 2. Cross-file tag is rejected; both files remain untouched.
		const crossTagResult = await new EditTool(session, "hashline").execute("edit-cross-tag", {
			input: `[draw.py#${otherTag}]\nPUT 7.=7:\n+        callout_xy=(0.240, 0.258))\n`,
		});
		expect(crossTagResult.isError).toBe(true);
		expect(extractEditErrorKind(crossTagResult)).toBe("other_file_tag");
		expect(classifyEditRejection(crossTagResult)).toBe("hash_reject");
		expect(textOutput(crossTagResult)).toContain("other.py");
		expect(await Bun.file(file).text()).toBe(SOURCE);
		expect(await Bun.file(otherFile).text()).toBe(otherSource);

		// 3. Re-reading the target range and applying with the current tag succeeds.
		const fullRangeRead = textOutput(await new ReadTool(session).execute("read", { path: "draw.py:3-5" }));
		const currentHeader = fullRangeRead.split("\n")[0]!;
		const applied = await new EditTool(session, "hashline").execute("edit-valid", {
			input: `${currentHeader}\nPUT 4.=4:\n+            beta, gamma),\n`,
		});
		expect(applied.isError).not.toBe(true);
		expect(await Bun.file(file).text()).toBe(SOURCE.replace("beta),", "beta, gamma),"));
	});

	it("applies a hunk anchored on a line the read displayed", async () => {
		const session = createSession(cwd);
		const read = textOutput(await new ReadTool(session).execute("read", { path: "draw.py:7-7" }));
		expect(read).toContain("callout_xy=(0.230, 0.258))");

		await new EditTool(session, "hashline").execute("edit", {
			input: `${read.split("\n")[0]}\nPUT 7.=7:\n+        callout_xy=(0.240, 0.258))\n`,
		});

		expect(await Bun.file(file).text()).toBe(SOURCE.replace("0.230", "0.240"));
	});
});

// Regression: an edit under a stale tag went through snapshot recovery without
// the seen-line check, so after one edit changed the file, a header copied
// from the earlier read anchored lines that read never displayed.
describe("read → edit seen-line guard under a stale tag", () => {
	let cwd: string;
	let file: string;
	const LINES = Array.from({ length: 30 }, (_, index) => `line ${index + 1}`);

	beforeEach(async () => {
		cwd = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-stale-seen-"));
		file = path.join(cwd, "list.txt");
		await Bun.write(file, `${LINES.join("\n")}\n`);
	});

	afterEach(async () => {
		await removeWithRetries(cwd);
	});

	it("reveals a line the earlier read never displayed, then applies the retry", async () => {
		const session = createSession(cwd);
		const header = textOutput(await new ReadTool(session).execute("read", { path: "list.txt:18-22" })).split("\n")[0];
		expect(header).toMatch(/^\[list\.txt#[0-9A-F]{4}\]$/);
		const edit = new EditTool(session, "hashline");
		await edit.execute("edit-1", { input: `${header}\nPUT 20.=20:\n+LINE TWENTY\n` });
		const afterFirst = await Bun.file(file).text();
		expect(afterFirst).toContain("LINE TWENTY");

		// The header now names a stale version, whose read showed lines 18-22.
		const stale = `${header}\nPUT 3.=3:\n+LINE THREE\n`;
		const refused = await edit.execute("edit-2", { input: stale });
		expect(textOutput(refused)).toContain("never displayed");
		expect(textOutput(refused)).toContain("3:line 3");
		expect(await Bun.file(file).text()).toBe(afterFirst);

		await edit.execute("edit-3", { input: stale });
		expect(await Bun.file(file).text()).toBe(afterFirst.replace("line 3\n", "LINE THREE\n"));
	});
});

/**
 * `grep`/`glob` under `tools.approvalMode: always-ask-cached` — the folders and
 * files each search reports as cache targets, and the grants those keys share
 * with `read` (and with each other).
 */
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import { recordApprovalGrant, resolveApproval } from "@reverse/coding-agent/tools/approval";
import {
	type ApprovalGrantStore,
	approvalDirectoryKey,
	approvalGrantKey,
	getApprovalGrants,
} from "@reverse/coding-agent/tools/approval-cache";
import { approvalTargetKey, approvalTreeSearchKey } from "@reverse/coding-agent/tools/approval-targets";
import { AstGrepTool } from "@reverse/coding-agent/tools/ast-grep";
import { GlobTool } from "@reverse/coding-agent/tools/glob";
import { GrepTool } from "@reverse/coding-agent/tools/grep";
import { ReadTool } from "@reverse/coding-agent/tools/read";
import type { ToolSession } from "@reverse/coding-agent/sdk";
import { TempDir } from "@reverse/utils";
import { writeArchive } from "@reverse/utils/ar";

/** Minimal tool session for directly exercising a search tool's approval-cache keys. */
function createToolSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated(),
	};
}

/** Check-only store for resolution tests: knows exactly the given keys, granted at `read` tier. */
function readTierGrants(targets: readonly string[] = []): ApprovalGrantStore {
	const grants = new Set(targets.map(target => approvalGrantKey("read", target)));
	return { present: keys => new Set(keys.filter(key => grants.has(key))) };
}

describe("search tool approval cache targets", () => {
	let temp: TempDir;
	let cwd: string;
	let srcDir: string;
	let otherDir: string;
	let notesFile: string;

	beforeEach(() => {
		temp = TempDir.createSync("@reverse-search-approval-");
		cwd = temp.path();
		srcDir = path.join(cwd, "src");
		otherDir = path.join(cwd, "other");
		notesFile = path.join(srcDir, "notes.txt");
		fs.mkdirSync(srcDir);
		fs.mkdirSync(otherDir);
		fs.writeFileSync(notesFile, "hello\n");
	});

	afterEach(() => temp.removeSync());

	it("reports a recursive search as the tree key, a one-level one as the folder key", () => {
		const grep = new GrepTool(createToolSession(cwd));
		const glob = new GlobTool(createToolSession(cwd));
		const folderKey = approvalDirectoryKey(srcDir);
		const treeKey = approvalTreeSearchKey(folderKey);

		// grep walks below subfolders, so a folder grant on the same folder is not enough for it.
		expect(grep.approvalCacheTargets?.({ pattern: "hello", path: "src" })).toEqual([treeKey]);
		expect(grep.approvalCacheTargets?.({ pattern: "hello", path: "src/*.txt" })).toEqual([treeKey]);
		// A `**` pattern recurses too; a one-segment pattern under an explicit base does not.
		expect(glob.approvalCacheTargets?.({ path: "src/**/*.txt" })).toEqual([treeKey]);
		expect(glob.approvalCacheTargets?.({ path: "src/*.txt" })).toEqual([folderKey]);
		// A glob root reports the folder the tool walks, never the pattern itself.
		expect(glob.approvalCacheTargets?.({ path: "src" })).toEqual([treeKey]);
	});

	it("splits a semicolon-delimited root list the way execution does", () => {
		const grep = new GrepTool(createToolSession(cwd));
		const glob = new GlobTool(createToolSession(cwd));
		const srcKey = approvalTreeSearchKey(approvalDirectoryKey(srcDir));
		const otherKey = approvalTreeSearchKey(approvalDirectoryKey(otherDir));

		// Execution fans `a;b` into two roots; keying the unsplit string would report nothing and
		// leave the search auto-allowed, so both roots are keyed.
		expect(grep.approvalCacheTargets?.({ pattern: "hello", path: "src;other" })).toEqual([srcKey, otherKey]);
		expect(glob.approvalCacheTargets?.({ path: "src/**/*.txt;other/**/*.txt" })).toEqual([srcKey, otherKey]);
		// A root that exists literally keeps its own key beside the split parts.
		expect(grep.approvalCacheTargets?.({ pattern: "hello", path: "src;missing" })).toEqual([srcKey]);
	});

	it("reports a file root as the file key a read of it would mint", () => {
		const grep = new GrepTool(createToolSession(cwd));
		const glob = new GlobTool(createToolSession(cwd));
		const fileKey = approvalTargetKey(cwd, "src/notes.txt")!;

		expect(grep.approvalCacheTargets?.({ pattern: "hello", path: "src/notes.txt" })).toEqual([fileKey]);
		expect(glob.approvalCacheTargets?.({ path: "src/notes.txt" })).toEqual([fileKey]);
		// A line-range selector is peeled, so a ranged search shares the one file key.
		expect(grep.approvalCacheTargets?.({ pattern: "hello", path: "src/notes.txt:1-2" })).toEqual([fileKey]);
	});

	it("reports every distinct root of a multi-root call, in order", () => {
		const grep = new GrepTool(createToolSession(cwd));

		expect(grep.approvalCacheTargets?.({ pattern: "hello", path: ["src", "src/notes.txt", "src"] })).toEqual([
			approvalTreeSearchKey(approvalDirectoryKey(srcDir)),
			approvalTargetKey(cwd, "src/notes.txt")!,
		]);
		// `paths` is the legacy alias the approval tier already reads.
		expect(grep.approvalCacheTargets?.({ pattern: "hello", paths: "src" })).toEqual([
			approvalTreeSearchKey(approvalDirectoryKey(srcDir)),
		]);
	});

	it("falls back to the session cwd with no path, and reports nothing unusable", () => {
		const grep = new GrepTool(createToolSession(cwd));
		const glob = new GlobTool(createToolSession(cwd));
		const cwdTreeKey = approvalTreeSearchKey(approvalDirectoryKey(cwd));

		// No path argument: both tools search the session cwd recursively, so that is the target.
		expect(grep.approvalCacheTargets?.({ pattern: "hello" })).toEqual([cwdTreeKey]);
		expect(glob.approvalCacheTargets?.({ path: "*.txt" })).toEqual([cwdTreeKey]);
		// Public web contents are public already: nothing to approve, nothing to remember.
		expect(grep.approvalCacheTargets?.({ pattern: "hello", path: "https://example.com/a.txt" })).toBeUndefined();
		expect(glob.approvalCacheTargets?.({ path: "https://example.com/*.txt" })).toBeUndefined();
		// A root nothing occupies is not worth a grant.
		expect(grep.approvalCacheTargets?.({ pattern: "hello", path: "missing/nothing.txt" })).toBeUndefined();
		expect(glob.approvalCacheTargets?.({ path: "missing/**" })).toBeUndefined();
		// An internal URL keeps the normalized form a read of the same resource mints.
		expect(grep.approvalCacheTargets?.({ pattern: "hello", path: "local://notes/a.md" })).toEqual([
			"local://notes/a.md",
		]);
		expect(glob.approvalCacheTargets?.({ path: "local://notes" })).toEqual(["local://notes"]);
	});

	it("prompts until the reported key is granted, under always-ask-cached", () => {
		const grep = new GrepTool(createToolSession(cwd));
		const glob = new GlobTool(createToolSession(cwd));
		const grepArgs = { pattern: "hello", path: "src" };
		const globArgs = { path: "src/**/*.txt" };

		expect(resolveApproval(grep, grepArgs, "always-ask-cached", {}, readTierGrants())).toMatchObject({
			policy: "prompt",
			tier: "read",
			source: "mode",
		});
		expect(resolveApproval(glob, globArgs, "always-ask-cached", {}, readTierGrants()).policy).toBe("prompt");

		// A folder grant covers the folder's own entries, which is one level — not a recursive
		// search that reads below its subfolders.
		const folderGrant = readTierGrants([approvalDirectoryKey(srcDir)]);
		expect(resolveApproval(grep, grepArgs, "always-ask-cached", {}, folderGrant).policy).toBe("prompt");
		expect(resolveApproval(glob, globArgs, "always-ask-cached", {}, folderGrant).policy).toBe("prompt");
		expect(resolveApproval(glob, { path: "src/*.txt" }, "always-ask-cached", {}, folderGrant).policy).toBe("allow");
		// It reaches a file search inside the folder too.
		expect(resolveApproval(glob, { path: "src/notes.txt" }, "always-ask-cached", {}, folderGrant).policy).toBe(
			"allow",
		);
		// The tree grant the search's own prompt records is what silences a recursive search.
		const treeGrant = readTierGrants([approvalTreeSearchKey(approvalDirectoryKey(srcDir))]);
		expect(resolveApproval(grep, grepArgs, "always-ask-cached", {}, treeGrant).policy).toBe("allow");
		expect(resolveApproval(glob, globArgs, "always-ask-cached", {}, treeGrant).policy).toBe("allow");

		// A grant for a different folder never covers this search.
		const elsewhere = readTierGrants([approvalDirectoryKey(otherDir)]);
		expect(resolveApproval(grep, grepArgs, "always-ask-cached", {}, elsewhere).policy).toBe("prompt");
		expect(resolveApproval(glob, globArgs, "always-ask-cached", {}, elsewhere).policy).toBe("prompt");
	});

	it("covers a later glob with the folder grant recorded from a grep", () => {
		const agentDir = TempDir.createSync("@reverse-search-approval-agent-");
		try {
			const store = getApprovalGrants(agentDir.path(), "s1");
			const grep = new GrepTool(createToolSession(cwd));
			const grepArgs = { pattern: "hello", path: "src" };
			const folderKey = approvalDirectoryKey(srcDir);

			recordApprovalGrant(grep, grepArgs, store, "read", { grant: "target", always: false });
			// The answer that silences the recursive search, plus the folder grant it subsumes.
			const tree = approvalGrantKey("read", approvalTreeSearchKey(folderKey));
			const folder = approvalGrantKey("read", folderKey);
			expect([...store.present([tree, folder])].sort()).toEqual([folder, tree].sort());

			const glob = new GlobTool(createToolSession(cwd));
			expect(resolveApproval(glob, { path: "src/**/*.txt" }, "always-ask-cached", {}, store).policy).toBe("allow");
			// The same grant covers a search of one file inside the folder.
			expect(
				resolveApproval(grep, { pattern: "hello", path: "src/notes.txt" }, "always-ask-cached", {}, store).policy,
			).toBe("allow");
		} finally {
			agentDir.removeSync();
		}
	});

	it("keys ast_grep roots like grep, so it cannot read past a read prompt", () => {
		const astGrep = new AstGrepTool(createToolSession(cwd));
		expect(astGrep.approvalCacheTargets?.({ pat: "$X", path: "src" })).toEqual([
			approvalTreeSearchKey(approvalDirectoryKey(srcDir)),
		]);
		expect(
			resolveApproval(astGrep, { pat: "$X", path: "src" }, "always-ask-cached", {}, readTierGrants()).policy,
		).toBe("prompt");
	});

	it.skipIf(process.platform === "win32")("never grants a selector-shaped literal through its sibling file", () => {
		const grep = new GrepTool(createToolSession(cwd));
		fs.writeFileSync(path.join(cwd, "secret:1"), "private\n");
		const args = { pattern: "private", path: "secret:1" };
		expect(resolveApproval(grep, args, "always-ask-cached", {}, readTierGrants()).policy).toBe("prompt");
		fs.writeFileSync(path.join(cwd, "secret"), "public\n");
		expect(
			resolveApproval(grep, args, "always-ask-cached", {}, readTierGrants([approvalTargetKey(cwd, "secret")!]))
				.policy,
		).toBe("prompt");
		expect(
			resolveApproval(grep, args, "always-ask-cached", {}, readTierGrants([approvalTargetKey(cwd, "secret:1")!]))
				.policy,
		).toBe("allow");
	});

	it("requires the backing archive grant for member searches and enforces its folder restrictions", async () => {
		const archivePath = path.join(otherDir, "bundle.zip");
		await writeArchive(archivePath, "zip", [["secret.txt", "private\n"]]);
		const grep = new GrepTool(createToolSession(cwd));
		const args = { pattern: "private", path: "other/bundle.zip:secret.txt" };
		expect(resolveApproval(grep, args, "always-ask-cached", {}, readTierGrants()).policy).toBe("prompt");
		expect(
			resolveApproval(grep, args, "always-ask-cached", {}, readTierGrants([approvalTargetKey(cwd, archivePath)!]))
				.policy,
		).toBe("allow");
		expect(resolveApproval(grep, args, "yolo", {}, undefined, { cwd, restrictedFolders: [otherDir] }).source).toBe(
			"restriction",
		);
	});

	it("treats bounded multisegment globs as tree searches", () => {
		const glob = new GlobTool(createToolSession(cwd));
		const privateDir = path.join(srcDir, "private");
		fs.mkdirSync(privateDir);
		fs.writeFileSync(path.join(privateDir, "secret.txt"), "private\n");
		const args = { path: "src/*/*.txt" };
		expect(
			resolveApproval(glob, args, "always-ask-cached", {}, readTierGrants([approvalDirectoryKey(srcDir)])).policy,
		).toBe("prompt");
		expect(resolveApproval(glob, args, "yolo", {}, undefined, { cwd, restrictedFolders: [privateDir] }).source).toBe(
			"restriction",
		);
	});

	it("authorizes private members of mixed public URL reads independently", () => {
		const read = new ReadTool(createToolSession(cwd));
		const args = { path: "https://example.com/;src/notes.txt" };
		expect(resolveApproval(read, args, "always-ask-cached", {}, readTierGrants()).policy).toBe("prompt");
		expect(
			resolveApproval(read, args, "always-ask-cached", {}, readTierGrants([approvalTargetKey(cwd, notesFile)!]))
				.policy,
		).toBe("allow");
		expect(resolveApproval(read, args, "yolo", {}, undefined, { cwd, restrictedFolders: [srcDir] }).source).toBe(
			"restriction",
		);
		expect(
			resolveApproval(read, { path: "https://example.com/x;v=1" }, "always-ask-cached", {}, readTierGrants()).policy,
		).toBe("allow");
		expect(
			resolveApproval(
				read,
				{ path: "https://example.com/;http://127.0.0.1/private" },
				"always-ask-cached",
				{},
				readTierGrants(),
			).policy,
		).toBe("prompt");
	});
});

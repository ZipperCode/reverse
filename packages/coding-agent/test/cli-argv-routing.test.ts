/**
 * Leading global option flags routing and removed command rejection.
 */
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, test } from "bun:test";
import { resolveCliArgv } from "@reverse/coding-agent/cli-commands";
import { APP_NAME } from "@reverse/utils/dirs";
import { CliUsageError } from "@reverse/utils/cli";
import { runSkillCommand, type SkillAction } from "@reverse/coding-agent/cli/skill-cli";

describe("resolveCliArgv routes subcommands hidden behind leading global flags", () => {
	test("`--approval-mode=yolo acp` dispatches the acp subcommand with the flag preserved", () => {
		expect(resolveCliArgv(["--approval-mode=yolo", "acp"])).toEqual({
			argv: ["acp", "--approval-mode=yolo"],
		});
	});

	test("space-form `--approval-mode yolo acp` keeps the flag and its value with acp", () => {
		expect(resolveCliArgv(["--approval-mode", "yolo", "acp"])).toEqual({
			argv: ["acp", "--approval-mode", "yolo"],
		});
	});

	test("multiple leading flags before the subcommand are all preserved", () => {
		expect(resolveCliArgv(["--approval-mode=yolo", "--model", "gpt", "acp"])).toEqual({
			argv: ["acp", "--approval-mode=yolo", "--model", "gpt"],
		});
	});

	test("a value-consuming flag does not mistake its value for a subcommand", () => {
		expect(resolveCliArgv(["--model", "acp"])).toEqual({
			argv: ["launch", "--model", "acp"],
		});
	});

	test("`--` ends option scanning so a following subcommand stays a launch prompt", () => {
		expect(resolveCliArgv(["--", "acp"])).toEqual({
			argv: ["launch", "--", "acp"],
		});
	});

	test("a genuine launch prompt is untouched", () => {
		expect(resolveCliArgv(["--approval-mode=yolo", "fix", "the", "bug"])).toEqual({
			argv: ["launch", "--approval-mode=yolo", "fix", "the", "bug"],
		});
	});

	test("a subcommand already in front still passes through unchanged", () => {
		expect(resolveCliArgv(["acp", "--approval-mode=yolo"])).toEqual({
			argv: ["acp", "--approval-mode=yolo"],
		});
	});

	test("`gc` dispatches as a top-level maintenance subcommand", () => {
		expect(resolveCliArgv(["gc", "--apply"])).toEqual({
			argv: ["gc", "--apply"],
		});
	});
});

describe("resolveCliArgv strips launch-global flags before non-launch subcommands (#8891)", () => {
	test("`--cwd <dir> gc` drops the inapplicable launch flag instead of forwarding it", () => {
		expect(resolveCliArgv(["--cwd", "/tmp", "gc"])).toEqual({ argv: ["gc"] });
	});

	test("`--cwd=<dir>` inline form is stripped too", () => {
		expect(resolveCliArgv(["--cwd=/tmp", "gc"])).toEqual({ argv: ["gc"] });
	});

	test("a trailing subcommand flag survives while the leading launch flag is stripped", () => {
		expect(resolveCliArgv(["--cwd", "/tmp", "gc", "--apply"])).toEqual({
			argv: ["gc", "--apply"],
		});
	});

	test("multiple leading launch flags are all stripped before a non-launch subcommand", () => {
		expect(resolveCliArgv(["--model", "gpt", "--cwd", "/x", "gc"])).toEqual({ argv: ["gc"] });
	});

	test("launch-shaped `acp` still receives forwarded launch-global flags", () => {
		expect(resolveCliArgv(["--cwd", "/x", "acp"])).toEqual({ argv: ["acp", "--cwd", "/x"] });
	});
});

describe("resolveCliArgv rejects removed hosted commands before prompt fallback", () => {
	const removed = ["collab", "join", "share", "stream", "clip", "grievances", "update"] as const;

	for (const word of removed) {
		const expectedError = `\`${APP_NAME} ${word}\` is not available; use \`${APP_NAME} launch\` for a prompt.`;

		test(`rejects bare \`${word}\``, () => {
			expect(resolveCliArgv([word])).toEqual({ error: expectedError });
		});

		test(`rejects \`${word}\` with arguments`, () => {
			expect(resolveCliArgv([word, "extra", "args"])).toEqual({ error: expectedError });
		});

		test(`rejects \`${word}\` behind leading launch flags`, () => {
			expect(resolveCliArgv(["--cwd", "/tmp", word])).toEqual({ error: expectedError });
			expect(resolveCliArgv(["--approval-mode=yolo", word, "arg"])).toEqual({ error: expectedError });
		});

		test(`allows explicit launch of prompt starting with \`${word}\``, () => {
			expect(resolveCliArgv(["launch", word, "prompt text"])).toEqual({
				argv: ["launch", word, "prompt text"],
			});
		});
	}
});

describe("skill command rejection of removed actions", () => {
	test("rejects removed action with CliUsageError", async () => {
		await expect(
			runSkillCommand({
				action: "install" as unknown as SkillAction,
				args: ["@scope/pkg"],
				cwd: process.cwd(),
				flags: {},
			}),
		).rejects.toBeInstanceOf(CliUsageError);
	});

	test("skill list --json discovers local skills from fixture directory", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rva-skill-list-"));
		try {
			const skillDir = path.join(tempDir, ".reverse", "skills", "fixture-tool");
			await fs.mkdir(skillDir, { recursive: true });
			await Bun.write(
				path.join(skillDir, "SKILL.md"),
				"---\nname: fixture-tool\ndescription: Local fixture skill\n---\n# Fixture\n",
			);
			const stdoutChunks: string[] = [];
			const origWrite = process.stdout.write;
			process.stdout.write = ((chunk: string | Uint8Array) => {
				stdoutChunks.push(String(chunk));
				return true;
			}) as typeof process.stdout.write;
			try {
				const code = await runSkillCommand({
					action: "list",
					args: [],
					cwd: tempDir,
					flags: { json: true },
				});
				expect(code).toBe(0);
				const output = JSON.parse(stdoutChunks.join("")) as { skills: Array<{ name: string }> };
				expect(output.skills.some(s => s.name === "fixture-tool")).toBe(true);
			} finally {
				process.stdout.write = origWrite;
			}
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});

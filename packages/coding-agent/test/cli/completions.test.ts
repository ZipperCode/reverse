import { describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { type CompletionSpec, generateCompletion } from "@reverse/coding-agent/cli/completion-gen";

// A compact synthetic spec exercising every value-source kind and an aliased
// subcommand.
const spec: CompletionSpec = {
	bin: "reverse",
	root: {
		flags: [
			{ name: "model", description: "Model to use", value: { kind: "models", multiple: false }, repeatable: false },
			{ name: "models", description: "Model list", value: { kind: "models", multiple: true }, repeatable: false },
			{
				name: "thinking",
				description: "Effort",
				value: { kind: "enum", values: ["low", "high"] },
				repeatable: false,
			},
			{ name: "tools", description: "Tools", value: { kind: "list", values: ["read", "bash"] }, repeatable: false },
			{ name: "resume", char: "r", description: "Resume", value: { kind: "sessions" }, repeatable: false },
			{ name: "print", char: "p", description: "Print", value: { kind: "flag" }, repeatable: false },
			{ name: "extension", char: "e", description: "Ext", value: { kind: "file" }, repeatable: true },
			{ name: "session-dir", description: "Dir", value: { kind: "dir" }, repeatable: false },
		],
		args: [],
	},
	commands: [
		{
			name: "commit",
			aliases: [],
			description: "Commit",
			flags: [{ name: "push", description: "Push", value: { kind: "flag" }, repeatable: false }],
			args: [],
		},
		{
			name: "worktree",
			aliases: ["wt"],
			description: "Worktrees",
			flags: [],
			args: [{ name: "action", description: "Action", value: { kind: "enum", values: ["list", "clear"] } }],
		},
	],
};

let hasZsh = false;
try {
	hasZsh = Bun.spawnSync(["zsh", "--version"]).exitCode === 0;
} catch {
	hasZsh = false;
}

describe.skipIf(!hasZsh)("zsh action helper under _arguments' calling convention", () => {
	it("reads the completion kind past the compadd options zsh prepends", () => {
		const script = generateCompletion("zsh", spec);
		const start = script.indexOf("_reverse_call() {");
		expect(start).toBeGreaterThanOrEqual(0);
		const fn = script.slice(start, script.indexOf("\n}\n", start) + 3);

		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "reverse-zsh-action-"));
		try {
			// `command reverse` bypasses shell functions, so the stub must be an
			// executable on PATH.
			const bin = path.join(dir, "reverse");
			fs.writeFileSync(bin, `#!/bin/sh\nprintf '%s\\n' "$*" >> "${dir}/argv.log"\n`, { mode: 0o755 });
			fs.writeFileSync(
				path.join(dir, "harness.zsh"),
				// _describe only exists inside a completion context.
				`_describe() { :; }\n${fn}\n_reverse_call -n -J -default- sessions\n`,
			);

			const result = Bun.spawnSync(["zsh", "-f", path.join(dir, "harness.zsh")], {
				cwd: dir,
				env: { ...process.env, PATH: `${dir}:${process.env.PATH}` },
			});
			expect(result.exitCode).toBe(0);

			const argv = fs.existsSync(path.join(dir, "argv.log"))
				? fs.readFileSync(path.join(dir, "argv.log"), "utf8")
				: "";
			// zsh calls the action as `fn <compadd options> <expl> <kind>`.
			// Both valueless flags (-n) and option/value pairs (-J -default-) can
			// precede the kind. Before the fix the stub saw `__complete -n -- `.
			expect(argv).toContain("__complete sessions --");
			expect(argv).not.toContain("__complete -n");
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

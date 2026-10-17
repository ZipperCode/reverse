import { afterEach, describe, expect, it, vi } from "bun:test";
import { type } from "@rva/omptype";
import type * as TypeBox from "@rva/omptype/typebox";
import * as zod from "@rva/omptype/zod";
import * as piCodingAgent from "@rva/coding-agent";
import { GreenCommand } from "@rva/coding-agent/extensibility/custom-commands/bundled/ci-green";
import type { CustomCommandAPI } from "@rva/coding-agent/extensibility/custom-commands/types";
import type { HookCommandContext } from "@rva/coding-agent/extensibility/hooks/types";
import type { VcsGitRepo } from "@rva/natives";
import * as vcs from "@rva/natives/vcs";

afterEach(() => {
	vi.restoreAllMocks();
});

function createApi(): CustomCommandAPI {
	return {
		cwd: "/tmp/test",
		exec: async () => ({
			stdout: "",
			stderr: "",
			code: 0,
			killed: false,
		}),
		typebox: {} as unknown as typeof TypeBox,
		arktype: Object.assign(Function.prototype.bind.call(type, undefined) as typeof type, type, { type }),
		zod,
		pi: piCodingAgent,
	};
}

describe("GreenCommand", () => {
	it("includes tag instructions when HEAD has a tag", async () => {
		vi.spyOn(vcs, "requireGit").mockReturnValue({
			tagsAt: async () => ["v0.1.0-alpha2"],
		} as unknown as VcsGitRepo);
		const command = new GreenCommand(createApi());

		const result = await command.execute([], {} as HookCommandContext);

		expect(result).toContain("v0.1.0-alpha2");
	});
});

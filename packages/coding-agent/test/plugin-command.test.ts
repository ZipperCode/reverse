import { describe, expect, it } from "bun:test";
import Plugin from "@reverse/coding-agent/commands/plugin";
import type { CliConfig } from "@reverse/utils/cli";

const TEST_CONFIG: CliConfig = {
	bin: "reverse",
	version: "0.0.0-test",
	commands: new Map(),
};

describe("Plugin command scope parsing", () => {
	it("rejects invalid scope values", async () => {
		const command = new Plugin(["install", "--scope", "porject"], TEST_CONFIG);
		await expect(command.parse(Plugin)).rejects.toThrow(/Expected --scope to be one of: user, project/);
	});
});

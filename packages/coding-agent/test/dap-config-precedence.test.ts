import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { getAdapterConfigs } from "@reverse/coding-agent/dap/config";
import { CONFIG_DIR_NAME } from "@reverse/utils/dirs";

const ADAPTER = "omp-precedence-probe";

let tempDir: string | undefined;

afterEach(async () => {
	if (tempDir) await fs.rm(tempDir, { recursive: true, force: true });
	tempDir = undefined;
});

describe("DAP config layering", () => {
	test("a cwd file overrides the project config dir field by field", async () => {
		tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "omp-dap-precedence-"));
		await Bun.write(
			path.join(tempDir, CONFIG_DIR_NAME, "dap.yaml"),
			`${ADAPTER}:\n  command: project-cmd\n  args: [from-project]\n`,
		);
		await Bun.write(path.join(tempDir, "dap.json"), JSON.stringify({ [ADAPTER]: { command: "cwd-cmd" } }));

		const adapter = getAdapterConfigs(tempDir)[ADAPTER];

		expect(adapter?.command).toBe("cwd-cmd");
		expect(adapter?.args).toEqual(["from-project"]);
	});
});

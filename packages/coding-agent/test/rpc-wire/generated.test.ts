import { describe, expect, test } from "bun:test";
import { generateRpcArtifacts } from "../../scripts/gen-rpc";

describe("RPC wire artifacts", () => {
	test("committed schema bundle and generated clients match a fresh `bun run gen:rpc`", async () => {
		for (const [file, contents] of generateRpcArtifacts()) {
			if (!(await Bun.file(file).exists())) continue;
			expect(await Bun.file(file).text(), file).toBe(contents);
		}
	});
});

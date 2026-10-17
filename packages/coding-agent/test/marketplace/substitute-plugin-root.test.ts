import { describe, expect, it } from "bun:test";
import { substitutePluginRoot } from "@rva/coding-agent/discovery/substitute-plugin-root";

// Use concatenation to avoid noTemplateCurlyInString lint rule on literal placeholder names
const CLAUDE_VAR = "$" + "{CLAUDE_PLUGIN_ROOT}";
const RVA_VAR = "$" + "{RVA_PLUGIN_ROOT}";

describe("substitutePluginRoot", () => {
	const ROOT = "/plugins/my-plugin";

	it("replaces both variables in same string", () => {
		expect(substitutePluginRoot(`${CLAUDE_VAR}:${RVA_VAR}`, ROOT)).toBe("/plugins/my-plugin:/plugins/my-plugin");
	});

	it("handles arrays recursively", () => {
		expect(substitutePluginRoot(["--config", `${CLAUDE_VAR}/config.json`], ROOT)).toEqual([
			"--config",
			"/plugins/my-plugin/config.json",
		]);
	});

	it("handles nested structures", () => {
		const input = {
			command: `${CLAUDE_VAR}/server`,
			args: ["--port", "3000"],
			env: { HOME: RVA_VAR },
		};
		expect(substitutePluginRoot(input, ROOT)).toEqual({
			command: "/plugins/my-plugin/server",
			args: ["--port", "3000"],
			env: { HOME: "/plugins/my-plugin" },
		});
	});

	it("returns string unchanged when no variables present", () => {
		expect(substitutePluginRoot("no-vars-here", ROOT)).toBe("no-vars-here");
	});

	it("leaves legacy OMP_PLUGIN_ROOT unexpanded (no legacy alias)", () => {
		const OMP_VAR = "$" + "{OMP_PLUGIN_ROOT}";
		expect(substitutePluginRoot(`${OMP_VAR}/server`, ROOT)).toBe("${OMP_PLUGIN_ROOT}/server");
	});
});
